# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import array
import os
import json
import time
import http
from enum import Enum
import infra.ccf
import infra.proc
import infra.checker
import infra.node
import infra.crypto
from infra.proposal_state import ProposalState

from loguru import logger as LOG


class Consortium:
    def __init__(self, members, curve, key_generator, common_dir):
        self.members = members
        self.common_dir = common_dir
        self.key_generator = key_generator
        for m_id in members:
            self._generate_new_member_info(m_id, curve)

    def _generate_new_member_info(self, member_id, curve):
        member = f"member{member_id}"
        infra.proc.ccall(
            self.key_generator,
            f"--name={member}",
            f"--curve={curve.name}",
            "--gen-key-share",
            path=self.common_dir,
            log_output=False,
        ).check_returncode()

    def get_members_info(self):
        members_certs = [f"member{m}_cert.pem" for m in self.members]
        members_kshare_pub = [f"member{m}_kshare_pub.pem" for m in self.members]
        return list(zip(members_certs, members_kshare_pub))

    def generate_and_propose_new_member(
        self, member_id, remote_node, new_member_id, curve
    ):
        # For now, the infra does not keep track of the members id
        self._generate_new_member_info(new_member_id, curve)
        return self.propose_add_member(
            member_id=member_id,
            remote_node=remote_node,
            new_member_cert=os.path.join(
                self.common_dir, f"member{new_member_id}_cert.pem"
            ),
            new_member_keyshare=os.path.join(
                self.common_dir, f"member{new_member_id}_kshare_pub.pem"
            ),
        )

    def propose(self, member_id, remote_node, script=None, params=None):
        with remote_node.member_client(member_id=member_id) as mc:
            r = mc.rpc(
                "propose",
                {"parameter": params, "script": {"text": script}},
                signed=True,
            )
            return r

    def vote(
        self,
        member_id,
        remote_node,
        proposal_id,
        accept,
        force_unsigned=False,
        should_wait_for_global_commit=True,
    ):
        script = """
        tables, changes = ...
        return true
        """
        with remote_node.member_client(member_id=member_id) as mc:
            response = mc.rpc(
                "vote",
                {"ballot": {"text": script}, "id": proposal_id},
                signed=not force_unsigned,
            )

        if response.error is not None:
            return response

        # If the proposal was accepted, wait for it to be globally committed
        # This is particularly useful for the open network proposal to wait
        # until the global hook on the SERVICE table is triggered
        if (
            response.result["state"] == ProposalState.Accepted.value
            and should_wait_for_global_commit
        ):
            with remote_node.node_client() as mc:
                infra.checker.wait_for_global_commit(
                    mc, response.commit, response.term, True
                )

        return response

    def vote_using_majority(
        self, remote_node, proposal_id, should_wait_for_global_commit=True
    ):
        # There is no need to stop after n / 2 + 1 members have voted,
        # but this could prove to be useful in detecting errors
        # related to the voting mechanism
        if len(self.members) == 1:
            return True
        majority_count = int(len(self.members) / 2 + 1)
        for i, member in enumerate(self.members):
            if i >= majority_count:
                break
            response = self.vote(
                member,
                remote_node,
                proposal_id,
                True,
                False,
                should_wait_for_global_commit,
            )
            assert response.status == http.HTTPStatus.OK.value
            if response.result["state"] == ProposalState.Accepted.value:
                break

        assert response is not None
        return response

    def withdraw(self, member_id, remote_node, proposal_id):
        with remote_node.member_client(member_id=member_id) as c:
            return c.rpc("withdraw", {"id": proposal_id}, signed=True)

    def update_ack_state_digest(self, member_id, remote_node):
        with remote_node.member_client(member_id=member_id) as mc:
            res = mc.rpc("updateAckStateDigest", params={})
            return bytearray(res.result["state_digest"])

    def ack(self, member_id, remote_node):
        state_digest = self.update_ack_state_digest(member_id, remote_node)
        with remote_node.member_client(member_id=member_id) as mc:
            r = mc.rpc("ack", params={"state_digest": list(state_digest)}, signed=True)
            assert r.error is None, f"Error ACK: {r.error}"

    def get_proposals(self, member_id, remote_node):
        script = """
        tables = ...
        local proposals = {}
        tables["ccf.proposals"]:foreach( function(k, v)
            proposals[tostring(k)] = v;
        end )
        return proposals;
        """

        with remote_node.member_client(member_id=member_id) as c:
            rep = c.do("query", {"text": script})
            return rep.result

    def propose_retire_node(self, member_id, remote_node, node_id):
        script = """
        tables, node_id = ...
        return Calls:call("retire_node", node_id)
        """
        return self.propose(member_id, remote_node, script, node_id)

    def retire_node(self, remote_node, node_to_retire):
        member_id = 1
        response = self.propose_retire_node(
            member_id, remote_node, node_to_retire.node_id
        )
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(remote_node, response.result["proposal_id"])

        with remote_node.member_client() as c:
            r = c.request("read", {"table": "ccf.nodes", "key": node_to_retire.node_id})
            assert r.result["status"] == infra.node.NodeStatus.RETIRED.name

    def propose_trust_node(self, member_id, remote_node, node_id):
        script = """
        tables, node_id = ...
        return Calls:call("trust_node", node_id)
        """
        return self.propose(member_id, remote_node, script, node_id)

    def trust_node(self, member_id, remote_node, node_id):
        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.PENDING
        ):
            raise ValueError(f"Node {node_id} does not exist in state PENDING")

        response = self.propose_trust_node(member_id, remote_node, node_id)
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(remote_node, response.result["proposal_id"])

        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.TRUSTED
        ):
            raise ValueError(f"Node {node_id} does not exist in state TRUSTED")

    def propose_add_member(
        self, member_id, remote_node, new_member_cert, new_member_keyshare
    ):
        script = """
        tables, member_info = ...
        return Calls:call("new_member", member_info)
        """
        with open(new_member_cert) as cert:
            new_member_cert_pem = [ord(c) for c in cert.read()]
        with open(new_member_keyshare) as keyshare:
            new_member_keyshare = [ord(k) for k in keyshare.read()]
        return self.propose(
            member_id,
            remote_node,
            script,
            {"cert": new_member_cert_pem, "keyshare": new_member_keyshare,},
        )

    def open_network(self, member_id, remote_node, pbft_open=False):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        script = """
        tables = ...
        return Calls:call("open_network")
        """
        response = self.propose(member_id, remote_node, script)
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(
            remote_node, response.result["proposal_id"], not pbft_open
        )
        self.check_for_service(remote_node, infra.ccf.ServiceStatus.OPEN, pbft_open)

    def rekey_ledger(self, member_id, remote_node):
        script = """
        tables = ...
        return Calls:call("rekey_ledger")
        """
        response = self.propose(member_id, remote_node, script)
        assert response.status == http.HTTPStatus.OK.value
        # Wait for global commit since sealed secrets are disclosed only
        # when the rekey transaction is globally committed.
        self.vote_using_majority(
            remote_node,
            response.result["proposal_id"],
            should_wait_for_global_commit=True,
        )

    def add_users(self, remote_node, users):
        for u in users:
            user_cert = []
            with open(os.path.join(self.common_dir, f"user{u}_cert.pem")) as cert:
                user_cert = [ord(c) for c in cert.read()]
            script = """
            tables, user_cert = ...
            return Calls:call("new_user", user_cert)
            """
            response = self.propose(0, remote_node, script, user_cert)
            assert response.status == http.HTTPStatus.OK.value
            self.vote_using_majority(remote_node, response.result["proposal_id"])

    def set_lua_app(self, member_id, remote_node, app_script):
        script = """
        tables, app = ...
        return Calls:call("set_lua_app", app)
        """
        with open(app_script) as app:
            new_lua_app = app.read()
        response = self.propose(member_id, remote_node, script, new_lua_app)
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(remote_node, response.result["proposal_id"])

    def set_js_app(self, member_id, remote_node, app_script):
        script = """
        tables, app = ...
        return Calls:call("set_js_app", app)
        """
        with open(app_script) as app:
            new_js_app = app.read()
        response = self.propose(member_id, remote_node, script, new_js_app)
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(remote_node, response.result["proposal_id"])

    def accept_recovery(self, member_id, remote_node, sealed_secrets):
        script = """
        tables, sealed_secrets = ...
        return Calls:call("accept_recovery", sealed_secrets)
        """
        response = self.propose(member_id, remote_node, script, sealed_secrets)
        self.vote_using_majority(remote_node, response.result["proposal_id"])

    def store_current_network_encryption_key(self):
        cmd = [
            "cp",
            os.path.join(self.common_dir, f"network_enc_pubk.pem"),
            os.path.join(self.common_dir, f"network_enc_pubk_orig.pem"),
        ]
        infra.proc.ccall(*cmd).check_returncode()

    def get_and_decrypt_shares(self, remote_node):
        for m in self.members:
            with remote_node.member_client(member_id=m) as mc:
                r = mc.rpc("getEncryptedRecoveryShare", params={})

                # For now, members rely on a copy of the original network encryption public key
                ctx = infra.crypto.CryptoBoxCtx(
                    os.path.join(self.common_dir, f"member{m}_kshare_priv.pem"),
                    os.path.join(self.common_dir, f"network_enc_pubk_orig.pem"),
                )

                nonce_bytes = bytes(r.result["nonce"])
                encrypted_share_bytes = bytes(r.result["encrypted_share"])
                decrypted_share = ctx.decrypt(encrypted_share_bytes, nonce_bytes,)

                r = mc.rpc(
                    "submitRecoveryShare", params={"share": list(decrypted_share)}
                )
                assert r.error is None, f"Error submitting recovery share: {r.error}"
                if m == 2:
                    assert (
                        r.result == True
                    ), "Shares should be combined when all members have submitted their shares"
                else:
                    assert (
                        r.result == False
                    ), "Shares should not be combined until all members have submitted their shares"

    def add_new_code(self, member_id, remote_node, new_code_id):
        script = """
        tables, code_digest = ...
        return Calls:call("new_code", code_digest)
        """
        code_digest = list(bytearray.fromhex(new_code_id))
        response = self.propose(member_id, remote_node, script, code_digest)
        assert response.status == http.HTTPStatus.OK.value
        self.vote_using_majority(remote_node, response.result["proposal_id"])

    def check_for_service(self, remote_node, status, pbft_open=False):
        """
        Check via the member frontend of the given node that the certificate
        associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        # When opening the service in PBFT, the first transaction to be
        # completed when f = 1 takes a significant amount of time
        with remote_node.member_client(request_timeout=(30 if pbft_open else 3)) as c:
            rep = c.do(
                "query",
                {
                    "text": """tables = ...
                    return tables["ccf.service"]:get(0)"""
                },
            )
            current_status = rep.result["status"]
            current_cert = array.array("B", rep.result["cert"]).tobytes()

            expected_cert = open(
                os.path.join(self.common_dir, "networkcert.pem"), "rb"
            ).read()
            assert (
                current_cert == expected_cert
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.name
            ), f"Service status {current_status} (expected {status.name})"

    def _check_node_exists(self, remote_node, node_id, node_status=None):
        with remote_node.member_client() as c:
            rep = c.do("read", {"table": "ccf.nodes", "key": node_id})

            if rep.error is not None or (
                node_status and rep.result["status"] != node_status.name
            ):
                return False

        return True

    def wait_for_node_to_exist_in_store(
        self, remote_node, node_id, timeout, node_status=None,
    ):
        exists = False
        for _ in range(timeout):
            try:
                if self._check_node_exists(remote_node, node_id, node_status):
                    exists = True
                    break
            except TimeoutError:
                LOG.warning(f"Node {node_id} has not been recorded in the store yet")
            time.sleep(1)
        if not exists:
            raise TimeoutError(
                f"Node {node_id} has not yet been recorded in the store"
                + getattr(node_status, f" with status {node_status.name}", "")
            )
