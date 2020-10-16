# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import time
import http
import json
import random
import infra.network
import infra.proc
import infra.checker
import infra.node
import infra.crypto
import infra.member
import ccf.proposal_generator
from infra.proposal import ProposalState

from loguru import logger as LOG


class Consortium:
    def __init__(
        self,
        common_dir,
        key_generator,
        share_script,
        member_ids=None,
        curve=None,
        remote_node=None,
    ):
        self.common_dir = common_dir
        self.members = []
        self.key_generator = key_generator
        self.share_script = share_script
        self.members = []
        self.recovery_threshold = None
        # If a list of member IDs is passed in, generate fresh member identities.
        # Otherwise, recover the state of the consortium from the state of CCF.
        if member_ids is not None:
            for m_id, m_data in member_ids:
                new_member = infra.member.Member(
                    m_id, curve, common_dir, share_script, key_generator, m_data
                )
                self.members.append(new_member)
            self.recovery_threshold = len(self.members)
        else:
            with remote_node.client("member0") as mc:
                r = mc.post(
                    "/gov/query",
                    {
                        "text": """tables = ...
                        non_retired_members = {}
                        tables["public:ccf.gov.members"]:foreach(function(member_id, details)
                        if details["status"] ~= "RETIRED" then
                            table.insert(non_retired_members, {member_id, details["status"]})
                        end
                        end)
                        return non_retired_members
                        """
                    },
                )
                for m in r.body.json():
                    new_member = infra.member.Member(
                        m[0], curve, self.common_dir, share_script
                    )
                    if (
                        infra.member.MemberStatus[m[1]]
                        == infra.member.MemberStatus.ACTIVE
                    ):
                        new_member.set_active()
                    self.members.append(new_member)
                    LOG.info(f"Successfully recovered member {m[0]} with status {m[1]}")

                r = mc.post(
                    "/gov/query",
                    {
                        "text": """tables = ...
                        return tables["public:ccf.gov.config"]:get(0)
                        """
                    },
                )
                self.recovery_threshold = r.body.json()["recovery_threshold"]

    def make_proposal(self, proposal_name, *args, **kwargs):
        func = getattr(ccf.proposal_generator, proposal_name)
        proposal, vote = func(*args, **kwargs)

        proposal_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_proposal.json"
        )
        vote_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_vote_for.json"
        )

        dump_args = {"indent": 2}

        LOG.debug(f"Writing proposal to {proposal_output_path}")
        with open(proposal_output_path, "w") as f:
            json.dump(proposal, f, **dump_args)

        LOG.debug(f"Writing vote to {vote_output_path}")
        with open(vote_output_path, "w") as f:
            json.dump(vote, f, **dump_args)

        return f"@{proposal_output_path}", f"@{vote_output_path}"

    def activate(self, remote_node):
        for m in self.members:
            m.ack(remote_node)

    def generate_and_propose_new_member(self, remote_node, curve, member_data=None):
        # The Member returned by this function is in state ACCEPTED. The new Member
        # should ACK to become active.
        new_member_id = len(self.members)
        new_member = infra.member.Member(
            new_member_id, curve, self.common_dir, self.share_script, self.key_generator
        )

        proposal_body, careful_vote = self.make_proposal(
            "new_member",
            os.path.join(self.common_dir, f"member{new_member_id}_cert.pem"),
            os.path.join(self.common_dir, f"member{new_member_id}_enc_pubk.pem"),
            member_data,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote

        return (
            proposal,
            new_member,
        )

    def generate_and_add_new_member(self, remote_node, curve, member_data=None):
        proposal, new_member = self.generate_and_propose_new_member(remote_node, curve)
        self.vote_using_majority(remote_node, proposal)

        # If the member was successfully registered, add it to the
        # local list of consortium members
        self.members.append(new_member)
        return new_member

    def get_members_info(self):
        info = []
        for m in self.members:
            i = (f"member{m.member_id}_cert.pem", f"member{m.member_id}_enc_pubk.pem")
            md = f"member{m.member_id}_data.json"
            if os.path.exists(os.path.join(self.common_dir, md)):
                i = i + (md,)
            info.append(i)
        return info

    def get_active_members(self):
        return [member for member in self.members if member.is_active()]

    def get_any_active_member(self):
        return random.choice(self.get_active_members())

    def get_member_by_id(self, member_id):
        return next(
            (member for member in self.members if member.member_id == member_id), None
        )

    def vote_using_majority(self, remote_node, proposal, wait_for_global_commit=True):
        # This function assumes that the proposal has just been proposed and
        # that at most, only the proposer has already voted for it when
        # proposing it
        majority_count = int(len(self.get_active_members()) / 2 + 1)

        for member in self.get_active_members():
            if proposal.votes_for >= majority_count:
                break

            # If the proposer has already voted for the proposal when it
            # was proposed, skip voting
            if (
                proposal.proposer_id == member.member_id
                and proposal.has_proposer_voted_for
            ):
                continue

            response = member.vote(
                remote_node,
                proposal,
                accept=True,
                wait_for_global_commit=wait_for_global_commit,
            )
            assert response.status_code == http.HTTPStatus.OK.value
            proposal.state = infra.proposal.ProposalState(response.body.json()["state"])
            proposal.increment_votes_for()

        if proposal.state is not ProposalState.Accepted:
            raise infra.proposal.ProposalNotAccepted(proposal)
        return proposal

    def get_proposals(self, remote_node):
        script = """
        tables = ...
        local proposals = {}
        tables["public:ccf.gov.proposals"]:foreach( function(k, v)
            proposals[tostring(k)] = v;
        end )
        return proposals;
        """

        proposals = []
        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.post("/gov/query", {"text": script})
            assert r.status_code == http.HTTPStatus.OK.value
            for proposal_id, attr in r.body.json().items():
                has_proposer_voted_for = False
                for vote in attr["votes"]:
                    if attr["proposer"] == vote[0]:
                        has_proposer_voted_for = True

                proposals.append(
                    infra.proposal.Proposal(
                        proposal_id=int(proposal_id),
                        proposer_id=int(attr["proposer"]),
                        state=infra.proposal.ProposalState(attr["state"]),
                        has_proposer_voted_for=has_proposer_voted_for,
                    )
                )
        return proposals

    def retire_node(self, remote_node, node_to_retire):
        proposal_body, careful_vote = self.make_proposal(
            "retire_node", node_to_retire.node_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        self.vote_using_majority(remote_node, proposal)

        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.post(
                "/gov/read",
                {"table": "public:ccf.gov.nodes", "key": node_to_retire.node_id},
            )
            assert r.body.json()["status"] == infra.node.NodeStatus.RETIRED.name

    def trust_node(self, remote_node, node_id):
        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.PENDING
        ):
            raise ValueError(f"Node {node_id} does not exist in state PENDING")

        proposal_body, careful_vote = self.make_proposal("trust_node", node_id)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        self.vote_using_majority(remote_node, proposal)

        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.TRUSTED
        ):
            raise ValueError(f"Node {node_id} does not exist in state TRUSTED")

    def retire_member(self, remote_node, member_to_retire):
        proposal_body, careful_vote = self.make_proposal(
            "retire_member", member_to_retire.member_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        self.vote_using_majority(remote_node, proposal)
        member_to_retire.status_code = infra.member.MemberStatus.RETIRED

    def open_network(self, remote_node):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        proposal_body, careful_vote = self.make_proposal("open_network")
        proposal = self.get_any_active_member().propose(
            remote_node, proposal_body, wait_for_global_commit=True
        )
        proposal.vote_for = careful_vote
        self.vote_using_majority(remote_node, proposal, wait_for_global_commit=True)
        self.check_for_service(remote_node, infra.network.ServiceStatus.OPEN)

    def rekey_ledger(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("rekey_ledger")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def update_recovery_shares(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("update_recovery_shares")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def add_user(self, remote_node, user_id, user_data=None):
        proposal, careful_vote = self.make_proposal(
            "new_user",
            os.path.join(self.common_dir, f"user{user_id}_cert.pem"),
            user_data,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def add_users(self, remote_node, users):
        for u in users:
            self.add_user(remote_node, u)

    def remove_user(self, remote_node, user_id):
        proposal, careful_vote = self.make_proposal("remove_user", user_id)

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        proposal.vote_for = careful_vote
        self.vote_using_majority(remote_node, proposal)

    def set_lua_app(self, remote_node, app_script_path):
        proposal_body, careful_vote = self.make_proposal("set_lua_app", app_script_path)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def set_js_app(self, remote_node, app_script_path):
        proposal_body, careful_vote = self.make_proposal("set_js_app", app_script_path)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def deploy_js_app(self, remote_node, app_bundle_path):
        proposal_body, careful_vote = self.make_proposal(
            "deploy_js_app", app_bundle_path
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def accept_recovery(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("accept_recovery")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def recover_with_shares(self, remote_node, defunct_network_enc_pubk):
        submitted_shares_count = 0
        with remote_node.client() as nc:
            check_commit = infra.checker.Checker(nc)

            for m in self.get_active_members():
                r = m.get_and_submit_recovery_share(
                    remote_node, defunct_network_enc_pubk
                )
                submitted_shares_count += 1
                check_commit(r)

                if submitted_shares_count >= self.recovery_threshold:
                    assert "End of recovery procedure initiated" in r.body.text()
                    break
                else:
                    assert "End of recovery procedure initiated" not in r.body.text()

    def set_recovery_threshold(self, remote_node, recovery_threshold):
        proposal_body, careful_vote = self.make_proposal(
            "set_recovery_threshold", recovery_threshold
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        self.recovery_threshold = recovery_threshold
        return self.vote_using_majority(remote_node, proposal)

    def add_new_code(self, remote_node, new_code_id):
        proposal_body, careful_vote = self.make_proposal("new_node_code", new_code_id)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def retire_code(self, remote_node, code_id):
        proposal_body, careful_vote = self.make_proposal("retire_node_code", code_id)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        return self.vote_using_majority(remote_node, proposal)

    def check_for_service(self, remote_node, status):
        """
        Check via the member frontend of the given node that the certificate
        associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        # When opening the service in PBFT, the first transaction to be
        # completed when f = 1 takes a significant amount of time
        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.post(
                "/gov/query",
                {
                    "text": """tables = ...
                    service = tables["public:ccf.gov.service"]:get(0)
                    if service == nil then
                        LOG_DEBUG("Service is nil")
                    else
                        LOG_DEBUG("Service version: ", tostring(service.version))
                        LOG_DEBUG("Service status: ", tostring(service.status_code))
                        cert_len = #service.cert
                        LOG_DEBUG("Service cert len: ", tostring(cert_len))
                        LOG_DEBUG("Service cert bytes: " ..
                            tostring(service.cert[math.ceil(cert_len / 4)]) .. " " ..
                            tostring(service.cert[math.ceil(cert_len / 3)]) .. " " ..
                            tostring(service.cert[math.ceil(cert_len / 2)])
                        )
                    end
                    return service
                    """
                },
                timeout=3,
            )
            current_status = r.body.json()["status"]
            current_cert = r.body.json()["cert"]

            expected_cert = open(
                os.path.join(self.common_dir, "networkcert.pem"), "rb"
            ).read()

            assert (
                current_cert == expected_cert[:-1].decode()
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.name
            ), f"Service status {current_status} (expected {status.name})"

    def _check_node_exists(self, remote_node, node_id, node_status=None):
        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.post("/gov/read", {"table": "public:ccf.gov.nodes", "key": node_id})

            if r.status_code != http.HTTPStatus.OK.value or (
                node_status and r.body.json()["status"] != node_status.name
            ):
                return False

        return True

    def wait_for_node_to_exist_in_store(
        self,
        remote_node,
        node_id,
        timeout,
        node_status=None,
    ):
        exists = False
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                if self._check_node_exists(remote_node, node_id, node_status):
                    exists = True
                    break
            except TimeoutError:
                LOG.warning(f"Node {node_id} has not been recorded in the store yet")
            time.sleep(0.5)
        if not exists:
            raise TimeoutError(
                f"Node {node_id} has not yet been recorded in the store"
                + getattr(node_status, f" with status {node_status.name}", "")
            )

    def wait_for_all_nodes_to_be_trusted(self, remote_node, nodes, timeout=3):
        for n in nodes:
            self.wait_for_node_to_exist_in_store(
                remote_node, n.node_id, timeout, infra.node.NodeStatus.TRUSTED
            )
