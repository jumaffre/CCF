# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager, closing
from enum import Enum
import infra.remote
import infra.net
import infra.path
import ccf.clients
import os
import socket
import time
import re

from loguru import logger as LOG


class NodeNetworkState(Enum):
    stopped = 0
    started = 1
    joined = 2


class NodeStatus(Enum):
    PENDING = 0
    TRUSTED = 1
    RETIRED = 2


def is_addr_local(host, port):
    with closing(socket.socket()) as s:
        try:
            s.bind((host, port or 0))
            return True
        except OSError:
            return False


def is_snapshot_committed(file_name):
    return file_name.endswith(".committed")


def get_snapshot_seqno(file_name):
    return int(re.findall(r"\d+", file_name)[0])


class Node:
    def __init__(self, node_id, host, binary_dir=".", debug=False, perf=False):
        self.node_id = node_id
        self.binary_dir = binary_dir
        self.debug = debug
        self.perf = perf
        self.remote = None
        self.network_state = NodeNetworkState.stopped
        self.common_dir = None

        hosts, *port = host.split(":")
        self.host, *self.pubhost = hosts.split(",")
        self.rpc_port = int(port[0]) if port else None
        self.node_port = None

        if self.host == "localhost":
            self.host = infra.net.expand_localhost()

        if is_addr_local(self.host, self.rpc_port):
            self.remote_impl = infra.remote.LocalRemote
        else:
            self.remote_impl = infra.remote.SSHRemote

        self.pubhost = self.pubhost[0] if self.pubhost else self.host

    def __hash__(self):
        return self.node_id

    def __eq__(self, other):
        return self.node_id == other.node_id

    def start(
        self,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        members_info,
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.new,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            members_info=members_info,
            **kwargs,
        )
        self.network_state = NodeNetworkState.joined

    def join(
        self,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        target_rpc_address,
        snapshot_dir,
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.join,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address=target_rpc_address,
            snapshot_dir=snapshot_dir,
            **kwargs,
        )

    def recover(self, lib_name, enclave_type, workspace, label, common_dir, **kwargs):
        self._start(
            infra.remote.StartType.recover,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            **kwargs,
        )
        self.network_state = NodeNetworkState.joined

    def _start(
        self,
        start_type,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        target_rpc_address=None,
        snapshot_dir=None,
        members_info=None,
        **kwargs,
    ):
        """
        Creates a CCFRemote instance, sets it up (connects, creates the directory
        and ships over the files), and (optionally) starts the node by executing
        the appropriate command.
        If self.debug is set, it will not actually start up the node, but will
        prompt the user to do so manually.
        """
        lib_path = infra.path.build_lib_path(lib_name, enclave_type)
        self.common_dir = common_dir
        self.remote = infra.remote.CCFRemote(
            start_type,
            lib_path,
            str(self.node_id),
            self.host,
            self.pubhost,
            self.node_port,
            self.rpc_port,
            self.remote_impl,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address=target_rpc_address,
            members_info=members_info,
            snapshot_dir=snapshot_dir,
            binary_dir=self.binary_dir,
            **kwargs,
        )
        self.remote.setup()
        self.network_state = NodeNetworkState.started
        if self.debug:
            with open("/tmp/vscode-gdb.sh", "a") as f:
                f.write(f"if [ $1 -eq {self.remote.local_node_id} ]; then\n")
                f.write(f"cd {self.remote.remote.root}\n")
                f.write(f"{' '.join(self.remote.remote.cmd)}\n")
                f.write("fi\n")

            print("")
            phost = "localhost" if self.host.startswith("127.") else self.host
            print(
                "================= Please run the below command on "
                + phost
                + " and press enter to continue ================="
            )
            print("")
            print(self.remote.debug_node_cmd())
            print("")
            input("Press Enter to continue...")
        else:
            if self.perf:
                self.remote.set_perf()
            self.remote.start()
        self.remote.get_startup_files(self.common_dir)
        self._read_ports()
        LOG.info("Node {} started".format(self.node_id))

    def _read_ports(self):
        node_address_path = os.path.join(self.common_dir, self.remote.node_address_path)
        with open(node_address_path, "r") as f:
            node_host, node_port = f.read().splitlines()
            node_port = int(node_port)
            assert (
                node_host == self.host
            ), f"Unexpected change in node address from {self.host} to {node_host}"
            if self.node_port is not None:
                assert (
                    node_port == self.node_port
                ), f"Unexpected change in node port from {self.node_port} to {node_port}"
            self.node_port = node_port

        rpc_address_path = os.path.join(self.common_dir, self.remote.rpc_address_path)
        with open(rpc_address_path, "r") as f:
            rpc_host, rpc_port = f.read().splitlines()
            rpc_port = int(rpc_port)
            assert (
                rpc_host == self.host
            ), f"Unexpected change in RPC address from {self.host} to {rpc_host}"
            if self.rpc_port is not None:
                assert (
                    rpc_port == self.rpc_port
                ), f"Unexpected change in RPC port from {self.rpc_port} to {rpc_port}"
            self.rpc_port = rpc_port

    def stop(self):
        if self.remote and self.network_state is not NodeNetworkState.stopped:
            self.network_state = NodeNetworkState.stopped
            return self.remote.stop()
        return [], []

    def is_stopped(self):
        return self.network_state == NodeNetworkState.stopped

    def is_joined(self):
        return self.network_state == NodeNetworkState.joined

    def wait_for_node_to_join(self, timeout=3):
        """
        This function can be used to check that a node has successfully
        joined a network and that it is part of the consensus.
        """
        # Until the node has joined, the SSL handshake will fail as the node
        # is not yet endorsed by the network certificate

        try:
            with self.client(connection_timeout=timeout) as nc:
                rep = nc.get("/node/commit")
                assert (
                    rep.status_code == 200
                ), f"An error occured after node {self.node_id} joined the network: {rep.body}"
        except ccf.clients.CCFConnectionException as e:
            raise TimeoutError(f"Node {self.node_id} failed to join the network") from e

    def get_ledger(self, **kwargs):
        return self.remote.get_ledger(**kwargs)

    def get_committed_snapshots(self):
        # Wait for all available snapshot files to be committed before
        # copying snapshot directory
        def wait_for_snapshots_to_be_committed(src_dir, list_src_dir_func, timeout=3):
            end_time = time.time() + timeout
            committed = True
            uncommitted_snapshots = []
            while time.time() < end_time:
                committed = True
                uncommitted_snapshots = []
                for f in list_src_dir_func(src_dir):
                    is_committed = is_snapshot_committed(f)
                    if not is_committed:
                        uncommitted_snapshots.append(f)
                    committed &= is_committed
                if committed:
                    break
                time.sleep(0.1)
            if not committed:
                LOG.error(
                    f"Error: Not all snapshots were committed after {timeout}s in {src_dir}: {uncommitted_snapshots}"
                )
            return committed

        return self.remote.get_committed_snapshots(wait_for_snapshots_to_be_committed)

    def client_certs(self, identity=None):
        return {
            "cert": os.path.join(self.common_dir, f"{identity}_cert.pem")
            if identity
            else None,
            "key": os.path.join(self.common_dir, f"{identity}_privk.pem")
            if identity
            else None,
            "ca": os.path.join(self.common_dir, "networkcert.pem"),
        }

    def client(self, identity=None, **kwargs):
        akwargs = self.client_certs(identity)
        akwargs.update(
            {
                "description": f"[{self.node_id}{'|' + identity if identity is not None else ''}]",
            }
        )
        akwargs.update(kwargs)
        return ccf.clients.client(self.pubhost, self.rpc_port, **akwargs)

    def suspend(self):
        self.remote.suspend()
        LOG.info(f"Node {self.node_id} suspended...")

    def resume(self):
        self.remote.resume()
        LOG.info(f"Node {self.node_id} has resumed from suspension.")


@contextmanager
def node(node_id, host, binary_directory, debug=False, perf=False, pdb=False):
    """
    Context manager for Node class.
    :param node_id: unique ID of node
    :param binary_directory: the directory where CCF's binaries are located
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :return: a Node instance that can be used to build a CCF network
    """
    this_node = Node(
        node_id=node_id, host=host, binary_dir=binary_directory, debug=debug, perf=perf
    )
    try:
        yield this_node
    except Exception:
        if pdb:
            import pdb

            pdb.set_trace()
        else:
            raise
    finally:
        this_node.stop()
