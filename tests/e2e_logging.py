# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.jsonrpc
import infra.notification
import suite.test_requirements as reqs
import e2e_args

from loguru import logger as LOG


@reqs.lua_generic_app
def test_update_lua(network, args):
    if args.package == "libluagenericenc":
        LOG.info("Updating Lua application")
        primary, term = network.find_primary()

        check = infra.checker.Checker()

        # Create a new lua application file (minimal app)
        # TODO: Writing to file will not be required when memberclient is deprecated
        new_app_file = "new_lua_app.lua"
        with open(new_app_file, "w") as qfile:
            qfile.write(
                """
                            return {
                            ping = [[
                                tables, args = ...
                                return {result = "pong"}
                            ]],
                            }"""
            )

        network.consortium.set_lua_app(
            member_id=1, remote_node=primary, app_script=new_app_file
        )
        with primary.user_client(format="json") as c:
            check(c.rpc("ping", params={}), result="pong")

            LOG.debug("Check that former endpoints no longer exists")
            for endpoint in [
                "LOG_record",
                "LOG_record_pub",
                "LOG_get",
                "LOG_get_pub",
            ]:
                check(
                    c.rpc(endpoint, params={}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.METHOD_NOT_FOUND.value,
                )
    else:
        LOG.warning("Skipping Lua app update as application is not Lua")

    return network


class LoggingTxs(reqs.TxInterface):
    def __init__(self):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = 0
        self.next_priv_index = 0

    def issue(self, network, number_transactions):
        primary, term = network.find_primary()

        with primary.node_client(format="json") as mc:
            check_commit = infra.checker.Checker(mc)

            LOG.info("Record on primary")
            with primary.user_client(format="json") as uc:

                for _ in range(number_transactions):
                    # TODO: Can we do this cheaper, i.e. only verify global commit for the latest transaction.
                    priv_msg = f"Private message at index {self.next_priv_index}, recorded in term {term}"
                    pub_msg = f"Public message at index {self.next_pub_index}, recorded in term {term}"
                    rep_priv = uc.rpc(
                        "LOG_record", {"id": self.next_priv_index, "msg": priv_msg,},
                    )
                    rep_pub = uc.rpc(
                        "LOG_record_pub", {"id": self.next_pub_index, "msg": pub_msg,},
                    )

                    LOG.success(rep_priv)
                    LOG.success(rep_pub)

                    check_commit(rep_priv, result=True)
                    check_commit(rep_pub, result=True)

                    self.priv[self.next_priv_index] = priv_msg
                    self.pub[self.next_pub_index] = pub_msg
                    self.next_priv_index += 1
                    self.next_pub_index += 1

    def verify(self, network):
        primary, term = network.find_primary()

        with primary.node_client(format="json") as mc:
            check = infra.checker.Checker()

            with primary.user_client(format="json") as uc:

                for pub_tx_index in self.pub:
                    LOG.warning(pub_tx_index)
                    check(
                        uc.rpc("LOG_get_pub", {"id": pub_tx_index}),
                        result={"msg": self.pub[pub_tx_index]},
                    )

                for priv_tx_index in self.priv:
                    LOG.warning(priv_tx_index)
                    check(
                        uc.rpc("LOG_get", {"id": priv_tx_index}),
                        result={"msg": self.priv[priv_tx_index]},
                    )


@reqs.supports_methods("mkSign", "LOG_record", "LOG_get")
@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None):
    LOG.info("Running transactions against logging app")
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client(format="json") as mc:
        check_commit = infra.checker.Checker(mc, notifications_queue)
        check = infra.checker.Checker()

        msg = "Hello world"
        msg2 = "Hello there"
        backup_msg = "Msg sent to a backup"

        LOG.info("Write/Read on primary")
        with primary.user_client(format="json") as c:
            check_commit(c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True)
            check_commit(c.rpc("LOG_record", {"id": 43, "msg": msg2}), result=True)
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})
            check(c.rpc("LOG_get", {"id": 43}), result={"msg": msg2})

        LOG.info("Write on all backup frontends")
        with backup.node_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)
        with backup.member_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)

        LOG.info("Write/Read on backup")

        with backup.user_client(format="json") as c:
            check_commit(
                c.rpc("LOG_record", {"id": 100, "msg": backup_msg}), result=True
            )
            check(c.rpc("LOG_get", {"id": 100}), result={"msg": backup_msg})
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})

        LOG.info("Write/Read large messages on primary")
        with primary.user_client(format="json") as c:
            id = 44
            for p in range(14, 20):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True,
                )
                check(c.rpc("LOG_get", {"id": id}), result={"msg": long_msg})
                id += 1

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        # https://github.com/microsoft/CCF/issues/415
        notifications_queue = (
            notifications.get_queue() if args.package == "libloggingenc" else None
        )

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
        ) as network:
            network.start_and_join(args)
            network = test(network, args, notifications_queue)
            network = test_update_lua(network, args)


if __name__ == "__main__":

    args = e2e_args.cli_args()
    if args.js_app_script:
        args.package = "libjsgenericenc"
    elif args.app_script:
        args.package = "libluagenericenc"
    else:
        args.package = "libloggingenc"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
