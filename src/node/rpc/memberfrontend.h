// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "frontend.h"
#include "luainterp/txscriptrunner.h"
#include "node/genesisgen.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/quoteverification.h"
#include "tls/entropy.h"
#include "tls/keypair.h"

#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace ccf
{
  struct SetUserData
  {
    UserId user_id;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetUserData)
  DECLARE_JSON_REQUIRED_FIELDS(SetUserData, user_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetUserData, user_data)

  class MemberHandlers : public CommonHandlerRegistry
  {
  private:
    Script get_script(Store::Tx& tx, std::string name)
    {
      const auto s = tx.get_view(network.gov_scripts)->get(name);
      if (!s)
        throw std::logic_error(
          fmt::format("Could not find gov script: {}", name));
      return *s;
    }

    void set_app_scripts(
      Store::Tx& tx, std::map<std::string, std::string> scripts)
    {
      auto tx_scripts = tx.get_view(network.app_scripts);

      // First, remove all existing handlers
      tx_scripts->foreach(
        [&tx_scripts](const std::string& name, const Script& script) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, lua::compile(rs.second));
      }
    }

    void set_js_scripts(
      Store::Tx& tx, std::map<std::string, std::string> scripts)
    {
      auto tx_scripts = tx.get_view(network.app_scripts);

      // First, remove all existing handlers
      tx_scripts->foreach(
        [&tx_scripts](const std::string& name, const Script& script) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, {rs.second});
      }
    }

    //! Table of functions that proposal scripts can propose to invoke
    const std::unordered_map<
      std::string,
      std::function<bool(Store::Tx&, const nlohmann::json&)>>
      hardcoded_funcs = {
        // set the lua application script
        {"set_lua_app",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_app_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));

           return true;
         }},
        // set the js application script
        {"set_js_app",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_js_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));
           return true;
         }},
        // add a new member
        {"new_member",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<MemberPubInfo>();
           GenesisGenerator g(this->network, tx);
           auto new_member_id =
             g.add_member(parsed.cert, parsed.keyshare, MemberStatus::ACCEPTED);

           auto ack = tx.get_view(this->network.member_acks);
           ack->put(new_member_id, {rng->random(SIZE_NONCE)});

           return true;
         }},
        // add a new user
        {"new_user",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const Cert pem_cert = args;

           GenesisGenerator g(this->network, tx);
           g.add_user(pem_cert);

           return true;
         }},
        {"set_user_data",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<SetUserData>();
           auto users_view = tx.get_view(this->network.users);
           auto user_info = users_view->get(parsed.user_id);
           if (!user_info.has_value())
           {
             throw std::logic_error(
               fmt::format("{} is not a valid user ID", parsed.user_id));
           }

           user_info->user_data = parsed.user_data;
           users_view->put(parsed.user_id, *user_info);
           return true;
         }},
        // accept a node
        {"trust_node",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<NodeId>();
           auto nodes = tx.get_view(this->network.nodes);
           auto info = nodes->get(id);
           if (!info)
           {
             throw std::logic_error(fmt::format("Node {} does not exist", id));
           }
           if (info->status == NodeStatus::RETIRED)
           {
             throw std::logic_error(
               fmt::format("Node {} is already retired", id));
           }
           info->status = NodeStatus::TRUSTED;
           nodes->put(id, *info);
           LOG_INFO_FMT("Node {} is now {}", id, info->status);
           return true;
         }},
        // retire a node
        {"retire_node",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<NodeId>();
           auto nodes = tx.get_view(this->network.nodes);
           auto info = nodes->get(id);
           if (!info)
           {
             throw std::logic_error(fmt::format("Node {} does not exist", id));
           }
           if (info->status == NodeStatus::RETIRED)
           {
             throw std::logic_error(
               fmt::format("Node {} is already retired", id));
           }
           info->status = NodeStatus::RETIRED;
           nodes->put(id, *info);
           LOG_INFO_FMT("Node {} is now {}", id, info->status);
           return true;
         }},
        // accept new code
        {"new_code",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<CodeDigest>();
           auto code_ids = tx.get_view(this->network.code_ids);
           auto existing_code_id = code_ids->get(id);
           if (existing_code_id)
             throw std::logic_error(fmt::format(
               "Code signature already exists with digest: {:02x}",
               fmt::join(id, "")));
           code_ids->put(id, CodeStatus::ACCEPTED);
           return true;
         }},
        {"accept_recovery",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           if (node.is_part_of_public_network())
             return node.finish_recovery(tx, args);
           else
             return false;
         }},
        {"open_network",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           return node.open_network(tx);
         }},
        {"rekey_ledger",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           return node.rekey_ledger(tx);
         }},
      };

    bool complete_proposal(Store::Tx& tx, const ObjectId id)
    {
      auto proposals = tx.get_view(this->network.proposals);
      auto proposal = proposals->get(id);
      if (!proposal)
        throw std::logic_error(fmt::format("No such proposal: {}", id));

      if (proposal->state != ProposalState::OPEN)
        throw std::logic_error(fmt::format(
          "Cannot complete non-open proposal - current state is {}",
          proposal->state));

      // run proposal script
      const auto proposed_calls = tsr.run<nlohmann::json>(
        tx,
        {proposal->script,
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         get_script(tx, GovScriptIds::ENV_PROPOSAL)},
        // vvv arguments to script vvv
        proposal->parameter);

      nlohmann::json votes;
      // Collect all member votes
      for (const auto& vote : proposal->votes)
      {
        // valid voter
        if (!check_member_active(tx, vote.first))
          continue;

        // does the voter agree?
        votes[std::to_string(vote.first)] = tsr.run<bool>(
          tx,
          {vote.second,
           {}, // can't write
           WlIds::MEMBER_CAN_READ,
           {}},
          proposed_calls);
      }

      const auto pass = tsr.run<bool>(
        tx,
        {get_script(tx, GovScriptIds::PASS),
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         {}},
        // vvv arguments to script vvv
        proposed_calls,
        votes);

      if (!pass)
        return false;

      // execute proposed calls
      ProposedCalls pc = proposed_calls;
      for (const auto& call : pc)
      {
        // proposing a hardcoded C++ function?
        const auto f = hardcoded_funcs.find(call.func);
        if (f != hardcoded_funcs.end())
        {
          if (!f->second(tx, call.args))
            return false;
          continue;
        }

        // proposing a script function?
        const auto s = tx.get_view(network.gov_scripts)->get(call.func);
        if (!s)
          continue;
        tsr.run<void>(
          tx,
          {*s,
           WlIds::MEMBER_CAN_PROPOSE, // can write!
           {},
           {}},
          call.args);
      }

      // if the vote was successful, update the proposal's state
      proposal->state = ProposalState::ACCEPTED;
      proposals->put(id, *proposal);

      return true;
    }

    bool check_member_active(Store::Tx& tx, MemberId id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_accepted(Store::Tx& tx, MemberId id)
    {
      return check_member_status(
        tx, id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED});
    }

    bool check_member_status(
      Store::Tx& tx, MemberId id, std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.get_view(this->network.members)->get(id);
      if (!member)
        return false;
      for (const auto s : allowed)
        if (member->status == s)
          return true;
      return false;
    }

    NetworkTables& network;
    AbstractNodeState& node;
    const lua::TxScriptRunner tsr;

    tls::EntropyPtr rng;
    static constexpr auto SIZE_NONCE = 16;

  public:
    MemberHandlers(NetworkTables& network, AbstractNodeState& node) :
      CommonHandlerRegistry(*network.tables, Tables::MEMBER_CERTS),
      network(network),
      node(node),
      tsr(network),
      rng(tls::create_entropy())
    {}

    void init_handlers(Store& tables_) override
    {
      CommonHandlerRegistry::init_handlers(tables_);

      auto read = [this](RequestArgs& args) {
        if (!check_member_status(
              args.tx,
              args.caller_id,
              {MemberStatus::ACTIVE, MemberStatus::ACCEPTED}))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        const auto in = args.params.get<KVRead::In>();

        const ccf::Script read_script(R"xxx(
        local tables, table_name, key = ...
        return tables[table_name]:get(key) or {}
        )xxx");

        auto value = tsr.run<nlohmann::json>(
          args.tx,
          {read_script, {}, WlIds::MEMBER_CAN_READ, {}},
          in.table,
          in.key);
        if (value.empty())
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format(
              "Key {} does not exist in table {}", in.key.dump(), in.table));
          return;
        }

        args.rpc_ctx->set_response_result(std::move(value));
        return;
      };
      install_with_auto_schema<KVRead>(MemberProcs::READ, read, Read);

      auto query = [this](RequestArgs& args) {
        if (!check_member_accepted(args.tx, args.caller_id))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        const auto script = args.params.get<ccf::Script>();
        args.rpc_ctx->set_response_result(tsr.run<nlohmann::json>(
          args.tx, {script, {}, WlIds::MEMBER_CAN_READ, {}}));
        return;
      };
      install_with_auto_schema<Script, nlohmann::json>(
        MemberProcs::QUERY, query, Read);

      auto propose = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        const auto in = args.params.get<Propose::In>();
        const auto proposal_id = get_next_id(
          args.tx.get_view(this->network.values), ValueIds::NEXT_PROPOSAL_ID);
        Proposal proposal(in.script, in.parameter, args.caller_id);
        auto proposals = args.tx.get_view(this->network.proposals);
        proposal.votes[args.caller_id] = in.ballot;
        proposals->put(proposal_id, proposal);
        const bool completed = complete_proposal(args.tx, proposal_id);
        args.rpc_ctx->set_response_result(
          Propose::Out({proposal_id, completed}));
        return;
      };
      install_with_auto_schema<Propose>(MemberProcs::PROPOSE, propose, Write);

      auto withdraw = [this](RequestArgs& args) {
        if (!check_member_status(
              args.tx, args.caller_id, {MemberStatus::ACTIVE}))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        const auto proposal_action = args.params.get<ProposalAction>();
        const auto proposal_id = proposal_action.id;
        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(proposal_id);

        if (!proposal)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format("Proposal {} does not exist", proposal_id));
          return;
        }

        if (proposal->proposer != args.caller_id)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            fmt::format(
              "Proposal {} can only be withdrawn by proposer {}, not caller {}",
              proposal_id,
              proposal->proposer,
              args.caller_id));
          return;
        }

        if (proposal->state != ProposalState::OPEN)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can be "
              "withdrawn",
              proposal_id,
              proposal->state,
              ProposalState::OPEN));
          return;
        }

        proposal->state = ProposalState::WITHDRAWN;
        proposals->put(proposal_id, *proposal);

        args.rpc_ctx->set_response_result(true);
        return;
      };
      install_with_auto_schema<ProposalAction, bool>(
        MemberProcs::WITHDRAW, withdraw, Write);

      auto vote = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        if (!args.rpc_ctx->signed_request.has_value())
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::RPC_NOT_SIGNED, "Votes must be signed");
          return;
        }

        const auto vote = args.params.get<Vote>();
        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(vote.id);
        if (!proposal)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format("Proposal {} does not exist", vote.id));
          return;
        }

        if (proposal->state != ProposalState::OPEN)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes",
              vote.id,
              proposal->state,
              ProposalState::OPEN));
          return;
        }

        // record vote
        proposal->votes[args.caller_id] = vote.ballot;
        proposals->put(vote.id, *proposal);

        auto voting_history = args.tx.get_view(this->network.voting_history);
        voting_history->put(
          args.caller_id, {args.rpc_ctx->signed_request.value()});

        args.rpc_ctx->set_response_result(complete_proposal(args.tx, vote.id));
        return;
      };
      install_with_auto_schema<Vote, bool>(MemberProcs::VOTE, vote, Write);

      auto create = [this](RequestArgs& args) {
        const auto in = args.params.get<CreateNetworkNodeToNode::In>();

        GenesisGenerator g(this->network, args.tx);

        // This endpoint can only be called once, directly from the starting
        // node for the genesis transaction to initialise the service
        if (g.is_service_created())
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "Service is already created");
          return;
        }

        g.init_values();
        for (auto& [cert, k_encryption_key] : in.members_info)
        {
          g.add_member(cert, k_encryption_key);
        }

        node.split_ledger_secrets(args.tx);

        size_t self = g.add_node({in.node_info_network,
                                  in.node_cert,
                                  in.quote,
                                  in.public_encryption_key,
                                  NodeStatus::TRUSTED});

        if (self != 0)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "Starting node ID is not 0");
          return;
        }

#ifdef GET_QUOTE
        CodeDigest node_code_id;
        std::copy_n(
          std::begin(in.code_digest),
          CODE_DIGEST_BYTES,
          std::begin(node_code_id));
        g.trust_code_id(node_code_id);
#endif

        for (const auto& wl : default_whitelists)
        {
          g.set_whitelist(wl.first, wl.second);
        }

        g.set_gov_scripts(
          lua::Interpreter().invoke<nlohmann::json>(in.gov_script));

        g.create_service(in.network_cert);

        // g.add_key_share_info(in.genesis_key_share_info);

        args.rpc_ctx->set_response_result(true);
        return;
      };
      install(MemberProcs::CREATE, create, Write);

      auto complete = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS);
          return;
        }

        const auto proposal_action = args.params.get<ProposalAction>();
        const auto proposal_id = proposal_action.id;

        args.rpc_ctx->set_response_result(
          complete_proposal(args.tx, proposal_id));
        return;
      };
      install_with_auto_schema<ProposalAction, bool>(
        MemberProcs::COMPLETE, complete, Write);

      //! A member acknowledges state
      auto ack = [this](RequestArgs& args) {
        auto mas = args.tx.get_view(this->network.member_acks);
        const auto last_ma = mas->get(args.caller_id);
        if (!last_ma)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            fmt::format("No ACK record exists for caller {}", args.caller_id));
          return;
        }

        auto verifier = tls::make_verifier(
          std::vector<uint8_t>(args.rpc_ctx->session.caller_cert));
        const auto rs = args.params.get<RawSignature>();
        if (!verifier->verify(last_ma->next_nonce, rs.sig))
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Signature is not valid");
          return;
        }

        MemberAck next_ma{rs.sig, rng->random(SIZE_NONCE)};
        mas->put(args.caller_id, next_ma);

        // update member status to ACTIVE
        auto members = args.tx.get_view(this->network.members);
        auto member = members->get(args.caller_id);
        if (member->status == MemberStatus::ACCEPTED)
        {
          member->status = MemberStatus::ACTIVE;
        }
        members->put(args.caller_id, *member);
        args.rpc_ctx->set_response_result(true);
        return;
      };
      // ACK method cannot be forwarded and should be run on primary as it makes
      // explicit use of caller certificate
      install_with_auto_schema<RawSignature, bool>(
        MemberProcs::ACK, ack, Write, Forwardable::DoNotForward);

      //! A member asks for a fresher nonce
      auto update_ack_nonce = [this](RequestArgs& args) {
        auto mas = args.tx.get_view(this->network.member_acks);
        auto ma = mas->get(args.caller_id);
        if (!ma)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            fmt::format("No ACK record exists for caller {}", args.caller_id));
          return;
        }
        ma->next_nonce = rng->random(SIZE_NONCE);
        mas->put(args.caller_id, *ma);
        args.rpc_ctx->set_response_result(true);
        return;
      };
      install_with_auto_schema<void, bool>(
        MemberProcs::UPDATE_ACK_NONCE, update_ack_nonce, Write);
    }
  };

  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    std::string invalid_caller_error_message() const override
    {
      return "Could not find matching member certificate";
    }

    MemberHandlers member_handlers;
    Members* members;

  public:
    MemberRpcFrontend(NetworkTables& network, AbstractNodeState& node) :
      RpcFrontend(
        *network.tables, member_handlers, &network.member_client_signatures),
      member_handlers(network, node),
      members(&network.members)
    {}

    std::vector<uint8_t> get_cert_to_forward(
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      // Caller cert can be looked up on receiver - so don't forward it
      return {};
    }

    bool lookup_forwarded_caller_cert(
      std::shared_ptr<enclave::RpcContext> ctx, Store::Tx& tx) override
    {
      // Lookup the caller member's certificate from the forwarded caller id
      auto members_view = tx.get_view(*members);
      auto caller = members_view->get(ctx->session.fwd->caller_id);
      if (!caller.has_value())
      {
        return false;
      }

      ctx->session.caller_cert = caller.value().cert;
      return true;
    }
  };
} // namespace ccf
