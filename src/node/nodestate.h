// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "calltypes.h"
#include "consensus/ledgerenclave.h"
#include "consensus/raft/raftconsensus.h"
#include "crypto/cryptobox.h"
#include "ds/logger.h"
#include "enclave/rpcsessions.h"
#include "encryptor.h"
#include "entities.h"
#include "genesisgen.h"
#include "history.h"
#include "networkstate.h"
#include "nodetonode.h"
#include "notifier.h"
#include "rpc/consts.h"
#include "rpc/frontend.h"
#include "rpc/memberfrontend.h"
#include "rpc/serialization.h"
#include "seal.h"
#include "secretshare.h"
#include "timer.h"
#include "tls/25519.h"
#include "tls/client.h"
#include "tls/entropy.h"

#ifdef PBFT
#  include "consensus/pbft/pbft.h"
#endif

#ifndef VIRTUAL_ENCLAVE
#  include <ccf_t.h>
#endif

#include <atomic>
#include <chrono>
#include <fmt/format_header_only.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <unordered_set>
#include <vector>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

namespace ccf
{
  enum class State
  {
    uninitialized,
    initialized,
    pending,
    partOfPublicNetwork,
    partOfNetwork,
    readingPublicLedger,
    readingPrivateLedger
  };
}

// Used by fmtlib to render ccf::State
namespace std
{
  std::ostream& operator<<(std::ostream& os, ccf::State s)
  {
    switch (s)
    {
      case ccf::State::uninitialized:
        return os << "uninitialized";
      case ccf::State::initialized:
        return os << "initialized";
      case ccf::State::pending:
        return os << "pending";
      case ccf::State::partOfPublicNetwork:
        return os << "partOfPublicNetwork";
      case ccf::State::partOfNetwork:
        return os << "partOfNetwork";
      case ccf::State::readingPublicLedger:
        return os << "readingPublicLedger";
      case ccf::State::readingPrivateLedger:
        return os << "readingPrivateLedger";
      default:
        return os << "unknown value";
    }
  }
}

namespace ccf
{
  using RaftConsensusType =
    raft::RaftConsensus<consensus::LedgerEnclave, NodeToNode>;
  using RaftType = raft::Raft<consensus::LedgerEnclave, NodeToNode>;

#ifdef PBFT
  using PbftConsensusType = pbft::Pbft<consensus::LedgerEnclave, NodeToNode>;
#endif

  template <typename T>
  class StateMachine
  {
    std::atomic<T> s;

  public:
    StateMachine(T s) : s(s) {}
    void expect(T s) const
    {
      auto state = this->s.load();
      if (s != state)
      {
        throw std::logic_error(
          fmt::format("State is {}, but expected {}", state, s));
      }
    }

    bool check(T s) const
    {
      return s == this->s.load();
    }

    void advance(T s)
    {
      LOG_DEBUG_FMT("Advancing to state {} (from {})", s, this->s.load());
      this->s.store(s);
    }
  };

  class NodeState : public ccf::AbstractNodeState
  {
  private:
    template <typename T>
    using Result = std::pair<T, bool>;

    template <typename T>
    static Result<T> Success(T&& v)
    {
      return {std::forward<T>(v), true};
    }

    template <typename T>
    static Result<T> Fail()
    {
      return {{}, false};
    }

    template <typename T>
    static Result<T> Fail(const char* s)
    {
      LOG_DEBUG_FMT(s);
      return {{}, false};
    }

    //
    // this node's core state
    //
    StateMachine<State> sm;
    SpinLock lock;

    NodeId self;
    tls::KeyPairPtr node_sign_kp;
    tls::KeyPairPtr node_encrypt_kp;
    std::vector<uint8_t> node_cert;
    CodeDigest node_code_id;

    //
    // kv store, replication, and I/O
    //
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;
    raft::Config raft_config;

    NetworkState& network;

    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    ccf::Notifier& notifier;
    Timers& timers;

    std::shared_ptr<kv::TxHistory> history;
    std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

    std::shared_ptr<Seal> seal;

    //
    // join protocol
    //
    jsonrpc::SeqNo join_seq_no = 1;
    std::shared_ptr<Timer> join_timer;

    //
    // recovery
    //
    NodeInfoNetwork node_info_network;
    std::shared_ptr<Store> recovery_store;
    std::shared_ptr<kv::TxHistory> recovery_history;
    std::shared_ptr<kv::AbstractTxEncryptor> recovery_encryptor;
    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> term_history;
    kv::Version last_recovered_commit_idx = 1;

    consensus::Index ledger_idx = 0;

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<enclave::RPCSessions> rpcsessions,
      ccf::Notifier& notifier,
      Timers& timers) :
      sm(State::uninitialized),
      self(INVALID_ID),
      node_sign_kp(tls::make_key_pair()),
      node_encrypt_kp(tls::make_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      notifier(notifier),
      timers(timers),
      seal(std::make_shared<Seal>(writer_factory))
    {
      ::EverCrypt_AutoConfig2_init();
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const raft::Config& raft_config_,
      std::shared_ptr<NodeToNode> n2n_channels_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder_)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::uninitialized);

      raft_config = raft_config_;
      n2n_channels = n2n_channels_;
      // Capture rpc_map to pass to pbft for frontend execution
      rpc_map = rpc_map_;
      cmd_forwarder = cmd_forwarder_;
      sm.advance(State::initialized);
    }

    //
    // funcs in state "initialized"
    //
    auto create(const CreateNew::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::initialized);

      create_node_cert(args.config);
      open_node_frontend();

      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
        return Fail<CreateNew::Out>("Quote could not be retrieved");
      quote = quote_opt.value();
#endif

      switch (args.start_type)
      {
        case StartType::New:
        {
          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");
          network.ledger_secrets = std::make_shared<LedgerSecrets>(seal);
          // TODO: This key should be passed to all nodes when they join
          network.encryption_priv_key =
            tls::create_entropy()->random(crypto::BoxKey::KEY_SIZE);

          // TODO: Remove
          // auto key_share_info =
          //   generate_key_share_info(args.config.genesis.members_info);

          self = 0; // The first node id is always 0

#ifdef PBFT
          setup_pbft(args.config);
#else
          setup_raft();
#endif
          setup_history();
          setup_encryptor();

          // Become the primary and force replication
          consensus->force_become_primary();

          // Open member frontend for members to configure and open the
          // network
          open_member_frontend();

          if (!create_and_send_request(args, quote))
          {
            return Fail<CreateNew::Out>(
              "Genesis transaction could not be committed");
          }

          accept_network_tls_connections(args.config);

          sm.advance(State::partOfNetwork);

          return Success<CreateNew::Out>(
            {node_cert, quote, network.identity->cert});
        }
        case StartType::Join:
        {
          // TLS connections are not endorsed by the network until the node has
          // joined
          accept_node_tls_connections();

          sm.advance(State::pending);

          return Success<CreateNew::Out>({node_cert, quote});
        }
        case StartType::Recover:
        {
          node_info_network = args.config.node_info_network;

          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");
          // Create temporary network secrets but do not seal yet
          network.ledger_secrets = std::make_shared<LedgerSecrets>(seal, false);

          setup_history();
          setup_encryptor();

          // Accept members connections for members to finish recovery once the
          // public ledger has been read
          open_member_frontend();

          accept_network_tls_connections(args.config);

          sm.advance(State::readingPublicLedger);

          return Success<CreateNew::Out>(
            {node_cert, quote, network.identity->cert});
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Node was started in unknown mode {}", args.start_type));
        }
      }
    }

    //
    // funcs in state "pending"
    //
    void initiate_join(const Join::In& args)
    {
      auto network_ca =
        std::make_shared<tls::CA>(args.config.joining.network_cert);
      auto join_client_cert = std::make_unique<tls::Cert>(
        network_ca, node_cert, node_sign_kp->private_key_pem());

      // Create RPC client and connect to remote node
      auto join_client =
        rpcsessions->create_client(std::move(join_client_cert));

      join_client->connect(
        args.config.joining.target_host,
        args.config.joining.target_port,
        [this, args](const std::vector<uint8_t>& data) {
          std::lock_guard<SpinLock> guard(lock);
          if (!sm.check(State::pending))
          {
            return false;
          }

          auto j = jsonrpc::unpack(data, jsonrpc::Pack::Text);

          jsonrpc::Response<JoinNetworkNodeToNode::Out> resp;
          try
          {
            resp = jsonrpc::Response<JoinNetworkNodeToNode::Out>(j);
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT(
              "An error occurred while joining the network {}", j.dump());
            return false;
          }

          // Set network secrets, node id and become part of network.
          if (resp->node_status == NodeStatus::TRUSTED)
          {
            network.identity =
              std::make_unique<NetworkIdentity>(resp->network_info.identity);
            network.ledger_secrets = std::make_shared<LedgerSecrets>(
              std::move(resp->network_info.ledger_secrets), seal);

            self = resp->node_id;
#ifdef PBFT
            setup_pbft(args.config);
#else
            setup_raft(resp->public_only);
#endif
            setup_history();
            setup_encryptor();

            open_member_frontend();

            accept_network_tls_connections(args.config);

            if (resp->public_only)
            {
              sm.advance(State::partOfPublicNetwork);
            }
            else
            {
              sm.advance(State::partOfNetwork);
            }

            join_timer.reset();

            LOG_INFO_FMT(
              "Node has now joined the network as node {}: {}",
              self,
              (resp->public_only ? "public only" : "all domains"));
          }
          else if (resp->node_status == NodeStatus::PENDING)
          {
            LOG_INFO_FMT(
              "Node {} is waiting for votes of members to be trusted",
              resp->node_id);
          }

          return true;
        });

      // Send RPC request to remote node to join the network.
      jsonrpc::ProcedureCall<JoinNetworkNodeToNode::In> join_rpc;
      join_rpc.id = join_seq_no++;
      std::stringstream ss;
      ss << "nodes/" << ccf::NodeProcs::JOIN;
      join_rpc.method = ss.str();
      join_rpc.params.node_info_network = args.config.node_info_network;
      join_rpc.params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();

      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
      {
        throw std::logic_error("Quote could not be retrieved");
      }
      quote = quote_opt.value();
#endif
      join_rpc.params.quote = quote;

      LOG_DEBUG_FMT(
        "Sending join request to {}:{}",
        args.config.joining.target_host,
        args.config.joining.target_port);

      join_client->send_request(
        join_rpc.method, jsonrpc::pack(join_rpc, jsonrpc::Pack::Text));
    }

    void join(const Join::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::pending);

      initiate_join(args);

      join_timer = timers.new_timer(
        std::chrono::milliseconds(args.config.joining.join_timer),
        [this, args]() {
          if (sm.check(State::pending))
          {
            initiate_join(args);
            return true;
          }
          return false;
        });
      join_timer->start();
    }

    //
    // funcs in state "readingPublicLedger"
    //
    void start_ledger_recovery()
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPublicLedger);
      LOG_INFO_FMT("Start public recovery");
      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPublicLedger);

      LOG_DEBUG_FMT(
        "Deserialising public ledger entry ({})", ledger_entry.size());

      // When reading the public ledger, deserialise in the real store
      auto result = network.tables->deserialise(ledger_entry, true);
      if (result == kv::DeserialiseSuccess::FAILED)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in public ledger");
        network.tables->rollback(ledger_idx - 1);
        recover_public_ledger_end_unsafe();
        return;
      }

      // If the ledger entry is a signature, it is safe to compact the store
      if (result == kv::DeserialiseSuccess::PASS_SIGNATURE)
      {
        network.tables->compact(ledger_idx);
        Store::Tx tx;
        GenesisGenerator g(network, tx);
        auto last_sig = g.get_last_signature();
        if (last_sig.has_value())
        {
          LOG_DEBUG_FMT(
            "Read signature at {} for term {}", ledger_idx, last_sig->term);
          for (auto i = term_history.size(); i <= last_sig->term; ++i)
          {
            term_history.push_back(last_recovered_commit_idx + 1);
          }
          last_recovered_commit_idx = ledger_idx;
        }
        else
        {
          throw std::logic_error("Invalid signature");
        }
      }

      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_end_unsafe()
    {
      sm.expect(State::readingPublicLedger);

      // When reaching the end of the public ledger, truncate to last signed
      // index and promote network secrets to this index
      Store::Tx tx;
      GenesisGenerator g(network, tx);

      auto last_sig = g.get_last_signature();
      kv::Version last_index = 0;
      if (last_sig.has_value())
        last_index = last_sig->index;

      network.tables->rollback(last_index);
      ledger_truncate(last_index);
      LOG_INFO_FMT("Truncating ledger to last signed index: {}", last_index);

      network.ledger_secrets->promote_secret(1, last_index + 1);

      g.create_service(network.identity->cert, last_index + 1);

      g.retire_active_nodes();

      // Quotes should be initialised and non-empty
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
      {
        throw std::logic_error("Quote could not be retrieved");
      }
      quote = quote_opt.value();
#endif

      self = g.add_node({node_info_network,
                         node_cert,
                         quote,
                         node_encrypt_kp->public_key_pem().raw(),
                         NodeStatus::PENDING});

      LOG_INFO_FMT("Deleted previous nodes and added self as {}", self);

      kv::Version index = 0;
      kv::Term term = 0;
      kv::Version global_commit = 0;

      auto ls = g.get_last_signature();
      if (ls.has_value())
      {
        auto s = ls.value();
        index = s.index;
        term = s.term;
        global_commit = s.commit;
      }

      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      if (h)
        h->set_node_id(self);

      setup_raft(true);

      LOG_DEBUG_FMT(
        "Restarting Raft at index: {} term: {} commit_idx {}",
        index,
        term,
        global_commit);
      consensus->force_become_primary(index, term, term_history, index);

      // Sets itself as trusted
      g.trust_node(self);

#ifdef GET_QUOTE
      g.trust_code_id(node_code_id);
#endif

      if (g.finalize() != kv::CommitSuccess::OK)
        throw std::logic_error(
          "Could not commit transaction when starting recovered public "
          "network");

      LOG_INFO_FMT("Restarted network");

      sm.advance(State::partOfPublicNetwork);
    }

    //
    // funcs in state "readingPrivateLedger"
    //
    void recover_private_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPrivateLedger);

      LOG_INFO_FMT(
        "Deserialising private ledger entry ({})", ledger_entry.size());

      // When reading the private ledger, deserialise in the recovery store
      auto result = recovery_store->deserialise(ledger_entry);
      if (result == kv::DeserialiseSuccess::FAILED)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in private ledger");
        recovery_store->rollback(ledger_idx - 1);
        recover_private_ledger_end_unsafe();
        return;
      }

      if (result == kv::DeserialiseSuccess::PASS_SIGNATURE)
        recovery_store->compact(ledger_idx);

      if (recovery_store->current_version() == recovery_v)
      {
        LOG_INFO_FMT("Reached recovery final version at {}", recovery_v);
        recover_private_ledger_end_unsafe();
      }
      else
      {
        read_ledger_idx(++ledger_idx);
      }
    }

    void recover_private_ledger_end_unsafe()
    {
      sm.expect(State::readingPrivateLedger);

      // When reaching the end of the private ledger, make sure the same
      // ledger has been read and swap in private state
      auto h = dynamic_cast<MerkleTxHistory*>(recovery_history.get());
      if (h->get_full_state_root() != recovery_root)
      {
        throw std::logic_error(
          "Root of public store does not match root of private store");
      }

      network.tables->swap_private_maps(*recovery_store.get());
      recovery_store.reset();

      // Raft should deserialise all security domains when network is opened
      consensus->enable_all_domains();

      // On backups, resume replication
      if (!consensus->is_primary())
      {
        consensus->resume_replication();
      }

      // Seal all known network secrets
      network.ledger_secrets->seal_all();

      // Open the service
      if (consensus->is_primary())
      {
        Store::Tx tx;
        GenesisGenerator g(network, tx);
        if (!g.open_service())
        {
          throw std::logic_error("Service could not be opened");
        }

        if (g.finalize() != kv::CommitSuccess::OK)
        {
          throw std::logic_error(
            "Could not commit transaction when finishing network recovery");
        }
      }

      sm.advance(State::partOfNetwork);
    }

    //
    // funcs in state "readingPublicLedger" or "readingPrivateLedger"
    //
    void recover_ledger_end()
    {
      std::lock_guard<SpinLock> guard(lock);

      if (is_reading_public_ledger())
      {
        recover_public_ledger_end_unsafe();
      }
      else if (is_reading_private_ledger())
      {
        recover_private_ledger_end_unsafe();
      }
      else
      {
        throw std::logic_error(
          "Cannot end ledger recovery if not reading public or private "
          "ledger");
      }
    }

    //
    // funcs in state "partOfPublicNetwork"
    //
    void setup_private_recovery_store()
    {
      // Setup recovery store by cloning tables of store
      recovery_store = std::make_shared<Store>();
      recovery_store->clone_schema(*network.tables);
      Signatures* recovery_signature_map =
        recovery_store->get<Signatures>(Tables::SIGNATURES);
      Nodes* recovery_nodes_map = recovery_store->get<Nodes>(Tables::NODES);

      recovery_history = std::make_shared<MerkleTxHistory>(
        *recovery_store.get(),
        self,
        *node_sign_kp,
        *recovery_signature_map,
        *recovery_nodes_map);

      recovery_encryptor =
#ifdef USE_NULL_ENCRYPTOR
        std::make_shared<NullTxEncryptor>();
#else
        // Recovery encryptor should not seal ledger secrets on compaction.
        // Since private ledger recovery is done in a temporary store, ledger
        // secrets are only sealed once the recovery is successful.
        std::make_shared<TxEncryptor>(self, network.ledger_secrets, true);
#endif

      recovery_store->set_history(recovery_history);
      recovery_store->set_encryptor(recovery_encryptor);

      // Record real store version and root
      recovery_v = network.tables->current_version();
      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      recovery_root = h->get_full_state_root();

      LOG_DEBUG_FMT("Recovery store successfully setup: {}", recovery_v);
    }

    bool finish_recovery(
      Store::Tx& tx, const nlohmann::json& sealed_secrets) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (primary)");

      // Unseal past network secrets
      auto past_secrets_idx = network.ledger_secrets->restore(sealed_secrets);

      // Emit signature to certify transactions that happened on public
      // network
      history->emit_signature();

      // For all nodes in the new network, write all past network secrets to
      // the secrets table, encrypted with the respective public keys
      for (auto const& secret_idx : past_secrets_idx)
      {
        auto secret = network.ledger_secrets->get_secret(secret_idx);
        if (!secret.has_value())
        {
          LOG_FAIL_FMT("Ledger secrets have not been restored: {}", secret_idx);
          return false;
        }

        // Do not broadcast the ledger secrets to self since they were already
        // restored from sealed file
        broadcast_ledger_secret(tx, secret.value(), secret_idx, true);
      }

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
      return true;
    }

    //
    // funcs in state "partOfNetwork" or "partOfPublicNetwork"
    //
    void tick(std::chrono::milliseconds elapsed)
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork))
        return;

      consensus->periodic(elapsed);
    }

    void node_msg(const std::vector<uint8_t>& data)
    {
      // Only process messages once part of network
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork))
      {
        return;
      }

      auto p = data.data();
      auto psize = data.size();
      Header header;
      NodeMsgType msg_type = serialized::overlay<NodeMsgType>(p, psize);

      switch (msg_type)
      {
        case channel_msg:
          n2n_channels->recv_message(p, psize);
          break;
        case consensus_msg:
          consensus->recv_message(p, psize);
          break;

        default:
        {}
      }
    }

    //
    // always available
    //
    bool is_primary() const override
    {
      return (
        (sm.check(State::partOfNetwork) ||
         sm.check(State::partOfPublicNetwork)) &&
        consensus->is_primary());
    }

    bool is_part_of_network() const override
    {
      return sm.check(State::partOfNetwork);
    }

    bool is_reading_public_ledger() const override
    {
      return sm.check(State::readingPublicLedger);
    }

    bool is_reading_private_ledger() const override
    {
      return sm.check(State::readingPrivateLedger);
    }

    bool is_part_of_public_network() const override
    {
      return sm.check(State::partOfPublicNetwork);
    }

    std::optional<std::vector<uint8_t>> get_quote()
    {
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      // Quote is over the DER-encoded node certificate
      crypto::Sha256Hash h{node_cert};
      uint8_t* report;
      size_t report_len = 0;

      oe_result_t res = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        h.h,
        h.SIZE,
        nullptr,
        0,
        &report,
        &report_len);

      if (res != OE_OK)
      {
        LOG_FAIL_FMT("Failed to get quote: {}", oe_result_str(res));
        return {};
      }

      quote.assign(report, report + report_len);
      oe_free_report(report);

      // Set own code version
      oe_report_t parsed_quote = {0};
      res = oe_parse_report(quote.data(), quote.size(), &parsed_quote);
      if (res != OE_OK)
      {
        LOG_FAIL_FMT("Failed to parse quote: {}", oe_result_str(res));
        return {};
      }

      std::copy(
        std::begin(parsed_quote.identity.unique_id),
        std::end(parsed_quote.identity.unique_id),
        std::begin(node_code_id));
#else
      throw std::logic_error("Quote retrieval is not yet implemented");
#endif
      return quote;
    }

    bool open_network(Store::Tx& tx) override
    {
      GenesisGenerator g(network, tx);
      return g.open_service();
    }

    bool rekey_ledger(Store::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfNetwork);

      // Effects of ledger rekey are only observed from the next transaction,
      // once the local hook on the secrets table has been triggered. The
      // corresponding new ledger secret is only sealed on global hook.

      auto new_ledger_secret = LedgerSecret(true);
      broadcast_ledger_secret(tx, new_ledger_secret);

      return true;
    }

    void node_quotes(Store::Tx& tx, GetQuotes::Out& result) override
    {
      auto nodes_view = tx.get_view(network.nodes);

      nodes_view->foreach([&result](const NodeId& nid, const NodeInfo& ni) {
        if (ni.status == ccf::NodeStatus::TRUSTED)
        {
          GetQuotes::Quote quote;
          quote.node_id = nid;
          quote.raw = ni.quote;

#ifdef GET_QUOTE
          oe_report_t parsed_quote = {0};
          auto res =
            oe_parse_report(ni.quote.data(), ni.quote.size(), &parsed_quote);
          if (res != OE_OK)
          {
            quote.error =
              fmt::format("Failed to parse quote: {}", oe_result_str(res));
          }
          else
          {
            quote.mrenclave = fmt::format(
              "{:02x}", fmt::join(parsed_quote.identity.unique_id, ""));
          }
#endif
          result.quotes.push_back(quote);
        }
        return true;
      });
    };

    void split_ledger_secrets(Store::Tx& tx) override
    {
      auto share_wrapping_key_raw =
        tls::create_entropy()->random(crypto::GCM_SIZE_KEY);
      auto share_wrapping_key = crypto::KeyAesGcm(share_wrapping_key_raw);

      // Once sealing is completely removed, this can be called from the
      // LedgerSecrets class directly
      crypto::GcmCipher encrypted_ls(
        network.ledger_secrets->get_secret(1)->master.size());
      share_wrapping_key.encrypt(
        encrypted_ls.hdr.get_iv(), // iv is always 0 here as the share wrapping
                                   // key is never re-used for encryption
        network.ledger_secrets->get_secret(1)->master,
        nullb,
        encrypted_ls.cipher.data(),
        encrypted_ls.hdr.tag);

      GenesisGenerator g(network, tx);
      auto active_members = g.get_active_members_keyshare();

      SecretSharing::SecretToSplit secret_to_split = {};
      std::copy_n(
        share_wrapping_key_raw.begin(),
        SecretSharing::SECRET_TO_SPLIT_LENGTH,
        secret_to_split.begin());

      // For now, the secret sharing threshold is set to the number of initial
      // members
      size_t threshold = active_members.size();
      auto shares =
        SecretSharing::split(secret_to_split, active_members.size(), threshold);

      {
        // Until recovery with key share is complete, this checks that the
        // shares can be combined
        assert(SecretSharing::combine(shares, threshold) == secret_to_split);
      }

      EncryptedSharesMap encrypted_shares;
      auto nonce = tls::create_entropy()->random(crypto::Box::NONCE_SIZE);

      size_t share_index = 0;
      for (auto const& [member_id, enc_pub_key] : active_members)
      {
        std::cout << "Encrypting share for active member " << member_id
                  << std::endl;

        auto share_raw = std::vector<uint8_t>(
          shares[share_index].begin(), shares[share_index].end());

        auto enc_pub_key_raw = tls::parse_25519_public(tls::Pem(enc_pub_key));

        auto encrypted_share = crypto::Box::create(
          share_raw, nonce, enc_pub_key_raw, network.encryption_priv_key);

        encrypted_shares[member_id] = {nonce, encrypted_share};
        share_index++;
      }

      g.add_key_share_info({encrypted_ls.serialise(), encrypted_shares});
    }

  private:
    tls::SubjectAltName get_subject_alt_name(const CCFConfig& config)
    {
      // If a domain is passed at node creation, record domain in SAN for node
      // hostname authentication over TLS. Otherwise, record IP in SAN.
      bool san_is_ip = config.domain.empty();
      return {san_is_ip ? config.node_info_network.rpchost : config.domain,
              san_is_ip};
    }

    void create_node_cert(const CCFConfig& config)
    {
      node_cert =
        node_sign_kp->self_sign("CN=CCF node", get_subject_alt_name(config));
    }

    void accept_node_tls_connections()
    {
      // Accept TLS connections, presenting self-signed (i.e. non-endorsed) node
      // certificate. Once the node is part of the network, this certificate
      // should be replaced with network-endorsed counterpart
      rpcsessions->set_cert(node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Node TLS connections now accepted");
    }

    void accept_network_tls_connections(const CCFConfig& config)
    {
      // Accept TLS connections, presenting node certificate signed by network
      // certificate
      auto nw = tls::make_key_pair({network.identity->priv_key});

      auto endorsed_node_cert = nw->sign_csr(
        node_sign_kp->create_csr(fmt::format("CN=CCF node {}", self)),
        fmt::format("CN={}", "CCF Network"),
        get_subject_alt_name(config));

      rpcsessions->set_cert(
        endorsed_node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Network TLS connections now accepted");
    }

    void open_frontend(ccf::ActorsType actor)
    {
      auto fe = rpc_map->find(actor);
      if (!fe.has_value())
      {
        throw std::logic_error(
          fmt::format("Cannot open {} frontend", (int)actor));
      }
      fe.value()->open();
    }

    void open_node_frontend()
    {
      open_frontend(ActorsType::nodes);
    }

    void open_member_frontend()
    {
      open_frontend(ActorsType::members);
    }

    void open_user_frontend()
    {
      open_frontend(ActorsType::users);
    }

    void broadcast_ledger_secret(
      Store::Tx& tx,
      const LedgerSecret& secret,
      kv::Version version = kv::NoVersion,
      bool exclude_self = false)
    {
      GenesisGenerator g(network, tx);
      auto secrets_view = tx.get_view(network.secrets);

      auto trusted_nodes = g.get_trusted_nodes(
        exclude_self ? std::make_optional(self) : std::nullopt);

      ccf::EncryptedLedgerSecrets secret_set;
      secret_set.primary_public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();

      for (auto [nid, ni] : trusted_nodes)
      {
        ccf::EncryptedLedgerSecret secret_for_node;
        secret_for_node.node_id = nid;

        // Encrypt secrets with a shared secret derived from backup public
        // key
        auto backup_pubk = tls::make_public_key(ni.encryption_pub_key);
        crypto::KeyAesGcm backup_shared_secret(
          tls::KeyExchangeContext(node_encrypt_kp, backup_pubk)
            .compute_shared_secret());

        crypto::GcmCipher gcmcipher(secret.master.size());
        auto iv = tls::create_entropy()->random(gcmcipher.hdr.get_iv().n);
        std::copy(iv.begin(), iv.end(), gcmcipher.hdr.iv);

        backup_shared_secret.encrypt(
          iv, secret.master, nullb, gcmcipher.cipher.data(), gcmcipher.hdr.tag);

        secret_for_node.encrypted_secret = gcmcipher.serialise();
        secret_set.secrets.emplace_back(std::move(secret_for_node));
      }

      secrets_view->put(version, secret_set);
    }

    std::vector<uint8_t> serialize_create_request(
      const CreateNew::In& args, const std::vector<uint8_t>& quote)
    {
      jsonrpc::ProcedureCall<CreateNetworkNodeToNode::In> create_rpc;

      create_rpc.id = 0;
      create_rpc.method = ccf::MemberProcs::CREATE;

      for (auto& m_info : args.config.genesis.members_info)
      {
        create_rpc.params.members_info.push_back(m_info);
      }

      create_rpc.params.gov_script = args.config.genesis.gov_script;
      create_rpc.params.node_cert = node_cert;
      create_rpc.params.network_cert = network.identity->cert;
      create_rpc.params.quote = quote;
      create_rpc.params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();
      create_rpc.params.code_digest =
        std::vector<uint8_t>(std::begin(node_code_id), std::end(node_code_id));
      create_rpc.params.node_info_network = args.config.node_info_network;

      nlohmann::json j = create_rpc;
      auto contents = nlohmann::json::to_msgpack(j);

      auto sig_contents = node_sign_kp->sign(contents);

      nlohmann::json sj;
      sj["req"] = j;
      sj["sig"] = sig_contents;

      return jsonrpc::pack(sj, jsonrpc::Pack::Text);
    }

    void send_create_request(const std::vector<uint8_t>& packed)
    {
      constexpr auto actor = ccf::ActorsType::members;

      auto handler = this->rpc_map->find(actor);
      if (!handler.has_value())
      {
        throw std::logic_error("Handler has no value");
      }
      auto frontend = handler.value();

      const enclave::SessionContext node_session(
        enclave::InvalidSessionId, node_cert);
      auto ctx = enclave::make_rpc_context(node_session, packed);

      ctx->is_create_request = true;
      ctx->actor = actor;

      frontend->process(ctx);
    }

    bool create_and_send_request(
      const CreateNew::In& args, const std::vector<uint8_t>& quote)
    {
      send_create_request(serialize_create_request(args, quote));
      return true;
    }

    void backup_finish_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Suspend consensus replication at recovery_v + 1 since this is called
      // from commit hook
      consensus->suspend_replication(recovery_v + 1);

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
    }

    void setup_basic_hooks()
    {
      // When a transaction that changes the configuration commits globally,
      // inform the host of any nodes that no longer need to be tracked.
      network.nodes.set_global_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          for (auto& [node_id, ni] : w)
          {
            if (ni.value.status == NodeStatus::RETIRED)
              remove_node(node_id);
          }
        });

      network.service.set_global_hook([this](
                                        kv::Version version,
                                        const Service::State& s,
                                        const Service::Write& w) {
        if (w.at(0).value.status == ServiceStatus::OPEN)
        {
          this->consensus->set_f(1);
          open_user_frontend();
          LOG_INFO_FMT("Network is OPEN, now accepting user transactions");
        }
      });

      network.secrets.set_local_hook([this](
                                       kv::Version version,
                                       const Secrets::State& s,
                                       const Secrets::Write& w) {
        bool has_secrets = false;

        for (auto& [v, secret_set] : w)
        {
          for (auto& encrypted_secret_for_node : secret_set.value.secrets)
          {
            if (encrypted_secret_for_node.node_id == self)
            {
              crypto::GcmCipher gcmcipher;
              gcmcipher.deserialise(encrypted_secret_for_node.encrypted_secret);
              std::vector<uint8_t> plain_secret(gcmcipher.cipher.size());

              auto primary_pubk = tls::make_public_key(
                secret_set.value.primary_public_encryption_key);

              crypto::KeyAesGcm primary_shared_key(
                tls::KeyExchangeContext(node_encrypt_kp, primary_pubk)
                  .compute_shared_secret());

              if (!primary_shared_key.decrypt(
                    gcmcipher.hdr.get_iv(),
                    gcmcipher.hdr.tag,
                    gcmcipher.cipher,
                    nullb,
                    plain_secret.data()))
              {
                throw std::logic_error(
                  "Decryption of past network secrets failed");
              }

              has_secrets = true;

              // If the version key is NoVersion, we are rekeying. Use the
              // version passed to the hook instead. For recovery, the version
              // of the past secrets is passed as the key.
              kv::Version secret_version = (v == kv::NoVersion) ? version : v;

              if (is_part_of_public_network())
              {
                // When recovering, set the past secret as a ledger secret to
                // be sealed at the end of the recovery
                if (!network.ledger_secrets->set_secret(
                      secret_version, plain_secret))
                {
                  throw std::logic_error(
                    "Cannot set ledger secrets because they already exist");
                }
              }
              else
              {
                // When rekeying, set the encryption key for the next version
                // onward (for the backups to deserialise this transaction
                // with the old key). The encryptor is in charge of updating
                // the ledger secrets on global commit.
                encryptor->update_encryption_key(
                  secret_version + 1, plain_secret);
              }
            }
          }
        }

        // When recovering, trigger end of recovery protocol
        if (has_secrets && is_part_of_public_network())
        {
          backup_finish_recovery();
        }
      });
    }

    void setup_n2n_channels()
    {
      n2n_channels->initialize(self, {network.identity->priv_key});
    }

    void setup_cmd_forwarder()
    {
      cmd_forwarder->initialize(self);
    }

    void setup_raft(bool public_only = false)
    {
      setup_n2n_channels();
      setup_cmd_forwarder();

      auto raft = std::make_unique<RaftType>(
        std::make_unique<raft::Adaptor<Store, kv::DeserialiseSuccess>>(
          network.tables),
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        self,
        std::chrono::milliseconds(raft_config.request_timeout),
        std::chrono::milliseconds(raft_config.election_timeout),
        public_only);

      consensus = std::make_shared<RaftConsensusType>(std::move(raft));

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      // When a node is added, even locally, inform the host so that it can
      // map the node id to a hostname and service and inform raft so that it
      // can add a new active configuration.
      network.nodes.set_local_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          auto configure = false;
          std::unordered_set<NodeId> configuration;

          for (auto& [node_id, ni] : w)
          {
            switch (ni.value.status)
            {
              case NodeStatus::PENDING:
              {
                // Pending nodes are not added to consensus until they are
                // trusted
                break;
              }
              case NodeStatus::TRUSTED:
              {
                add_node(node_id, ni.value.nodehost, ni.value.nodeport);
                configure = true;
                break;
              }
              case NodeStatus::RETIRED:
              {
                configure = true;
                break;
              }
              default:
              {}
            }
          }

          if (configure)
          {
            s.foreach([&](NodeId node_id, const Nodes::VersionV& v) {
              if (v.value.status == NodeStatus::TRUSTED)
                configuration.insert(node_id);
              return true;
            });
            consensus->add_configuration(version, move(configuration));
          }
        });

      setup_basic_hooks();
    }

    void setup_history()
    {
      // This function can be called once the node has started up and before
      // it has joined the service.
      history = std::make_shared<MerkleTxHistory>(
        *network.tables.get(),
        self,
        *node_sign_kp,
        network.signatures,
        network.nodes);

      network.tables->set_history(history);
    }

    void setup_encryptor()
    {
      // This function makes use of network secrets and should be called once
      // the node has joined the service (either via start_network() or
      // join_network())
      encryptor =
#ifdef USE_NULL_ENCRYPTOR
        std::make_shared<NullTxEncryptor>();
#else
        std::make_shared<TxEncryptor>(self, network.ledger_secrets);
#endif

      network.tables->set_encryptor(encryptor);
    }

    void add_node(
      NodeId node, const std::string& hostname, const std::string& service)
    {
      if (node != self)
      {
        RINGBUFFER_WRITE_MESSAGE(
          ccf::add_node, to_host, node, hostname, service);
      }
    }

    void remove_node(NodeId node)
    {
      if (node != self)
      {
        RINGBUFFER_WRITE_MESSAGE(ccf::remove_node, to_host, node);
      }
    }

    void read_ledger_idx(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_get, to_host, idx);
    }

    void ledger_truncate(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_truncate, to_host, idx);
    }

#ifdef PBFT
    void setup_pbft(const CCFConfig& config)
    {
      setup_n2n_channels();

      consensus = std::make_shared<PbftConsensusType>(
        std::make_unique<pbft::Adaptor<Store, kv::DeserialiseSuccess>>(
          network.tables),
        n2n_channels,
        self,
        config.signature_intervals.sig_max_tx,
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        rpc_map,
        rpcsessions,
        *network.tables->get<pbft::RequestsMap>(pbft::Tables::PBFT_REQUESTS),
        *network.tables->get<pbft::PrePreparesMap>(
          pbft::Tables::PBFT_PRE_PREPARES),
        node_sign_kp->private_key_pem().str(),
        node_cert);

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      // When a node is added, even locally, inform the host so that it can
      // map the node id to a hostname and service and inform pbft
      network.nodes.set_local_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          std::unordered_set<NodeId> configuration;
          for (auto& [node_id, ni] : w)
          {
            add_node(node_id, ni.value.nodehost, ni.value.nodeport);

            consensus->add_configuration(
              version,
              configuration,
              {node_id, ni.value.nodehost, ni.value.nodeport, ni.value.cert});
          }
        });

      setup_basic_hooks();
    }
#endif
  };
}