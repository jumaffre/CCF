// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "ds/spin_lock.h"
#include "impl/execution.h"
#include "impl/request_message.h"
#include "impl/state.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "node/node_to_node.h"
#include "node/node_types.h"
#include "node/progress_tracker.h"
#include "node/rpc/tx_status.h"
#include "node/signatures.h"
#include "raft_types.h"

#include <algorithm>
#include <deque>
#include <list>
#include <random>
#include <unordered_map>
#include <vector>

namespace aft
{
  using Configuration = kv::Consensus::Configuration;

  template <class LedgerProxy, class ChannelProxy, class SnapshotterProxy>
  class Aft
  {
  private:
    enum ReplicaState
    {
      Leader,
      Follower,
      Candidate,
      Retired
    };

    struct NodeState
    {
      Configuration::NodeInfo node_info;

      // the highest index sent to the node
      Index sent_idx;

      // the highest matching index with the node that was confirmed
      Index match_idx;

      NodeState() = default;

      NodeState(
        const Configuration::NodeInfo& node_info_,
        Index sent_idx_,
        Index match_idx_ = 0) :
        node_info(node_info_),
        sent_idx(sent_idx_),
        match_idx(match_idx_)
      {}
    };

    ConsensusType consensus_type;
    std::unique_ptr<Store<kv::DeserialiseSuccess>> store;

    // Persistent
    NodeId voted_for;

    // Volatile
    NodeId leader_id;
    std::unordered_set<NodeId> votes_for_me;

    ReplicaState replica_state;
    std::chrono::milliseconds timeout_elapsed;
    // Last (committable) index preceding the node's election, this is
    // used to decide when to start issuing signatures. While commit_idx
    // hasn't caught up with election_index, a newly elected leader is
    // effectively finishing establishing commit over the previous term
    // or even previous terms, and can therefore not meaningfully sign
    // over the commit level.
    kv::Version election_index = 0;

    // BFT
    RequestsMap& bft_requests_map;
    std::shared_ptr<aft::State> state;
    std::shared_ptr<Executor> executor;

    // Timeouts
    std::chrono::milliseconds request_timeout;
    std::chrono::milliseconds election_timeout;

    // Configurations
    std::list<Configuration> configurations;
    std::unordered_map<NodeId, NodeState> nodes;

    size_t entry_size_not_limited = 0;
    size_t entry_count = 0;
    Index entries_batch_size = 1;
    static constexpr int batch_window_size = 100;
    int batch_window_sum = 0;

    // Indices that are eligible for global commit, from a Node's perspective
    std::deque<Index> committable_indices;

    // When this is set, only public domain is deserialised when receving append
    // entries
    bool public_only = false;

    // Randomness
    std::uniform_int_distribution<int> distrib;
    std::default_random_engine rand;

  public:
    static constexpr size_t append_entries_size_limit = 20000;
    std::unique_ptr<LedgerProxy> ledger;
    std::shared_ptr<ccf::NodeToNode> channels;
    std::shared_ptr<SnapshotterProxy> snapshotter;
    std::shared_ptr<enclave::RPCSessions> rpc_sessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;

  public:
    Aft(
      ConsensusType consensus_type_,
      std::unique_ptr<Store<kv::DeserialiseSuccess>> store_,
      std::unique_ptr<LedgerProxy> ledger_,
      std::shared_ptr<ccf::NodeToNode> channels_,
      std::shared_ptr<SnapshotterProxy> snapshotter_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      const std::vector<uint8_t>& /*cert*/,
      RequestsMap& requests_map,
      std::shared_ptr<aft::State> state_,
      std::shared_ptr<Executor> executor_,
      std::chrono::milliseconds request_timeout_,
      std::chrono::milliseconds election_timeout_,
      bool public_only_ = false) :
      consensus_type(consensus_type_),
      store(std::move(store_)),
      voted_for(NoNode),

      replica_state(Follower),
      timeout_elapsed(0),

      bft_requests_map(requests_map),
      state(state_),
      executor(executor_),

      request_timeout(request_timeout_),
      election_timeout(election_timeout_),
      public_only(public_only_),

      distrib(0, (int)election_timeout_.count() / 2),
      rand((int)(uintptr_t)this),

      ledger(std::move(ledger_)),
      channels(channels_),
      snapshotter(snapshotter_),
      rpc_sessions(rpc_sessions_),
      rpc_map(rpc_map_)

    {
      leader_id = NoNode;

      if (consensus_type == ConsensusType::BFT)
      {
        // Initialize view history for bft. We start on view 2 and the first
        // commit is always 1.
        state->view_history.update(1, 2);
      }
    }

    NodeId leader()
    {
      return leader_id;
    }

    NodeId id()
    {
      return state->my_node_id;
    }

    bool is_leader()
    {
      return replica_state == Leader;
    }

    bool is_follower()
    {
      return replica_state == Follower;
    }

    Index last_committable_index() const
    {
      return committable_indices.empty() ? state->commit_idx :
                                           committable_indices.back();
    }

    void enable_all_domains()
    {
      // When receiving append entries as a follower, all security domains will
      // be deserialised
      std::lock_guard<SpinLock> guard(state->lock);
      public_only = false;
    }

    void force_become_leader()
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<SpinLock> guard(state->lock);
      state->current_view += 2;
      become_leader();
    }

    void force_become_leader(
      Index index,
      Term term,
      const std::vector<Index>& terms,
      Index commit_idx_)
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      std::lock_guard<SpinLock> guard(state->lock);
      state->current_view = term;
      state->last_idx = index;
      state->commit_idx = commit_idx_;
      state->view_history.initialise(terms);
      state->view_history.update(index, term);
      state->current_view += 2;
      become_leader();
    }

    void init_as_follower(
      Index index, Term term, const std::vector<Index>& term_history)
    {
      // This should only be called when the node resumes from a snapshot and
      // before it has received any append entries.
      std::lock_guard<SpinLock> guard(state->lock);

      state->last_idx = index;
      state->commit_idx = index;

      state->view_history.initialise(term_history);

      ledger->init(index);
      snapshotter->set_last_snapshot_idx(index);

      become_follower(term);
    }

    Index get_last_idx()
    {
      return state->last_idx;
    }

    Index get_commit_idx()
    {
      if (consensus_type == ConsensusType::BFT && is_follower())
      {
        return state->commit_idx;
      }
      std::lock_guard<SpinLock> guard(state->lock);
      return state->commit_idx;
    }

    Term get_term()
    {
      if (consensus_type == ConsensusType::BFT && is_follower())
      {
        return state->current_view;
      }
      std::lock_guard<SpinLock> guard(state->lock);
      return state->current_view;
    }

    std::pair<Term, Index> get_commit_term_and_idx()
    {
      if (consensus_type == ConsensusType::BFT && is_follower())
      {
        return {get_term_internal(state->commit_idx), state->commit_idx};
      }
      std::lock_guard<SpinLock> guard(state->lock);
      return {get_term_internal(state->commit_idx), state->commit_idx};
    }

    std::optional<std::pair<Term, Index>> get_signable_commit_term_and_idx()
    {
      std::lock_guard<SpinLock> guard(state->lock);
      if (state->commit_idx >= election_index)
      {
        return std::pair<Term, Index>{get_term_internal(state->commit_idx),
                                      state->commit_idx};
      }
      else
      {
        return std::nullopt;
      }
    }

    Term get_term(Index idx)
    {
      if (consensus_type == ConsensusType::BFT && is_follower())
      {
        return get_term_internal(idx);
      }
      std::lock_guard<SpinLock> guard(state->lock);
      return get_term_internal(idx);
    }

    std::vector<Index> get_term_history(Index idx)
    {
      // This should only be called when the spin lock is held.
      return state->view_history.get_history_until(idx);
    }

    void initialise_term_history(const std::vector<Index>& term_history)
    {
      // This should only be called when the spin lock is held.
      return state->view_history.initialise(term_history);
    }

    void add_configuration(Index idx, const Configuration::Nodes& conf)
    {
      // This should only be called when the spin lock is held.
      configurations.push_back({idx, std::move(conf)});
      create_and_remove_node_state();
    }

    Configuration::Nodes get_latest_configuration() const
    {
      if (configurations.empty())
      {
        return {};
      }

      return configurations.back().nodes;
    }

    uint32_t node_count() const
    {
      return get_latest_configuration().size();
    }

    template <typename T>
    bool replicate(
      const std::vector<std::tuple<Index, T, bool>>& entries, Term term)
    {
      if (consensus_type == ConsensusType::BFT && is_follower())
      {
        for (auto& [index, data, globally_committable] : entries)
        {
          state->last_idx = index;
          ledger->put_entry(*data, globally_committable, false);
        }
        return true;
      }

      std::lock_guard<SpinLock> guard(state->lock);

      if (replica_state != Leader)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items: not leader", entries.size());
        rollback(state->last_idx);
        return false;
      }

      if (term != state->current_view)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items at term {}, current term is {}",
          entries.size(),
          term,
          state->current_view);
        return false;
      }

      LOG_DEBUG_FMT("Replicating {} entries", entries.size());

      for (auto& [index, data, is_globally_committable] : entries)
      {
        bool globally_committable =
          is_globally_committable || consensus_type == ConsensusType::BFT;

        if (index != state->last_idx + 1)
          return false;

        LOG_DEBUG_FMT(
          "Replicated on leader {}: {}{}",
          state->my_node_id,
          index,
          (globally_committable ? " committable" : ""));

        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          committable_indices.push_back(index);

          // Only if globally committable, a snapshot requires a new ledger
          // chunk to be created
          force_ledger_chunk = snapshotter->requires_snapshot(index);
        }

        state->last_idx = index;
        ledger->put_entry(*data, globally_committable, force_ledger_chunk);
        entry_size_not_limited += data->size();
        entry_count++;

        state->view_history.update(index, state->current_view);
        if (entry_size_not_limited >= append_entries_size_limit)
        {
          update_batch_size();
          entry_count = 0;
          entry_size_not_limited = 0;
          for (const auto& it : nodes)
          {
            LOG_DEBUG_FMT("Sending updates to follower {}", it.first);
            send_append_entries(it.first, it.second.sent_idx + 1);
          }
        }
      }

      // If we are the only node, attempt to commit immediately.
      if (nodes.size() == 0)
      {
        update_commit();
      }

      return true;
    }
    void recv_message(const uint8_t* data, size_t size)
    {
      recv_message(OArray({data, data + size}));
    }

    void recv_message(OArray&& d)
    {
      const uint8_t* data = d.data();
      size_t size = d.size();
      // The host does a CALLIN to this when a Aft message
      // is received. Invalid or malformed messages are ignored
      // without informing the host. Messages are idempotent,
      // so it is not necessary to defend against replay attacks.
      switch (serialized::peek<RaftMsgType>(data, size))
      {
        case raft_append_entries:
          recv_append_entries(data, size);
          break;

        case raft_append_entries_response:
          recv_append_entries_response(data, size);
          break;

        case raft_append_entries_signed_response:
          recv_append_entries_signed_response(data, size);
          break;

        case raft_request_vote:
          recv_request_vote(data, size);
          break;

        case raft_request_vote_response:
          recv_request_vote_response(data, size);
          break;

        case bft_signature_received_ack:
          recv_signature_received_ack(data, size);
          break;

        case bft_nonce_reveal:
          recv_nonce_reveal(data, size);
          break;

        default:
        {
        }
      }
    }

    void periodic(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(state->lock);
      timeout_elapsed += elapsed;

      if (replica_state == Leader)
      {
        if (timeout_elapsed >= request_timeout)
        {
          using namespace std::chrono_literals;
          timeout_elapsed = 0ms;

          update_batch_size();
          // Send newly available entries to all nodes.
          for (const auto& it : nodes)
          {
            send_append_entries(it.first, it.second.sent_idx + 1);
          }
        }
      }
      else
      {
        if (replica_state != Retired && timeout_elapsed >= election_timeout)
        {
          // Start an election.
          become_candidate();
        }
      }
    }

    bool is_first_request = true;

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args)
    {
      auto request = executor->create_request_message(args);
      executor->execute_request(std::move(request), is_first_request);
      is_first_request = false;

      return true;
    }

  private:
    inline void update_batch_size()
    {
      auto avg_entry_size = (entry_count == 0) ?
        append_entries_size_limit :
        entry_size_not_limited / entry_count;

      auto batch_size = (avg_entry_size == 0) ?
        append_entries_size_limit / 2 :
        append_entries_size_limit / avg_entry_size;

      auto batch_avg = batch_window_sum / batch_window_size;
      // balance out total batch size across batch window
      batch_window_sum += (batch_size - batch_avg);
      entries_batch_size = std::max((batch_window_sum / batch_window_size), 1);
    }

    Term get_term_internal(Index idx)
    {
      if (idx > state->last_idx)
        return ccf::VIEW_UNKNOWN;

      return state->view_history.view_at(idx);
    }

    void send_append_entries(NodeId to, Index start_idx)
    {
      Index end_idx = (state->last_idx == 0) ?
        0 :
        std::min(start_idx + entries_batch_size, state->last_idx);

      for (Index i = end_idx; i < state->last_idx; i += entries_batch_size)
      {
        send_append_entries_range(to, start_idx, i);
        start_idx = std::min(i + 1, state->last_idx);
      }

      if (state->last_idx == 0 || end_idx <= state->last_idx)
      {
        send_append_entries_range(to, start_idx, state->last_idx);
      }
    }

    void send_append_entries_range(NodeId to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;
      const auto prev_term = get_term_internal(prev_idx);
      const auto term_of_idx = get_term_internal(end_idx);

      LOG_DEBUG_FMT(
        "Send append entries from {} to {}: {} to {} ({})",
        state->my_node_id,
        to,
        start_idx,
        end_idx,
        state->commit_idx);

      AppendEntries ae = {{raft_append_entries, state->my_node_id},
                          {end_idx, prev_idx},
                          state->current_view,
                          prev_term,
                          state->commit_idx,
                          term_of_idx};

      auto& node = nodes.at(to);

      // The host will append log entries to this message when it is
      // sent to the destination node.
      if (!channels->send_authenticated(
            ccf::NodeMsgType::consensus_msg, to, ae))
      {
        return;
      }

      // Record the most recent index we have sent to this node.
      node.sent_idx = end_idx;
    }

    void recv_append_entries(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(state->lock);
      AppendEntries r;

      try
      {
        r = channels->template recv_authenticated<AppendEntries>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      LOG_DEBUG_FMT(
        "Received pt: {} pi: {} t: {} i: {} toi: {}",
        r.prev_term,
        r.prev_idx,
        r.term,
        r.idx,
        r.term_of_idx);

      // Don't check that the sender node ID is valid. Accept anything that
      // passes the integrity check. This way, entries containing dynamic
      // topology changes that include adding this new leader can be accepted.

      // First, check append entries term against our own term, becoming
      // follower if necessary
      if (state->current_view == r.term && replica_state == Candidate)
      {
        // Become a follower in this term.
        become_follower(r.term);
      }
      else if (state->current_view < r.term)
      {
        // Become a follower in the new term.
        become_follower(r.term);
      }
      else if (state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_INFO_FMT(
          "Recv append entries to {} from {} but our term is later ({} > {})",
          state->my_node_id,
          r.from_node,
          state->current_view,
          r.term);
        send_append_entries_response(r.from_node, false);
        return;
      }

      // Second, check term consistency with the entries we have so far
      const auto prev_term = get_term_internal(r.prev_idx);
      if (prev_term != r.prev_term)
      {
        LOG_DEBUG_FMT(
          "Previous term for {} should be {}", r.prev_idx, prev_term);

        // Reply false if the log doesn't contain an entry at r.prev_idx
        // whose term is r.prev_term.
        if (prev_term == 0)
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log does not yet "
            "contain index {}",
            state->my_node_id,
            r.from_node,
            r.prev_idx);
        }
        else
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log at {} has the wrong "
            "previous term (ours: {}, theirs: {})",
            state->my_node_id,
            r.from_node,
            r.prev_idx,
            prev_term,
            r.prev_term);
        }
        send_append_entries_response(r.from_node, false);
        return;
      }

      // If the terms match up, it is sufficient to convince us that the sender
      // is leader in our term
      restart_election_timeout();
      if (leader_id != r.from_node)
      {
        leader_id = r.from_node;
        LOG_DEBUG_FMT(
          "Node {} thinks leader is {}", state->my_node_id, leader_id);
      }

      // Third, check index consistency, making sure entries are not in the past
      // or in the future
      if (r.prev_idx < state->commit_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}) < commit_idx "
          "({})",
          state->my_node_id,
          r.from_node,
          r.prev_idx,
          state->commit_idx);
        return;
      }
      else if (r.prev_idx > state->last_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}) > last_idx ({})",
          state->my_node_id,
          r.from_node,
          r.prev_idx,
          state->last_idx);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries to {} from {} for index {} and previous index {}",
        state->my_node_id,
        r.from_node,
        r.idx,
        r.prev_idx);

      // Finally, deserialise each entry in the batch
      for (Index i = r.prev_idx + 1; i <= r.idx; i++)
      {
        if (i <= state->last_idx)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          ledger->skip_entry(data, size);
          continue;
        }

        LOG_DEBUG_FMT("Replicating on follower {}: {}", state->my_node_id, i);

        std::vector<uint8_t> entry;
        try
        {
          entry = ledger->get_entry(data, size);
        }
        catch (const std::logic_error& e)
        {
          // This should only fail if there is malformed data.
          LOG_FAIL_FMT(
            "Recv append entries to {} from {} but the data is malformed: {}",
            state->my_node_id,
            r.from_node,
            e.what());
          send_append_entries_response(r.from_node, false);
          return;
        }

        state->last_idx = i;

        Term sig_term = 0;
        Index sig_index = 0;
        auto tx = store->create_tx();
        kv::DeserialiseSuccess deserialise_success;
        ccf::PrimarySignature sig;
        if (consensus_type == ConsensusType::BFT)
        {
          deserialise_success = store->deserialise_views(
            entry, public_only, &sig_term, &sig_index, &tx, &sig);
        }
        else
        {
          deserialise_success =
            store->deserialise(entry, public_only, &sig_term);
        }

        bool globally_committable =
          (deserialise_success == kv::DeserialiseSuccess::PASS_SIGNATURE);
        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          force_ledger_chunk = snapshotter->requires_snapshot(i);
        }

        ledger->put_entry(entry, globally_committable, force_ledger_chunk);

        switch (deserialise_success)
        {
          case kv::DeserialiseSuccess::FAILED:
          {
            LOG_FAIL_FMT("Follower failed to apply log entry: {}", i);
            state->last_idx--;
            send_append_entries_response(r.from_node, false);
            break;
          }

          case kv::DeserialiseSuccess::PASS_SIGNATURE:
          {
            LOG_DEBUG_FMT("Deserialising signature at {}", i);
            auto prev_lci = last_committable_index();
            committable_indices.push_back(i);

            if (sig_term)
            {
              // A signature for sig_term tells us that all transactions from
              // the previous signature onwards (at least, if not further back)
              // happened in sig_term. We reflect this in the history.
              if (r.term_of_idx == aft::ViewHistory::InvalidView)
                state->view_history.update(1, r.term);
              else
                state->view_history.update(prev_lci + 1, sig_term);
              commit_if_possible(r.leader_commit_idx);
            }
            if (consensus_type == ConsensusType::BFT)
            {
              send_append_entries_signed_response(r.from_node, sig);
            }
            break;
          }

          case kv::DeserialiseSuccess::PASS_BACKUP_SIGNATURE:
          {
            break;
          }

          case kv::DeserialiseSuccess::PASS_BACKUP_SIGNATURE_SEND_ACK:
          {
            try_send_sig_ack(
              {sig_term, sig_index},
              kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK);
            break;
          }

          case kv::DeserialiseSuccess::PASS_NONCES:
          {
            break;
          }

          case kv::DeserialiseSuccess::PASS:
          {
            if (consensus_type == ConsensusType::BFT)
            {
              state->last_idx = executor->commit_replayed_request(tx);
            }
            break;
          }

          case kv::DeserialiseSuccess::PASS_SNAPSHOT_EVIDENCE:
          {
            break;
          }

          default:
          {
            throw std::logic_error("Unknown DeserialiseSuccess value");
          }
        }
      }

      // After entries have been deserialised, we try to commit the leader's
      // commit index and update our term history accordingly
      commit_if_possible(r.leader_commit_idx);

      // The term may have changed, and we have not have seen a signature yet.
      auto lci = last_committable_index();
      if (r.term_of_idx == aft::ViewHistory::InvalidView)
        state->view_history.update(1, r.term);
      else
        state->view_history.update(lci + 1, r.term_of_idx);

      send_append_entries_response(r.from_node, true);
    }

    void send_append_entries_response(NodeId to, bool answer)
    {
      LOG_DEBUG_FMT(
        "Send append entries response from {} to {} for index {}: {}",
        state->my_node_id,
        to,
        state->last_idx,
        answer);

      AppendEntriesResponse response = {
        {raft_append_entries_response, state->my_node_id},
        state->current_view,
        state->last_idx,
        answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void send_append_entries_signed_response(
      NodeId to, ccf::PrimarySignature& sig)
    {
      LOG_DEBUG_FMT(
        "Send append entries signed response from {} to {} for index {}",
        state->my_node_id,
        to,
        state->last_idx);

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      auto h = progress_tracker->get_my_hashed_nonce(
        {state->current_view, state->last_idx});

      Nonce hashed_nonce;
      std::copy(h.begin(), h.end(), hashed_nonce.begin());

      SignedAppendEntriesResponse r = {
        {raft_append_entries_signed_response, state->my_node_id},
        state->current_view,
        state->last_idx,
        hashed_nonce,
        static_cast<uint32_t>(sig.sig.size()),
        {}};
      std::copy(sig.sig.begin(), sig.sig.end(), r.sig.data());

      auto result = progress_tracker->add_signature(
        {r.term, r.last_log_idx},
        r.from_node,
        r.signature_size,
        r.sig,
        hashed_nonce,
        node_count(),
        is_leader());
      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        auto send_to = it->first;
        if (send_to != state->my_node_id)
        {
          channels->send_authenticated(
            ccf::NodeMsgType::consensus_msg, send_to, r);
        }
      }

      try_send_sig_ack({r.term, r.last_log_idx}, result);
    }

    void recv_append_entries_signed_response(const uint8_t* data, size_t size)
    {
      SignedAppendEntriesResponse r;

      try
      {
        r = channels->template recv_authenticated<SignedAppendEntriesResponse>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Error in recv_authenticated message");
        LOG_DEBUG_FMT("Error in recv_authenticated message: {}", err.what());
        return;
      }

      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv signed append entries response to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      auto result = progress_tracker->add_signature(
        {r.term, r.last_log_idx},
        r.from_node,
        r.signature_size,
        r.sig,
        r.hashed_nonce,
        node_count(),
        is_leader());
      try_send_sig_ack({r.term, r.last_log_idx}, result);
    }

    void try_send_sig_ack(kv::TxID tx_id, kv::TxHistory::Result r)
    {
      switch (r)
      {
        case kv::TxHistory::Result::OK:
        case kv::TxHistory::Result::FAIL:
        {
          break;
        }
        case kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK:
        {
          SignaturesReceivedAck r = {
            {bft_signature_received_ack, state->my_node_id},
            tx_id.term,
            tx_id.version};
          for (auto it = nodes.begin(); it != nodes.end(); ++it)
          {
            auto send_to = it->first;
            if (send_to != state->my_node_id)
            {
              channels->send_authenticated(
                ccf::NodeMsgType::consensus_msg, send_to, r);
            }
          }

          auto progress_tracker = store->get_progress_tracker();
          CCF_ASSERT(
            progress_tracker != nullptr, "progress_tracker is not set");
          auto result = progress_tracker->add_signature_ack(
            tx_id, state->my_node_id, node_count());
          try_send_reply_and_nonce(tx_id, result);
          break;
        }
        default:
        {
          throw ccf::ccf_logic_error(fmt::format("Unknown enum type: {}", r));
        }
      }
    }

    void recv_signature_received_ack(const uint8_t* data, size_t size)
    {
      SignaturesReceivedAck r;

      try
      {
        r = channels->template recv_authenticated<SignaturesReceivedAck>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Error in recv_signature_received_ack message");
        LOG_DEBUG_FMT(
          "Error in recv_signature_received_ack message: {}", err.what());
        return;
      }

      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv signature received ack to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      LOG_TRACE_FMT(
        "processing recv_signature_received_ack, from:{} view:{}, seqno:{}",
        r.from_node,
        r.term,
        r.idx);
      auto result = progress_tracker->add_signature_ack(
        {r.term, r.idx}, r.from_node, node_count());
      try_send_reply_and_nonce({r.term, r.idx}, result);
    }

    void try_send_reply_and_nonce(kv::TxID tx_id, kv::TxHistory::Result r)
    {
      switch (r)
      {
        case kv::TxHistory::Result::OK:
        case kv::TxHistory::Result::FAIL:
        {
          break;
        }
        case kv::TxHistory::Result::SEND_REPLY_AND_NONCE:
        {
          Nonce nonce;
          auto progress_tracker = store->get_progress_tracker();
          CCF_ASSERT(
            progress_tracker != nullptr, "progress_tracker is not set");
          nonce = progress_tracker->get_my_nonce(tx_id);
          NonceRevealMsg r = {{bft_nonce_reveal, state->my_node_id},
                              tx_id.term,
                              tx_id.version,
                              nonce};

          for (auto it = nodes.begin(); it != nodes.end(); ++it)
          {
            auto send_to = it->first;
            if (send_to != state->my_node_id)
            {
              channels->send_authenticated(
                ccf::NodeMsgType::consensus_msg, send_to, r);
            }
          }
          progress_tracker->add_nonce_reveal(
            tx_id, nonce, state->my_node_id, node_count(), is_leader());
          break;
        }
        default:
        {
          throw ccf::ccf_logic_error(fmt::format("Unknown enum type: {}", r));
        }
      }
    }

    void recv_nonce_reveal(const uint8_t* data, size_t size)
    {
      NonceRevealMsg r;

      try
      {
        r = channels->template recv_authenticated<NonceRevealMsg>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Error in recv_signature_received_ack message");
        LOG_DEBUG_FMT(
          "Error in recv_signature_received_ack message: {}", err.what());
        return;
      }

      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv nonce reveal to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      LOG_TRACE_FMT(
        "processing nonce_reveal, from:{} view:{}, seqno:{}",
        r.from_node,
        r.term,
        r.idx);
      progress_tracker->add_nonce_reveal(
        {r.term, r.idx}, r.nonce, r.from_node, node_count(), is_leader());

      update_commit();
    }

    void recv_append_entries_response(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(state->lock);
      // Ignore if we're not the leader.
      if (replica_state != Leader)
        return;

      AppendEntriesResponse r;

      try
      {
        r = channels->template recv_authenticated<AppendEntriesResponse>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv append entries response to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }
      else if (state->current_view < r.term)
      {
        // We are behind, convert to a follower.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: more recent term",
          state->my_node_id,
          r.from_node);
        become_follower(r.term);
        return;
      }
      else if (state->current_view != r.term)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale term",
          state->my_node_id,
          r.from_node);
        if (r.success)
          return;
      }
      else if (r.last_log_idx < node->second.match_idx)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale idx",
          state->my_node_id,
          r.from_node);
        if (r.success)
          return;
      }

      // Update next and match for the responding node.
      node->second.match_idx = std::min(r.last_log_idx, state->last_idx);

      if (!r.success)
      {
        // Failed due to log inconsistency. Reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: failed",
          state->my_node_id,
          r.from_node);
        send_append_entries(r.from_node, node->second.match_idx + 1);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries response to {} from {} for index {}: success",
        state->my_node_id,
        r.from_node,
        r.last_log_idx);
      update_commit();
    }

    void send_request_vote(NodeId to)
    {
      LOG_INFO_FMT("Send request vote from {} to {}", state->my_node_id, to);

      auto last_committable_idx = last_committable_index();
      CCF_ASSERT(last_committable_idx >= state->commit_idx, "lci < ci");

      RequestVote rv = {{raft_request_vote, state->my_node_id},
                        state->current_view,
                        last_committable_idx,
                        get_term_internal(last_committable_idx)};

      channels->send_authenticated(ccf::NodeMsgType::consensus_msg, to, rv);
    }

    void recv_request_vote(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(state->lock);
      RequestVote r;

      try
      {
        r = channels->template recv_authenticated<RequestVote>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        LOG_FAIL_FMT(
          "Recv request vote to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }

      if (state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: our term is later ({} > {})",
          state->my_node_id,
          r.from_node,
          state->current_view,
          r.term);
        send_request_vote_response(r.from_node, false);
        return;
      }
      else if (state->current_view < r.term)
      {
        // Become a follower in the new term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: their term is later ({} < {})",
          state->my_node_id,
          r.from_node,
          state->current_view,
          r.term);
        become_follower(r.term);
      }

      if ((voted_for != NoNode) && (voted_for != r.from_node))
      {
        // Reply false, since we already voted for someone else.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: already voted for {}",
          state->my_node_id,
          r.from_node,
          voted_for);
        send_request_vote_response(r.from_node, false);
        return;
      }

      // If the candidate's committable log is at least as up-to-date as ours,
      // vote yes

      auto last_committable_idx = last_committable_index();
      auto term_of_last_committable_index =
        get_term_internal(last_committable_idx);

      auto answer =
        (r.term_of_last_committable_idx > term_of_last_committable_index) ||
        ((r.term_of_last_committable_idx == term_of_last_committable_index) &&
         (r.last_committable_idx >= last_committable_idx));

      if (answer)
      {
        // If we grant our vote, we also acknowledge that an election is in
        // progress.
        restart_election_timeout();
        leader_id = NoNode;
        voted_for = r.from_node;
      }

      send_request_vote_response(r.from_node, answer);
    }

    void send_request_vote_response(NodeId to, bool answer)
    {
      LOG_INFO_FMT(
        "Send request vote response from {} to {}: {}",
        state->my_node_id,
        to,
        answer);

      RequestVoteResponse response = {
        {raft_request_vote_response, state->my_node_id},
        state->current_view,
        answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void recv_request_vote_response(const uint8_t* data, size_t size)
    {
      if (replica_state != Candidate)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {}: we aren't a candidate",
          state->my_node_id);
        return;
      }

      RequestVoteResponse r;

      try
      {
        r = channels->template recv_authenticated<RequestVoteResponse>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: unknown node",
          state->my_node_id,
          r.from_node);
        return;
      }

      if (state->current_view < r.term)
      {
        // Become a follower in the new term.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: their term is more recent "
          "({} < {})",
          state->my_node_id,
          r.from_node,
          state->current_view,
          r.term);
        become_follower(r.term);
        return;
      }
      else if (state->current_view != r.term)
      {
        // Ignore as it is stale.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: stale ({} != {})",
          state->my_node_id,
          r.from_node,
          state->current_view,
          r.term);
        return;
      }
      else if (!r.vote_granted)
      {
        // Do nothing.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: they voted no",
          state->my_node_id,
          r.from_node);
        return;
      }

      LOG_INFO_FMT(
        "Recv request vote response to {} from {}: they voted yes",
        state->my_node_id,
        r.from_node);
      add_vote_for_me(r.from_node);
    }

    void restart_election_timeout()
    {
      // Randomise timeout_elapsed to get a random election timeout
      // between 0.5x and 1x the configured election timeout.
      timeout_elapsed = std::chrono::milliseconds(distrib(rand));
    }

    void become_candidate()
    {
      replica_state = Candidate;
      leader_id = NoNode;
      voted_for = state->my_node_id;
      votes_for_me.clear();
      state->current_view++;

      restart_election_timeout();
      add_vote_for_me(state->my_node_id);

      LOG_INFO_FMT(
        "Becoming candidate {}: {}", state->my_node_id, state->current_view);

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        channels->create_channel(
          it->first, it->second.node_info.hostname, it->second.node_info.port);
        send_request_vote(it->first);
      }
    }

    void become_leader()
    {
      election_index = last_committable_index();
      LOG_DEBUG_FMT("Election index is {}", election_index);
      // Discard any un-committable updates we may hold,
      // since we have no signature for them. Except at startup,
      // where we do not want to roll back the genesis transaction.
      if (state->commit_idx)
      {
        rollback(election_index);
      }
      else
      {
        // but we still want the KV to know which term we're in
        store->set_term(state->current_view);
      }

      replica_state = Leader;
      leader_id = state->my_node_id;

      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;

      LOG_INFO_FMT(
        "Becoming leader {}: {}", state->my_node_id, state->current_view);

      // Immediately commit if there are no other nodes.
      if (nodes.size() == 0)
      {
        commit(state->last_idx);
        return;
      }

      // Reset next, match, and sent indices for all nodes.
      auto next = state->last_idx + 1;

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        it->second.match_idx = 0;
        it->second.sent_idx = next - 1;

        // Send an empty append_entries to all nodes.
        send_append_entries(it->first, next);
      }
    }

    void become_follower(Term term)
    {
      replica_state = Follower;
      leader_id = NoNode;
      restart_election_timeout();

      state->current_view = term;
      voted_for = NoNode;
      votes_for_me.clear();

      rollback(last_committable_index());

      LOG_INFO_FMT(
        "Becoming follower {}: {}", state->my_node_id, state->current_view);
      channels->close_all_outgoing();
    }

    void become_retired()
    {
      replica_state = Retired;
      leader_id = NoNode;

      LOG_INFO_FMT(
        "Becoming retired {}: {}", state->my_node_id, state->current_view);
      channels->destroy_all_channels();
    }

    void add_vote_for_me(NodeId from)
    {
      // Need 50% + 1 of the total nodes, which are the other nodes plus us.
      votes_for_me.insert(from);

      if (votes_for_me.size() >= ((nodes.size() + 1) / 2) + 1)
        become_leader();
    }

    void update_commit()
    {
      // If there exists some idx in the current term such that
      // idx > commit_idx and a majority of nodes have replicated it,
      // commit to that idx.
      auto new_commit_cft_idx = std::numeric_limits<Index>::max();
      auto new_commit_bft_idx = std::numeric_limits<Index>::max();

      // Obtain BFT watermarks
      auto progress_tracker = store->get_progress_tracker();
      if (progress_tracker != nullptr)
      {
        new_commit_bft_idx = progress_tracker->get_highest_committed_nonce();
      }

      // Obtain CFT watermarks
      for (auto& c : configurations)
      {
        // The majority must be checked separately for each active
        // configuration.
        std::vector<Index> match;
        match.reserve(c.nodes.size() + 1);

        for (auto node : c.nodes)
        {
          if (node.first == state->my_node_id)
          {
            match.push_back(state->last_idx);
          }
          else
          {
            match.push_back(nodes.at(node.first).match_idx);
          }
        }

        sort(match.begin(), match.end());
        auto confirmed = match.at((match.size() - 1) / 2);

        if (confirmed < new_commit_cft_idx)
        {
          new_commit_cft_idx = confirmed;
        }
      }
      LOG_DEBUG_FMT(
        "In update_commit, new_commit_cft_idx: {}, new_commit_bft_idx:{}. "
        "last_idx: {}",
        new_commit_cft_idx,
        new_commit_bft_idx,
        state->last_idx);

      if (new_commit_cft_idx != std::numeric_limits<Index>::max())
      {
        state->cft_watermark_idx = new_commit_cft_idx;
      }

      if (new_commit_bft_idx != std::numeric_limits<Index>::max())
      {
        state->bft_watermark_idx = new_commit_bft_idx;
      }

      if (get_commit_watermark_idx() > state->last_idx)
      {
        throw std::logic_error(
          "Followers appear to have later match indices than leader");
      }

      commit_if_possible(get_commit_watermark_idx());
    }

    void commit_if_possible(Index idx)
    {
      LOG_DEBUG_FMT(
        "Commit if possible {} (ci: {}) (ti {})",
        idx,
        state->commit_idx,
        get_term_internal(idx));
      if (
        (idx > state->commit_idx) &&
        (get_term_internal(idx) <= state->current_view))
      {
        Index highest_committable = 0;
        bool can_commit = false;
        while (!committable_indices.empty() &&
               (committable_indices.front() <= idx))
        {
          highest_committable = committable_indices.front();
          committable_indices.pop_front();
          can_commit = true;
        }

        if (can_commit)
          commit(highest_committable);
      }
    }

    void commit(Index idx)
    {
      if (idx > state->last_idx)
      {
        throw std::logic_error(fmt::format(
          "Tried to commit {} but last_idx is {}", idx, state->last_idx));
      }

      LOG_DEBUG_FMT("Starting commit");

      // This could happen if a follower becomes the leader when it
      // has committed fewer log entries, although it has them available.
      if (idx <= state->commit_idx)
        return;

      state->commit_idx = idx;

      LOG_DEBUG_FMT("Compacting...");
      snapshotter->compact(idx);
      if (replica_state == Leader)
      {
        snapshotter->snapshot(idx);
      }
      store->compact(idx);
      ledger->commit(idx);

      LOG_DEBUG_FMT("Commit on {}: {}", state->my_node_id, idx);

      // Examine all configurations that are followed by a globally committed
      // configuration.
      bool changed = false;

      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
          break;

        auto next = std::next(conf);
        if (next == configurations.end())
          break;

        if (idx < next->idx)
          break;

        configurations.pop_front();
        changed = true;
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    Index get_commit_watermark_idx()
    {
      if (consensus_type == ConsensusType::BFT)
      {
        return state->bft_watermark_idx;
      }
      else
      {
        return state->cft_watermark_idx;
      }
    }

    void rollback(Index idx)
    {
      snapshotter->rollback(idx);
      store->rollback(idx, state->current_view);
      LOG_DEBUG_FMT("Setting term in store to: {}", state->current_view);
      ledger->truncate(idx);
      state->last_idx = idx;
      LOG_DEBUG_FMT("Rolled back at {}", idx);

      while (!committable_indices.empty() && (committable_indices.back() > idx))
      {
        committable_indices.pop_back();
      }

      // Rollback configurations.
      bool changed = false;

      while (!configurations.empty() && (configurations.back().idx > idx))
      {
        configurations.pop_back();
        changed = true;
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    void create_and_remove_node_state()
    {
      // Find all nodes present in any active configuration.
      Configuration::Nodes active_nodes;

      for (auto& conf : configurations)
      {
        for (auto node : conf.nodes)
        {
          active_nodes.emplace(node.first, node.second);
        }
      }

      // Remove all nodes in the node state that are not present in any active
      // configuration.
      std::vector<NodeId> to_remove;

      for (auto& node : nodes)
      {
        if (active_nodes.find(node.first) == active_nodes.end())
        {
          to_remove.push_back(node.first);
        }
      }

      for (auto node_id : to_remove)
      {
        if (replica_state == Leader || consensus_type == ConsensusType::BFT)
        {
          channels->destroy_channel(node_id);
        }
        nodes.erase(node_id);
        LOG_INFO_FMT("Removed raft node {}", node_id);
      }

      // Add all active nodes that are not already present in the node state.
      bool self_is_active = false;

      for (auto node_info : active_nodes)
      {
        if (node_info.first == state->my_node_id)
        {
          self_is_active = true;
          continue;
        }

        if (nodes.find(node_info.first) == nodes.end())
        {
          // A new node is sent only future entries initially. If it does not
          // have prior data, it will communicate that back to the leader.
          auto index = state->last_idx + 1;
          nodes.try_emplace(node_info.first, node_info.second, index, 0);

          if (replica_state == Leader || consensus_type == ConsensusType::BFT)
          {
            channels->create_channel(
              node_info.first,
              node_info.second.hostname,
              node_info.second.port);
          }

          if (replica_state == Leader)
          {
            send_append_entries(node_info.first, index);
          }

          LOG_INFO_FMT("Added raft node {}", node_info.first);
        }
      }

      if (!self_is_active)
      {
        LOG_INFO_FMT("Removed raft self {}", state->my_node_id);
        if (replica_state == Leader)
        {
          become_retired();
        }
      }
    }
  };
}
