// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"
#include "node/members.h"
#include "node/network_encryption.h"
#include "node/node_info_network.h"

#include <nlohmann/json.hpp>
#include <openenclave/advanced/mallinfo.h>

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

  struct GetState
  {
    using In = void;

    struct Out
    {
      ccf::NodeId id;
      ccf::State state;
      kv::Version last_signed_seqno;

      // Only on recovery
      std::optional<kv::Version> recovery_target_seqno;
      std::optional<kv::Version> last_recovered_seqno;
    };
  };

  struct GetQuotes
  {
    using In = void;

    struct Quote
    {
      NodeId node_id = {};
      std::string raw = {}; // < Hex-encoded

      std::string error = {};
      std::string mrenclave = {}; // < Hex-encoded
    };

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  struct CreateNetworkNodeToNode
  {
    struct In
    {
      std::vector<MemberPubInfo> members_info;
      std::string gov_script;
      tls::Pem node_cert;
      tls::Pem network_cert;
      std::vector<uint8_t> quote;
      tls::Pem public_encryption_key;
      std::vector<uint8_t> code_digest;
      NodeInfoNetwork node_info_network;
      ConsensusType consensus_type = ConsensusType::CFT;
      size_t recovery_threshold;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      NodeInfoNetwork node_info_network;
      std::vector<uint8_t> quote;
      tls::Pem public_encryption_key;
      ConsensusType consensus_type = ConsensusType::CFT;
    };

    struct Out
    {
      NodeStatus node_status;
      NodeId node_id;

      // Only if the caller node is trusted
      struct NetworkInfo
      {
        bool public_only = false;
        kv::Version last_recovered_signed_idx = kv::NoVersion;
        ConsensusType consensus_type = ConsensusType::CFT;

        LedgerSecrets ledger_secrets;
        NetworkIdentity identity;
        NetworkEncryptionKey encryption_key;

        bool operator==(const NetworkInfo& other) const
        {
          return public_only == other.public_only &&
            last_recovered_signed_idx == other.last_recovered_signed_idx &&
            consensus_type == other.consensus_type &&
            ledger_secrets == other.ledger_secrets &&
            identity == other.identity &&
            encryption_key == other.encryption_key;
        }

        bool operator!=(const NetworkInfo& other) const
        {
          return !(*this == other);
        }
      };

      NetworkInfo network_info;
    };
  };

  struct MemoryUsage
  {
    using In = void;

    struct Out
    {
      Out(const oe_mallinfo_t& info) :
        max_total_heap_size(info.max_total_heap_size),
        current_allocated_heap_size(info.current_allocated_heap_size),
        peak_allocated_heap_size(info.peak_allocated_heap_size)
      {}
      Out() = default;

      size_t max_total_heap_size = 0;
      size_t current_allocated_heap_size = 0;
      size_t peak_allocated_heap_size = 0;
    };
  };
}