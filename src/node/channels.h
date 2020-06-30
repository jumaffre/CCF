// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "entities.h"
#include "nodetypes.h"
#include "tls/key_exchange.h"
#include "tls/key_pair.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace ccf
{
  using SeqNo = uint64_t;
  using GcmHdr = crypto::GcmHeader<sizeof(SeqNo)>;

  struct RecvNonce
  {
    uint8_t tid;
    uint64_t nonce : (sizeof(uint64_t) - sizeof(uint8_t)) * CHAR_BIT;

    RecvNonce(uint64_t nonce_, uint8_t tid_) : nonce(nonce_), tid(tid_) {}
    RecvNonce(const uint64_t header)
    {
      *this = *reinterpret_cast<const RecvNonce*>(&header);
    }

    uint64_t get_val() const
    {
      return *reinterpret_cast<const uint64_t*>(this);
    }
  };
  static_assert(
    sizeof(RecvNonce) == sizeof(SeqNo), "RecvNonce is the wrong size");

  enum ChannelStatus
  {
    INITIATED = 0,
    ESTABLISHED
  };

  class Channel
  {
  private:
    // Used for key exchange
    tls::KeyExchangeContext ctx;
    ChannelStatus status;

    // Indicates a channel with a node not yet known by the local store (e.g.
    // when a new node joins the network)
    bool known_by_local_store; // TODO: Unused now

    // Only use for incoming messages (e.g. follower only)
    bool incoming_only;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> key;

    // Incremented for each tagged/encrypted message
    std::atomic<SeqNo> send_nonce{1};

    // Used to prevent replayed messages.
    // Set to the latest successfully received nonce.
    struct ChannelSeqno
    {
      SeqNo main_thread_seqno;
      SeqNo tid_seqno;
    };
    std::array<ChannelSeqno, threading::ThreadMessaging::max_num_threads>
      local_recv_nonce = {0};

    bool verify_or_decrypt(
      const GcmHdr& header,
      CBuffer aad,
      CBuffer cipher = nullb,
      Buffer plain = {})
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for verifying");
      }

      RecvNonce recv_nonce(header.get_iv_int());
      auto tid = recv_nonce.tid;
      auto& channel_nonce = local_recv_nonce[tid];

      uint16_t current_tid = threading::get_current_thread_id();
      assert(
        current_tid == threading::ThreadMessaging::main_thread ||
        current_tid % threading::ThreadMessaging::thread_count == tid);

      SeqNo* local_nonce;
      if (current_tid == threading::ThreadMessaging::main_thread)
      {
        local_nonce = &local_recv_nonce[tid].main_thread_seqno;
      }
      else
      {
        local_nonce = &local_recv_nonce[tid].tid_seqno;
      }

      if (recv_nonce.nonce <= *local_nonce)
      {
        // If the nonce received has already been processed, return
        LOG_FAIL_FMT(
          "Invalid nonce, possible replay attack, received:{}, last_seen:{}, "
          "recv_nonce.tid:{}",
          reinterpret_cast<uint64_t>(recv_nonce.nonce),
          *local_nonce,
          recv_nonce.tid);
        return false;
      }

      auto ret =
        key->decrypt(header.get_iv(), header.tag, cipher, aad, plain.p);
      if (ret)
      {
        // Set local recv nonce to received nonce only if verification is
        // successful
        *local_nonce = recv_nonce.nonce;
      }

      return ret;
    }

  public:
    Channel(bool incoming_only_ = false) :
      status(INITIATED),
      known_by_local_store(true),
      incoming_only(incoming_only_)
    {}

    // TODO: Delete me
    ~Channel()
    {
      LOG_FAIL_FMT("Channel destroyed!");
    }

    void set_status(ChannelStatus status_)
    {
      status = status_;
    }

    ChannelStatus get_status()
    {
      return status;
    }

    bool is_incoming_only()
    {
      return incoming_only;
    }

    void set_incoming_only()
    {
      // TODO: Naming is bad
      incoming_only = false;
    }

    bool is_known_by_local_store()
    {
      return known_by_local_store;
    }

    void set_known_by_local_store()
    {
      known_by_local_store = true;
    }

    std::optional<std::vector<uint8_t>> get_public()
    {
      if (status == ESTABLISHED)
      {
        return {};
      }

      return ctx.get_own_public();
    }

    bool load_peer_public(const uint8_t* bytes, size_t size)
    {
      if (status == ESTABLISHED)
      {
        return false;
      }

      ctx.load_peer_public(bytes, size);
      return true;
    }

    void establish()
    {
      auto shared_secret = ctx.compute_shared_secret();
      key = std::make_unique<crypto::KeyAesGcm>(shared_secret);
      ctx.free_ctx();
      status = ESTABLISHED;
    }

    void free_ctx()
    {
      if (status != ESTABLISHED)
      {
        return;
      }

      ctx.free_ctx();
    }

    void tag(GcmHdr& header, CBuffer aad)
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for tagging");
      }
      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      header.set_iv_seq(nonce.get_val());
      key->encrypt(header.get_iv(), nullb, aad, nullptr, header.tag);
    }

    static RecvNonce get_nonce(const GcmHdr& header)
    {
      return RecvNonce(header.get_iv_int());
    }

    bool verify(const GcmHdr& header, CBuffer aad)
    {
      return verify_or_decrypt(header, aad);
    }

    void encrypt(GcmHdr& header, CBuffer aad, CBuffer plain, Buffer cipher)
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for encrypting");
      }

      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      header.set_iv_seq(nonce.get_val());
      key->encrypt(header.get_iv(), plain, aad, cipher.p, header.tag);
    }

    bool decrypt(
      const GcmHdr& header, CBuffer aad, CBuffer cipher, Buffer plain)
    {
      return verify_or_decrypt(header, aad, cipher, plain);
    }
  };

  class ChannelManager
  {
  private:
    // A std::nullopt value indicates a channel that no longer exists
    std::unordered_map<NodeId, std::optional<Channel>> channels;
    ringbuffer::WriterPtr to_host;
    tls::KeyPairPtr network_kp;

  public:
    ChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory,
      const tls::Pem& network_pkey) :
      to_host(writer_factory.create_writer_to_outside()),
      network_kp(tls::make_key_pair(network_pkey))
    {}

    void create_channel(
      NodeId peer_id, const std::string& hostname, const std::string& service)
    {
      LOG_FAIL_FMT("Creating a channel with {}...", peer_id);

      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        // if (
        //   search->second.has_value() &&
        //   !search->second->is_known_by_local_store())
        // {
        //   LOG_FAIL_FMT(
        //     "Channel already exists but is not known by local store");
        //   search->second->set_known_by_local_store();
        //   return;
        // }

        // throw std::logic_error(fmt::format(
        //   "Cannot create node channel with {}: channel already exists",
        //   peer_id));

        if (search->second.has_value())
        {
          if (search->second->is_incoming_only())
          {
            LOG_FAIL_FMT(
              "Channel with {} exists but is incoming only. Create host "
              "connection.", peer_id);

            // Notify host to create an outgoing connection to the peer
            RINGBUFFER_WRITE_MESSAGE(
              ccf::add_node, to_host, peer_id, hostname, service);
            search->second->set_incoming_only();
            return;
          }
          else
          {
            LOG_FAIL_FMT("Channel with already exists. Use it.");
            return;
          }
        }
        else
        {
          throw std::logic_error(
            "Cannot create a channel with a node that has been deleted!");
        }

        return;
      }

      // Odd emplace syntax here as Channel is non-copyable and Channel() needs
      // to be differentiated from std::nullopt
      channels[peer_id].emplace();

      // TODO: Move messaging to host to Channel class instead
      // Notify host to create an outgoing connection to the peer
      RINGBUFFER_WRITE_MESSAGE(
        ccf::add_node, to_host, peer_id, hostname, service);
    }

    void close_channel(NodeId peer_id)
    {
      auto search = channels.find(peer_id);
      if (search == channels.end())
      {
        LOG_FAIL_FMT(
          "Cannot close node channel with {}: channel does not exist", peer_id);
        return;
      }

      LOG_INFO_FMT("Node channel with {} is now closed", peer_id);

      // Record that the channel is closed, keeping track of closed channels so
      // that they are not re-used
      search->second = std::nullopt;

      // Notify host to remove outgoing connection to the peer
      RINGBUFFER_WRITE_MESSAGE(ccf::remove_node, to_host, peer_id);
    }

    std::optional<Channel>& get(NodeId peer_id)
    {
      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return search->second;
      }

      LOG_FAIL_FMT("Creating temporary channel with {}", peer_id);

      // Creating temporary channel that is incoming only
      channels.emplace(peer_id, true);

      return channels[peer_id];
    }

    std::optional<std::vector<uint8_t>> get_signed_public(NodeId peer_id)
    {
      auto& channel = get(peer_id);
      if (!channel.has_value())
      {
        return std::nullopt;
      }

      const auto own_public_for_peer_ = channel->get_public();
      if (!own_public_for_peer_.has_value())
      {
        return std::nullopt;
      }

      const auto& own_public_for_peer = own_public_for_peer_.value();

      auto signature = network_kp->sign(own_public_for_peer);

      // Serialise channel public and network signature
      // Length-prefix both
      auto space =
        own_public_for_peer.size() + signature.size() + 2 * sizeof(size_t);
      std::vector<uint8_t> ret(space);
      auto data_ = ret.data();
      serialized::write(data_, space, own_public_for_peer.size());
      serialized::write(
        data_, space, own_public_for_peer.data(), own_public_for_peer.size());
      serialized::write(data_, space, signature.size());
      serialized::write(data_, space, signature.data(), signature.size());

      return ret;
    }

    bool load_peer_signed_public(
      NodeId peer_id, const std::vector<uint8_t>& peer_signed_public)
    {
      auto& channel = get(peer_id);
      if (!channel.has_value())
      {
        LOG_FAIL_FMT(
          "Cannot load peer signed public: node channel with {} does not exist",
          peer_id);
        return false;
      }

      // Verify signature
      auto network_pubk = tls::make_public_key(network_kp->public_key_pem());

      auto data = peer_signed_public.data();
      auto data_remaining = peer_signed_public.size();

      auto peer_public_size = serialized::read<size_t>(data, data_remaining);
      auto peer_public_start = data;

      if (peer_public_size > data_remaining)
      {
        LOG_FAIL_FMT(
          "Peer public key header wants {} bytes, but only {} remain",
          peer_public_size,
          data_remaining);
        return false;
      }

      data += peer_public_size;
      data_remaining -= peer_public_size;

      auto signature_size = serialized::read<size_t>(data, data_remaining);
      auto signature_start = data;

      if (signature_size > data_remaining)
      {
        LOG_FAIL_FMT(
          "Signature header wants {} bytes, but only {} remain",
          signature_size,
          data_remaining);
        return false;
      }

      if (signature_size < data_remaining)
      {
        LOG_FAIL_FMT(
          "Expected signature to use all remaining {} bytes, but only uses {}",
          data_remaining,
          signature_size);
        return false;
      }

      if (!network_pubk->verify(
            peer_public_start,
            peer_public_size,
            signature_start,
            signature_size))
      {
        LOG_FAIL_FMT(
          "node2node peer signature verification failed {}", peer_id);
        return false;
      }

      // Load peer public
      if (!channel->load_peer_public(peer_public_start, peer_public_size))
      {
        return false;
      }

      // Channel can be established
      channel->establish();

      LOG_INFO_FMT("node channel with {} is now established", peer_id);

      return true;
    }
  };
}
