// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/logger.h"
#include "kv/test/null_encryptor.h"
#include "node/network_state.h"
#include "node/snapshotter.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

// Because snapshot serialisation is costly, the snapshotter serialises
// snapshots asynchronously.
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;

using StringString = kv::Map<std::string, std::string>;
using rb_msg = std::pair<ringbuffer::Message, size_t>;

auto read_ringbuffer_out(ringbuffer::Circuit& circuit)
{
  std::optional<rb_msg> idx = std::nullopt;
  circuit.read_from_inside().read(
    -1, [&idx](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::snapshot:
        case consensus::snapshot_commit:
        {
          auto idx_ = serialized::read<consensus::Index>(data, size);
          idx = {m, idx_};
          break;
        }
        default:
        {
          REQUIRE(false);
        }
      }
    });

  return idx;
}

void issue_transactions(ccf::NetworkState& network, size_t tx_count)
{
  for (size_t i = 0; i < tx_count; i++)
  {
    auto tx = network.tables->create_tx();
    auto view = tx.get_view2<StringString>("map");
    view->put("foo", "bar");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }
}

TEST_CASE("Regular snapshotting")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  ccf::NetworkState network;
  network.tables->set_encryptor(encryptor);
  ringbuffer::Circuit eio(1024 * 16);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  size_t interval_count = 3;

  issue_transactions(network, snapshot_tx_interval * interval_count);

  auto snapshotter =
    std::make_shared<ccf::Snapshotter>(*writer_factory, network);
  snapshotter->set_tx_interval(snapshot_tx_interval);

  REQUIRE_FALSE(snapshotter->requires_snapshot(snapshot_tx_interval - 1));
  REQUIRE(snapshotter->requires_snapshot(snapshot_tx_interval));

  INFO("Generated snapshots at regular intervals");
  {
    for (size_t i = 1; i <= interval_count; i++)
    {
      // No snapshot generated if < interval
      snapshotter->snapshot(i * (snapshot_tx_interval - 1));
      threading::ThreadMessaging::thread_messaging.run_one();
      REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

      snapshotter->snapshot(i * snapshot_tx_interval);
      threading::ThreadMessaging::thread_messaging.run_one();
      REQUIRE(
        read_ringbuffer_out(eio) ==
        rb_msg({consensus::snapshot, (i * snapshot_tx_interval)}));
    }
  }
}

TEST_CASE("Commit snapshot evidence")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  ccf::NetworkState network;
  network.tables->set_encryptor(encryptor);
  ringbuffer::Circuit eio(1024 * 16);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter =
    std::make_shared<ccf::Snapshotter>(*writer_factory, network);
  snapshotter->set_tx_interval(snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->snapshot(snapshot_tx_interval);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot, snapshot_tx_interval}));
  }

  INFO("Commit evidence");
  {
    // This assumes that the evidence was committed just after the snasphot, at
    // idx = (snapshot_tx_interval + 1)
    snapshotter->compact(snapshot_tx_interval + 1);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_tx_interval}));
  }
}

TEST_CASE("Rollback before evidence is committed")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  ccf::NetworkState network;
  network.tables->set_encryptor(encryptor);
  ringbuffer::Circuit eio(1024 * 16);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter =
    std::make_shared<ccf::Snapshotter>(*writer_factory, network);
  snapshotter->set_tx_interval(snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->snapshot(snapshot_tx_interval);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot, snapshot_tx_interval}));
  }

  INFO("Rollback evidence and commit past it");
  {
    snapshotter->rollback(snapshot_tx_interval);

    // ... More transactions are committed, passing the idx at which the
    // evidence was originally committed

    snapshotter->compact(snapshot_tx_interval + 1);

    // Snapshot previously generated is not committed
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Snapshot again and commit evidence");
  {
    issue_transactions(network, snapshot_tx_interval);

    size_t snapshot_idx = network.tables->current_version();
    snapshotter->snapshot(snapshot_idx);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));

    snapshotter->compact(snapshot_idx + 1);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }
}