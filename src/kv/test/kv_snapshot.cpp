// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/tx.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
};

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);
  auto& num_map =
    store.create<MapTypes::NumNum>("num_map", kv::SecurityDomain::PUBLIC);

  kv::Version first_snapshot_version = kv::NoVersion;
  kv::Version second_snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "bar");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    first_snapshot_version = tx1.commit_version();

    kv::Tx tx2;
    auto view_2 = tx2.get_view(num_map);
    view_2->put(42, 123);
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
    second_snapshot_version = tx2.commit_version();

    kv::Tx tx3;
    auto view_3 = tx1.get_view(string_map);
    view_3->put("key", "not committed");
    // Do not commit tx3
  }

  auto first_snapshot = store.snapshot(first_snapshot_version);
  auto first_serialised_snapshot =
    store.serialise_snapshot(std::move(first_snapshot));

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    REQUIRE_EQ(
      new_store.deserialise_snapshot(first_serialised_snapshot),
      kv::DeserialiseSuccess::PASS);
    REQUIRE_EQ(new_store.current_version(), 1);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("num_map");

    kv::Tx tx1;
    auto view = tx1.get_view(*new_string_map);
    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");

    auto view_ = tx1.get_view(*new_num_map);
    auto v_ = view_->get(42);
    REQUIRE(!v_.has_value());

    view = tx1.get_view(*new_string_map);
    v = view->get("key");
    REQUIRE(!v.has_value());
  }

  auto second_snapshot = store.snapshot(second_snapshot_version);
  auto second_serialised_snapshot =
    store.serialise_snapshot(std::move(second_snapshot));

  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    auto new_num_map = new_store.get<MapTypes::NumNum>("num_map");

    new_store.deserialise_snapshot(second_serialised_snapshot);
    REQUIRE_EQ(new_store.current_version(), 2);

    kv::Tx tx1;
    auto view = tx1.get_view(*new_string_map);

    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");

    auto view_ = tx1.get_view(*new_num_map);
    auto v_ = view_->get(42);
    REQUIRE(v_.has_value());
    REQUIRE_EQ(v_.value(), 123);

    view = tx1.get_view(*new_string_map);
    v = view->get("key");
    REQUIRE(!v.has_value());
  }
}

TEST_CASE("Deleted keys" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    view_1->put("bar", "bar");
    view_1->put("foo", "foooooooooooooooooooooooo");
    view_1->put("lalal", "fdsfsfsd");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    kv::Tx tx2;
    auto view_2 = tx2.get_view(string_map);
    view_2->remove("foo");
    view_2->put("lalla", "hohoho");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshots and verify deleted keys");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    new_store.deserialise_snapshot(serialised_snapshot);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    kv::Tx tx;
    auto view = tx.get_view(*new_string_map);

    REQUIRE_FALSE(view->get("foo").has_value());
    REQUIRE(view->get("bar").has_value());
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    kv::Tx tx2;
    auto view_2 = tx2.get_view(string_map);
    view_2->put("bar", "bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot while committing a transaction");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");
    kv::Tx tx;
    auto view = tx.get_view(*new_string_map);
    view->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    new_store.deserialise_snapshot(serialised_snapshot);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == kv::CommitSuccess::CONFLICT);

    view = tx.get_view(*new_string_map);
    view->put("baz", "baz");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }
}

TEST_CASE("Commit hooks with snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto& string_map = store.create<MapTypes::StringString>(
    "string_map", kv::SecurityDomain::PUBLIC);

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    kv::Tx tx1;
    auto view_1 = tx1.get_view(string_map);
    view_1->put("foo", "foo");
    view_1->put("bar", "bar");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK); // Committed at 1

    // New transaction, deleting content from the previous transaction
    kv::Tx tx2;
    auto view_2 = tx2.get_view(string_map);
    view_2->put("baz", "baz");
    view_2->remove("bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot with local hook on target store");
  {
    kv::Store new_store;
    new_store.clone_schema(store);

    auto new_string_map = new_store.get<MapTypes::StringString>("string_map");

    using Write = MapTypes::StringString::Write;
    std::vector<Write> local_writes;
    std::vector<Write> global_writes;

    INFO("Set hooks on target store");
    {
      auto local_hook = [&](kv::Version v, const Write& w) {
        local_writes.push_back(w);
      };
      auto global_hook = [&](kv::Version v, const Write& w) {
        global_writes.push_back(w);
      };
      new_string_map->set_local_hook(local_hook);
      new_string_map->set_global_hook(global_hook);
    }

    new_store.deserialise_snapshot(serialised_snapshot);

    INFO("Verify content of snapshot");
    {
      kv::Tx tx;
      auto view = tx.get_view(*new_string_map);
      REQUIRE(view->get("foo").has_value());
      REQUIRE(!view->get("bar").has_value());
      REQUIRE(view->get("baz").has_value());
    }

    INFO("Verify local hook execution");
    {
      REQUIRE_EQ(local_writes.size(), 1);
      auto writes = local_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      REQUIRE_EQ(global_writes.size(), 1);
      auto writes = global_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }
  }
}