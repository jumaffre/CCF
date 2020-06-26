// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "node/entities.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

TEST_CASE("Map creation")
{
  kv::Store kv_store;
  const auto map_name = "map";
  auto& map = kv_store.create<MapTypes::StringString>(map_name);

  INFO("Get a map that does not exist");
  {
    REQUIRE(kv_store.get<MapTypes::StringString>("invalid_map") == nullptr);
  }

  INFO("Get a map that does exist");
  {
    auto* p_map = kv_store.get<MapTypes::StringString>(map_name);
    REQUIRE(*p_map == map);
    REQUIRE(p_map == &map); // They're the _same instance_, not just equal
  }

  INFO("Compare different maps");
  {
    auto& map2 = kv_store.create<MapTypes::StringString>("map2");
    REQUIRE(map != map2);
  }

  INFO("Can't create map that already exists");
  {
    REQUIRE_THROWS_AS(
      kv_store.create<MapTypes::StringString>(map_name), std::logic_error);
  }

  INFO("Can't get a map with the wrong type");
  {
    REQUIRE(kv_store.get<MapTypes::NumNum>(map_name) == nullptr);
    REQUIRE(kv_store.get<MapTypes::NumString>(map_name) == nullptr);
    REQUIRE(kv_store.get<MapTypes::StringNum>(map_name) == nullptr);
  }

  INFO("Can create a map with a previously invalid name");
  {
    CHECK_NOTHROW(kv_store.create<MapTypes::StringString>("version"));
  }
}

TEST_CASE("Reads/writes and deletions")
{
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Start empty transaction");
  {
    kv::Tx tx;
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE_THROWS_AS(tx.commit(), std::logic_error);
  }

  INFO("Read own writes");
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    auto v = view->get(k);
    REQUIRE(!v.has_value());
    view->put(k, v1);
    auto va = view->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Read previous writes");
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    auto v = view->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Remove keys");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);

    REQUIRE(!view->remove(invalid_key));
    REQUIRE(view->remove(k));
    auto va = view->get(k);
    REQUIRE(!va.has_value());

    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    auto view2 = tx2.get_view(map);
    REQUIRE(view2->remove(k));
  }

  INFO("Remove key that was deleted from state");
  {
    kv::Tx tx;
    kv::Tx tx2;
    kv::Tx tx3;
    auto view = tx.get_view(map);
    view->put(k, v1);
    auto va = view->get_globally_committed(k);
    REQUIRE(!va.has_value());
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    auto view2 = tx2.get_view(map);
    REQUIRE(view2->remove(k));
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    auto view3 = tx3.get_view(map);
    auto vc = view3->get(k);
    REQUIRE(!vc.has_value());
  }
}

TEST_CASE("foreach")
{
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);

  std::map<std::string, std::string> iterated_entries;

  auto store_iterated =
    [&iterated_entries](const auto& key, const auto& value) {
      auto it = iterated_entries.find(key);
      REQUIRE(it == iterated_entries.end());
      iterated_entries[key] = value;
      return true;
    };

  SUBCASE("Empty map")
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    view->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading own writes")
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    view->put("key1", "value1");
    view->put("key2", "value2");
    view->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");

    iterated_entries.clear();

    INFO("Uncommitted writes from other txs are not visible");
    kv::Tx tx2;
    auto view2 = tx2.get_view(map);
    view2->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading committed writes")
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    view->put("key1", "value1");
    view->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    kv::Tx tx2;
    auto view2 = tx2.get_view(map);
    view2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");
  }

  SUBCASE("Mix of committed and own writes")
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    view->put("key1", "value1");
    view->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    kv::Tx tx2;
    auto view2 = tx2.get_view(map);
    view2->put("key2", "replaced2");
    view2->put("key3", "value3");
    view2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 3);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "replaced2");
    REQUIRE(iterated_entries["key3"] == "value3");
  }

  SUBCASE("Deletions")
  {
    {
      kv::Tx tx;
      auto view = tx.get_view(map);
      view->put("key1", "value1");
      view->put("key2", "value2");
      view->put("key3", "value3");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    {
      kv::Tx tx;
      auto view = tx.get_view(map);
      view->remove("key1");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    {
      kv::Tx tx;
      auto view = tx.get_view(map);
      view->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 2);
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      view->remove("key2");
      view->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 1);
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      view->put("key1", "value1");
      view->put("key2", "value2");
      view->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 3);
      REQUIRE(iterated_entries["key1"] == "value1");
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");
    }
  }

  SUBCASE("Early termination")
  {
    {
      kv::Tx tx;
      auto view = tx.get_view(map);
      view->put("key1", "value1");
      view->put("key2", "value2");
      view->put("key3", "value3");
      size_t ctr = 0;
      view->foreach([&ctr](const auto& key, const auto& value) {
        ++ctr;
        return ctr < 2; // Continue after the first, but not the second (so
                        // never see the third)
      });
      REQUIRE(ctr == 2);
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    {
      kv::Tx tx;
      auto view = tx.get_view(map);
      view->put("key4", "value4");
      view->put("key5", "value5");

      {
        size_t ctr = 0;
        view->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 2; //< See only committed state
        });
        REQUIRE(ctr == 2);
      }

      {
        size_t ctr = 0;
        view->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 4; //< See mix of old state and new writes
        });
        REQUIRE(ctr == 4);
      }

      {
        size_t ctr = 0;
        view->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 100; //< See as much as possible
        });
        REQUIRE(ctr == 5);
      }
    }
  }
}

TEST_CASE("Read-only tx")
{
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Write some keys");
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    auto v = view->get(k);
    REQUIRE(!v.has_value());
    view->put(k, v1);
    auto va = view->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Do only reads with an overpowered Tx");
  {
    kv::Tx tx;
    auto view = tx.get_read_only_view(map);
    const auto v = view->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    const auto invalid_v = view->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // view->put(k, v1);
    // view->remove(k);
  }

  INFO("Read with read-only tx");
  {
    kv::ReadOnlyTx tx;
    auto view = tx.get_read_only_view(map);
    const auto v = view->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    const auto invalid_v = view->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // view->put(k, v1);
    // view->remove(k);
  }
}

TEST_CASE("Rollback and compact")
{
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);

  constexpr auto k = "key";
  constexpr auto v1 = "value1";

  INFO("Do not read transactions that have been rolled back");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    kv_store.rollback(0);
    auto view2 = tx2.get_view(map);
    auto v = view2->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
  }

  INFO("Read committed key");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    kv_store.compact(kv_store.current_version());

    auto view2 = tx2.get_view(map);
    auto va = view2->get_globally_committed(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
  }

  INFO("Read deleted committed key");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto view = tx.get_view(map);
    REQUIRE(view->remove(k));
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    kv_store.compact(kv_store.current_version());

    auto view2 = tx2.get_view(map);
    auto va = view2->get_globally_committed(k);
    REQUIRE(!va.has_value());
  }
}

TEST_CASE("Clear entire store")
{
  kv::Store kv_store;
  auto& map1 =
    kv_store.create<MapTypes::StringString>("map1", kv::SecurityDomain::PUBLIC);
  auto& map2 =
    kv_store.create<MapTypes::StringString>("map2", kv::SecurityDomain::PUBLIC);

  INFO("Commit a transaction over two maps");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto [view1, view2] = tx.get_view(map1, map2);
    view1->put("key1", "value1");
    view2->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    auto [view1_, view2_] = tx2.get_view(map1, map2);
    REQUIRE(view1_->get("key1") == "value1");
    REQUIRE(view2_->get("key2") == "value2");
  }

  INFO("Clear the entire store and make sure it is empty");
  {
    kv::Tx tx;
    kv::Tx tx2;
    auto [view1, view2] = tx.get_view(map1, map2);

    kv_store.clear();

    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(kv_store.commit_version() == 0);
    REQUIRE(view1->get("key1") == "value1");
    auto [view1_, view2_] = tx2.get_view(map1, map2);
    REQUIRE_FALSE(view1_->get("key1").has_value());
    REQUIRE_FALSE(view2_->get("key2").has_value());
  }
}

TEST_CASE("Local commit hooks")
{
  using Write = MapTypes::StringString::Write;
  std::vector<Write> local_writes;
  std::vector<Write> global_writes;

  auto local_hook = [&](kv::Version v, const Write& w) {
    local_writes.push_back(w);
  };
  auto global_hook = [&](kv::Version v, const Write& w) {
    global_writes.push_back(w);
  };

  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);
  map.set_local_hook(local_hook);
  map.set_global_hook(global_hook);

  INFO("Write with hooks");
  {
    kv::Tx tx;
    auto view = tx.get_view(map);
    view->put("key1", "value1");
    view->put("key2", "value2");
    view->remove("key2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    REQUIRE(latest_writes.at("key1").has_value());
    REQUIRE(latest_writes.at("key1").value() == "value1");
    INFO("Local removals are not seen");
    REQUIRE(latest_writes.find("key2") == latest_writes.end());
    REQUIRE(latest_writes.size() == 1);

    local_writes.clear();
  }

  INFO("Write without hooks");
  {
    map.unset_local_hook();
    map.unset_global_hook();

    kv::Tx tx;
    auto view = tx.get_view(map);
    view->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(local_writes.size() == 0);
    REQUIRE(global_writes.size() == 0);
  }

  INFO("Write with hook again");
  {
    map.set_local_hook(local_hook);
    map.set_global_hook(global_hook);

    kv::Tx tx;
    auto view = tx.get_view(map);
    view->remove("key2");
    view->put("key3", "value3");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    INFO("Old writes are not included");
    REQUIRE(latest_writes.find("key1") == latest_writes.end());
    INFO("Visible removals are included");
    const auto it2 = latest_writes.find("key2");
    REQUIRE(it2 != latest_writes.end());
    REQUIRE(!it2->second.has_value());
    const auto it3 = latest_writes.find("key3");
    REQUIRE(it3 != latest_writes.end());
    REQUIRE(it3->second.has_value());
    REQUIRE(it3->second.value() == "value3");
    REQUIRE(latest_writes.size() == 2);

    local_writes.clear();
  }
}

TEST_CASE("Global commit hooks")
{
  using Write = MapTypes::StringString::Write;

  struct GlobalHookInput
  {
    kv::Version version;
    Write writes;
  };

  std::vector<GlobalHookInput> global_writes;

  auto global_hook = [&](kv::Version v, const Write& w) {
    global_writes.emplace_back(GlobalHookInput({v, w}));
  };

  kv::Store kv_store;
  auto& map_with_hook = kv_store.create<std::string, std::string>(
    "map_with_hook", kv::SecurityDomain::PUBLIC);
  map_with_hook.set_global_hook(global_hook);
  auto& map_no_hook = kv_store.create<std::string, std::string>(
    "map_no_hook", kv::SecurityDomain::PUBLIC);

  INFO("Compact an empty store");
  {
    kv_store.compact(0);

    REQUIRE(global_writes.size() == 0);
  }

  INFO("Compact one transaction");
  {
    kv::Tx tx1;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    kv_store.compact(1);

    REQUIRE(global_writes.size() == 1);
    const auto& latest_writes = global_writes.front();
    REQUIRE(latest_writes.version == 1);
    const auto it1 = latest_writes.writes.find("key1");
    REQUIRE(it1 != latest_writes.writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact beyond the last map version");
  {
    kv::Tx tx1, tx2, tx3;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    view_hook = tx2.get_view(map_with_hook);
    view_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    const auto compact_version = kv_store.current_version();

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto view_no_hook = tx3.get_view(map_no_hook);
    view_no_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitSuccess::OK);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 2);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
    const auto it2 = global_writes.at(1).writes.find("key2");
    REQUIRE(it2 != global_writes.at(1).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact in between two map versions");
  {
    kv::Tx tx1, tx2, tx3;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto view_no_hook = tx2.get_view(map_no_hook);
    view_no_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    const auto compact_version = kv_store.current_version();

    view_hook = tx3.get_view(map_with_hook);
    view_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitSuccess::OK);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact twice");
  {
    kv::Tx tx1, tx2;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    kv_store.compact(kv_store.current_version());
    global_writes.clear();

    view_hook = tx2.get_view(map_with_hook);
    view_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    kv_store.compact(kv_store.current_version());

    // Only writes since the last compact are passed to the global hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 2);
    const auto it2 = global_writes.at(0).writes.find("key2");
    REQUIRE(it2 != global_writes.at(0).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");

    global_writes.clear();
    kv_store.clear();
  }
}

TEST_CASE("Clone schema")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store store;
  store.set_encryptor(encryptor);

  auto& public_map =
    store.create<MapTypes::NumString>("public", kv::SecurityDomain::PUBLIC);
  auto& private_map = store.create<MapTypes::NumString>("private");
  kv::Tx tx1(store.next_version());
  auto [view1, view2] = tx1.get_view(public_map, private_map);
  view1->put(42, "aardvark");
  view2->put(14, "alligator");
  auto [success, reqid, data] = tx1.commit_reserved();
  REQUIRE(success == kv::CommitSuccess::OK);

  kv::Store clone;
  clone.clone_schema(store);
  clone.set_encryptor(encryptor);

  REQUIRE(clone.deserialise(data) == kv::DeserialiseSuccess::PASS);
}

TEST_CASE("Deserialise return status")
{
  kv::Store store;

  auto& signatures = store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);
  auto& nodes =
    store.create<ccf::Nodes>(ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& data =
    store.create<MapTypes::NumNum>("data", kv::SecurityDomain::PUBLIC);

  auto kp = tls::make_key_pair();

  auto history =
    std::make_shared<ccf::NullTxHistory>(store, 0, *kp, signatures, nodes);
  store.set_history(history);

  {
    kv::Tx tx(store.next_version());
    auto data_view = tx.get_view(data);
    data_view->put(42, 42);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::PASS);
  }

  {
    kv::Tx tx(store.next_version());
    auto sig_view = tx.get_view(signatures);
    ccf::Signature sigv(0, 2);
    sig_view->put(0, sigv);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::PASS_SIGNATURE);
  }

  INFO("Signature transactions with additional contents should fail");
  {
    kv::Tx tx(store.next_version());
    auto [sig_view, data_view] = tx.get_view(signatures, data);
    ccf::Signature sigv(0, 2);
    sig_view->put(0, sigv);
    data_view->put(43, 43);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE("Map swap between stores")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store s1;
  s1.set_encryptor(encryptor);

  auto& d1 = s1.create<MapTypes::NumNum>("data");
  auto& pd1 =
    s1.create<MapTypes::NumNum>("public_data", kv::SecurityDomain::PUBLIC);

  kv::Store s2;
  s2.set_encryptor(encryptor);
  auto& d2 = s2.create<MapTypes::NumNum>("data");
  auto& pd2 =
    s2.create<MapTypes::NumNum>("public_data", kv::SecurityDomain::PUBLIC);

  {
    kv::Tx tx;
    auto v = tx.get_view(d1);
    v->put(42, 42);
    tx.commit();
  }

  {
    kv::Tx tx;
    auto v = tx.get_view(pd1);
    v->put(14, 14);
    tx.commit();
  }

  {
    kv::Tx tx;
    auto v = tx.get_view(d2);
    v->put(41, 41);
    tx.commit();
  }

  s2.swap_private_maps(s1);

  {
    kv::Tx tx;
    auto v = tx.get_view(d1);
    auto val = v->get(41);
    REQUIRE_FALSE(v->get(42).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 41);
  }

  {
    kv::Tx tx;
    auto v = tx.get_view(pd1);
    auto val = v->get(14);
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 14);
  }

  {
    kv::Tx tx;
    auto v = tx.get_view(d2);
    auto val = v->get(42);
    REQUIRE_FALSE(v->get(41).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 42);
  }

  {
    kv::Tx tx;
    auto v = tx.get_view(pd2);
    REQUIRE_FALSE(v->get(14).has_value());
  }
}

TEST_CASE("Invalid map swaps")
{
  {
    kv::Store s1;
    s1.create<MapTypes::NumNum>("one");

    kv::Store s2;
    s2.create<MapTypes::NumNum>("one");
    s2.create<MapTypes::NumNum>("two");

    REQUIRE_THROWS_WITH(
      s2.swap_private_maps(s1),
      "Private map list mismatch during swap, missing at least two");
  }

  {
    kv::Store s1;
    s1.create<MapTypes::NumNum>("one");
    s1.create<MapTypes::NumNum>("two");

    kv::Store s2;
    s2.create<MapTypes::NumNum>("one");

    REQUIRE_THROWS_WITH(
      s2.swap_private_maps(s1),
      "Private map list mismatch during swap, two not found");
  }
}

TEST_CASE("Private recovery map swap")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store s1;
  s1.set_encryptor(encryptor);
  auto& priv1 = s1.create<MapTypes::NumNum>("private");
  auto& pub1 =
    s1.create<MapTypes::NumString>("public", kv::SecurityDomain::PUBLIC);

  kv::Store s2;
  s2.set_encryptor(encryptor);
  auto& priv2 = s2.create<MapTypes::NumNum>("private");
  auto& pub2 =
    s2.create<MapTypes::NumString>("public", kv::SecurityDomain::PUBLIC);

  INFO("Populate s1 with public entries");
  // We compact twice, deliberately. A public KV during recovery
  // would have compacted some number of times.
  {
    kv::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(42, "42");
    tx.commit();
  }
  {
    kv::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(42, "43");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    kv::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(44, "44");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    kv::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(45, "45");
    tx.commit();
  }

  INFO("Populate s2 with private entries");
  // We compact only once, at a lower index than we did for the public
  // KV, which is what we expect during recovery of the private KV. We do expect
  // that the _entire_ private state is compacted
  {
    kv::Tx tx;
    auto v = tx.get_view(priv2);
    v->put(12, 12);
    tx.commit();
  }
  {
    kv::Tx tx;
    auto v = tx.get_view(priv2);
    v->put(13, 13);
    tx.commit();
  }
  s2.compact(s2.current_version());

  INFO("Swap in private maps");
  REQUIRE_NOTHROW(s1.swap_private_maps(s2));

  INFO("Check state looks as expected in s1");
  {
    kv::Tx tx;
    auto [priv, pub] = tx.get_view(priv1, pub1);
    {
      auto val = pub->get(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get(45);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "45");

      REQUIRE(s1.commit_version() == 3);
    }
    {
      auto val = priv->get(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);
    }
  }

  INFO("Check committed state looks as expected in s1");
  {
    kv::Tx tx;
    auto [priv, pub] = tx.get_view(priv1, pub1);
    {
      auto val = pub->get_globally_committed(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get_globally_committed(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get_globally_committed(45);
      REQUIRE_FALSE(val.has_value());
    }
    {
      auto val = priv->get_globally_committed(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get_globally_committed(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);

      // Uncompacted state is visible, which is expected, but isn't
      // something that would happen in recovery (only compacted state
      // would be swapped in). There is deliberately no check for compacted
      // state later than the compact level on the public KV, as this is
      // impossible during recovery.
    }
  }
}

TEST_CASE("Conflict resolution")
{
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>("map", kv::SecurityDomain::PUBLIC);

  auto try_write = [&](kv::Tx& tx, const std::string& s) {
    auto view = tx.get_view(map);

    // Numroduce read-dependency
    view->get("foo");
    view->put("foo", s);

    view->put(s, s);
  };

  auto confirm_state = [&](
                         const std::vector<std::string>& present,
                         const std::vector<std::string>& missing) {
    kv::Tx tx;
    auto view = tx.get_view(map);

    for (const auto& s : present)
    {
      const auto it = view->get(s);
      REQUIRE(it.has_value());
      REQUIRE(it.value() == s);
    }

    for (const auto& s : missing)
    {
      const auto it = view->get(s);
      REQUIRE(!it.has_value());
    }
  };

  // Simulate parallel execution by interleaving tx steps
  kv::Tx tx1;
  kv::Tx tx2;

  // First transaction tries to write a value, depending on initial version
  try_write(tx1, "bar");

  {
    // A second transaction is committed, conflicting with the first
    try_write(tx2, "baz");
    const auto res2 = tx2.commit();
    REQUIRE(res2 == kv::CommitSuccess::OK);

    confirm_state({"baz"}, {"bar"});
  }

  // Trying to commit first transaction produces a conflict
  auto res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitSuccess::CONFLICT);
  confirm_state({"baz"}, {"bar"});

  // First transaction is rerun with same object, producing different result
  try_write(tx1, "buzz");

  // Expected results are committed
  res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitSuccess::OK);
  confirm_state({"baz", "buzz"}, {"bar"});

  // Re-running a _committed_ transaction is exceptionally bad
  REQUIRE_THROWS(tx1.commit());
  REQUIRE_THROWS(tx2.commit());
}

TEST_CASE("Serialization")
{
  const char* map_name = "map";
  kv::SecurityDomain security_domain = kv::SecurityDomain::PUBLIC;
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>(map_name, security_domain);

  auto try_write = [&](kv::Tx& tx, const std::string& s) {
    auto view = tx.get_view(map);

    // Numroduce read-dependency
    view->get("foo");
    view->put("foo", s);

    view->put(s, s);
  };

  INFO("Simulate parallel execution by interleaving tx steps");
  {
    kv::Tx tx1;
    kv::Tx tx2;

    // First transaction tries to write a value, depending on initial version
    try_write(tx1, "bar");

    {
      // A second transaction is committed, conflicting with the first
      try_write(tx2, "baz");
      const auto res2 = tx2.commit();
      REQUIRE(res2 == kv::CommitSuccess::OK);
    }

    // Trying to commit first transaction produces a conflict
    auto res1 = tx1.commit();
    REQUIRE(res1 == kv::CommitSuccess::CONFLICT);

    // First transaction is rerun with same object, producing different result
    try_write(tx1, "buzz");

    // Expected results are committed
    res1 = tx1.commit();
    REQUIRE(res1 == kv::CommitSuccess::OK);
  }

  // now we serialize the a KV that is in the mid point of the known versions
  std::unique_ptr<kv::AbstractStore::AbstractSnapshot> s = kv_store.snapshot(1);
  auto& vec_s = s->get_snapshots();
  for (auto& s : vec_s)
  {
    REQUIRE_EQ(s->get_name(), map_name);
    REQUIRE_EQ(s->get_security_domain(), security_domain);
    REQUIRE_EQ(s->get_is_replicated(), true);
    REQUIRE_GT(s->get_serialized_size(), 0);
  }

  kv::Store new_store;
  auto& new_map =
    new_store.create<MapTypes::StringString>(map_name, security_domain);
  new_store.deserialize(s);

  REQUIRE_EQ(new_store.current_version(), 1);
}