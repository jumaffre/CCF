// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ledger.h"
#include "../multiple_ledger.h"

#include <doctest/doctest.h>
#include <string>

// TEST_CASE("Read/Write test")
// {
//   ringbuffer::Circuit eio(1024);
//   auto wf = ringbuffer::WriterFactory(eio);

//   const std::vector<uint8_t> e1 = {1, 2, 3};
//   const std::vector<uint8_t> e2 = {5, 5, 6, 7};
//   {
//     asynchost::Ledger l("testlog", wf);
//     l.truncate(0);
//     REQUIRE(l.get_last_idx() == 0);
//     l.write_entry(e1.data(), e1.size());
//     l.write_entry(e2.data(), e2.size());
//   }

//   asynchost::Ledger l("testlog", wf);
//   REQUIRE(l.get_last_idx() == 2);
//   auto r1 = l.read_entry(1);
//   REQUIRE(e1 == r1);
//   auto r2 = l.read_entry(2);
//   REQUIRE(e2 == r2);
// }

// TEST_CASE("Entry sizes")
// {
//   ringbuffer::Circuit eio(2);
//   auto wf = ringbuffer::WriterFactory(eio);

//   const std::vector<uint8_t> e1 = {1, 2, 3};
//   const std::vector<uint8_t> e2 = {5, 5, 6, 7};

//   asynchost::Ledger l("testlog", wf);
//   l.truncate(0);
//   REQUIRE(l.get_last_idx() == 0);
//   l.write_entry(e1.data(), e1.size());
//   l.write_entry(e2.data(), e2.size());

//   REQUIRE(l.entry_size(1) == e1.size());
//   REQUIRE(l.entry_size(2) == e2.size());
//   REQUIRE(l.entry_size(0) == 0);
//   REQUIRE(l.entry_size(3) == 0);

//   REQUIRE(l.framed_entries_size(1, 1) == (e1.size() + sizeof(uint32_t)));
//   REQUIRE(
//     l.framed_entries_size(1, 2) ==
//     (e1.size() + sizeof(uint32_t) + e2.size() + sizeof(uint32_t)));

//   /*
//     auto e = l.read_framed_entries(1, 1);
//     for (auto c : e)
//       std::cout << std::hex << (int)c;
//     std::cout << std::endl;*/
// }

struct LedgerEntry
{
  uint8_t value;
};

static constexpr size_t frame_header_size = sizeof(uint32_t);

size_t number_of_files_in_directory(const fs::path& dir)
{
  size_t file_count = 0;
  for (auto const& f : fs::directory_iterator(dir))
  {
    file_count++;
  }
  return file_count;
}

TEST_CASE("Multiple ledgers")
{
  ringbuffer::Circuit eio(1024);
  auto wf = ringbuffer::WriterFactory(eio);
  std::string ledger_dir = "ledger_dir";
  size_t chunk_threshold = 100;
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);

  LedgerEntry dummy_entry = {0x42};
  size_t tx_per_chunk =
    chunk_threshold / (frame_header_size + sizeof(LedgerEntry));

  INFO("Not quite enough entries before chunk threshold");
  {
    bool is_committable = true;
    for (int i = 0; i < tx_per_chunk - 1; i++)
    {
      ledger.write_entry(
        &dummy_entry.value, sizeof(LedgerEntry), is_committable);
    }

    // Writing globally commitable entries without reaching the chunk threshold
    // does not create new ledger files

    REQUIRE(number_of_files_in_directory(ledger_dir) == 1);
  }

  INFO("Additional non-committable entries do not trigger chunking");
  {
    bool is_committable = false;
    ledger.write_entry(&dummy_entry.value, sizeof(LedgerEntry), is_committable);
    ledger.write_entry(&dummy_entry.value, sizeof(LedgerEntry), is_committable);

    REQUIRE(number_of_files_in_directory(ledger_dir) == 1);
  }

  INFO("Additional committable entry triggers chunking");
  {
    bool is_committable = true;
    ledger.write_entry(&dummy_entry.value, sizeof(LedgerEntry), is_committable);
    REQUIRE(number_of_files_in_directory(ledger_dir) == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunks_so_far = number_of_files_in_directory(ledger_dir);

    size_t expected_number_of_chunks = 5;
    for (int i = 0; i < tx_per_chunk * expected_number_of_chunks; i++)
    {
      bool is_committable = true;
      ledger.write_entry(
        &dummy_entry.value, sizeof(LedgerEntry), is_committable);
    }
    REQUIRE(
      number_of_files_in_directory(ledger_dir) ==
      expected_number_of_chunks + chunks_so_far);
  }

  // TODO:
  // 1. Also check for size of files
  // 2. Fix issue with offset

  // fs::remove_all(ledger_dir);
}