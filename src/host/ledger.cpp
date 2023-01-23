// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "kv/generic_serialise_wrapper.h"
#include "kv/raw_serialise.h"
#include "kv/serialised_entry_format.h"
#include "kv/test/null_encryptor.h"

#include <filesystem>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

void display_entry(const std::vector<uint8_t>& entry)
{
  LOG_INFO_FMT("Displaying one entry of size: {}", entry.size());

  auto e = std::make_shared<kv::NullTxEncryptor>();
  kv::GenericDeserialiseWrapper<kv::RawReader> r(e, kv::SecurityDomain::PUBLIC);

  kv::Term term;
  // TODO: init() below requires crypto::Sha256Hash :(
  r.init(entry.data(), entry.size(), term);

  // TODO: Currently, init() fails
}

int main(int argc, char** argv)
{
  logger::config::default_init();

  if (argc != 2)
  {
    LOG_FAIL_FMT("Error. Usage: {} <path-to-ccf-ledger-dir>", argv[0]);
    exit(1);
  }

  const auto& dir = argv[1];

  if (!fs::is_directory(dir))
  {
    LOG_FAIL_FMT("Error. Ledger {} directory is not valid directory", dir);
    exit(1);
  }

  LOG_INFO_FMT("Reading CCF ledger directory: {}", dir);

  for (auto const& f : fs::directory_iterator(dir))
  {
    // TODO: Order files
    size_t total_file_size = f.file_size();
    LOG_DEBUG_FMT("File: {} [{}]", f.path(), total_file_size);

    std::ifstream file(f.path(), std::ios::binary);

    // Read offset table
    size_t offset_header_table;
    file.read(
      reinterpret_cast<char*>(&offset_header_table),
      sizeof(offset_header_table));

    size_t total_len = sizeof(size_t);
    auto len = offset_header_table - total_len;

    // API:
    // Register on_entry_begin, on_table, on_key, on_value, on_entry_end
    std::vector<std::vector<uint8_t>> entries;

    // TODO: Differentiate completed vs. uncompleted files
    while (file && len >= kv::serialised_entry_header_size)
    {
      // Peek entry header
      auto pos = file.tellg();
      kv::SerialisedEntryHeader entry_header = {};
      file.read(
        reinterpret_cast<char*>(&entry_header),
        kv::serialised_entry_header_size);

      const auto& entry_size = entry_header.size;
      if (len < entry_size)
      {
        LOG_FAIL_FMT("Malformed!");
        return 1;
      }

      // Read full entry
      const auto& full_entry_size =
        kv::serialised_entry_header_size + entry_size;
      file.seekg(pos);

      std::vector<uint8_t> entry(full_entry_size);
      file.read(reinterpret_cast<char*>(entry.data()), full_entry_size);

      display_entry(entry);

      entries.emplace_back(std::move(entry));

      // fseeko(file, entry_size, SEEK_CUR);
      len -= full_entry_size;

      LOG_TRACE_FMT("Recovered one entry of size {}", full_entry_size);

      total_len += (full_entry_size);
    }

    break; // TODO: Only one file for now
  }
}