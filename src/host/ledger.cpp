// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "kv/generic_serialise_wrapper.h"
#include "kv/serialised_entry_format.h"

#include <filesystem>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

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

    // 1. Read offset table
    size_t offset_header_table;
    file.read(
      reinterpret_cast<char*>(&offset_header_table),
      sizeof(offset_header_table));
    LOG_INFO_FMT("Offset header table: {}", offset_header_table);

    size_t total_len = sizeof(size_t);
    auto len = offset_header_table - total_len;

    // API:
    // Register on_entry_begin, on_table, on_key, on_value, on_entry_end
    std::vector<std::vector<uint8_t>> entries;

    // TODO: Differentiate completed vs. uncompleted files
    while (file && len >= kv::serialised_entry_header_size)
    {
      LOG_FAIL_FMT("len: {}", len);
      kv::SerialisedEntryHeader entry_header = {};
      file.read(
        reinterpret_cast<char*>(&entry_header),
        kv::serialised_entry_header_size);

      len -= kv::serialised_entry_header_size;

      const auto& entry_size = entry_header.size;
      if (len < entry_size)
      {
        LOG_FAIL_FMT("Malformed!");
        return 1;
      }

      LOG_FAIL_FMT("Entry of size: {}", entry_size);

      std::vector<uint8_t> entry(entry_size);
      file.read(reinterpret_cast<char*>(entry.data()), entry.size());

      entries.emplace_back(std::move(entry));

      // fseeko(file, entry_size, SEEK_CUR);
      len -= entry_size;

      LOG_TRACE_FMT(
        "Recovered one entry of size {}",
        kv::serialised_entry_header_size + entry_size);

      total_len += (kv::serialised_entry_header_size + entry_size);
    }
  }
}