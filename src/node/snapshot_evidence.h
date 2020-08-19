// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "kv/map.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  struct SnapshotHash
  {
    crypto::Sha256Hash hash;

    MSGPACK_DEFINE(hash);
  };

  // As we only keep track of the latest snapshot, the key for the
  // SnapshotEvidence table is always 0.
  using SnapshotEvidence = kv::Map<size_t, SnapshotHash>;
}