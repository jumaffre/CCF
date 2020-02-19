// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <map>
#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  using KeyShareIndex = ObjectId;
  using EncryptedSharesMap = std::map<MemberId, std::vector<uint8_t>>;

  // TODO: encrypted_ledger_secrets should be a mapping of kv::Version to ledger
  // secrets, all of that encrypted with k_z encrypted_shares should also
  // contain the corresponding member id for each share

  // struct EncryptedKeyShare
  // {
  //   MemberId member_id;
  //   std::vector<uint8_t> encrypted_share;

  //   MSGPACK_DEFINE(member_id, encrypted_share);
  // };

  // DECLARE_JSON_TYPE(EncryptedKeyShare)
  // DECLARE_JSON_REQUIRED_FIELDS(EncryptedKeyShare, member_id, encrypted_share)

  struct KeyShareInfo
  {
    std::vector<uint8_t> encrypted_ledger_secret;
    // std::vector<EncryptedKeyShare> encrypted_shares;
    EncryptedSharesMap encrypted_shares;

    MSGPACK_DEFINE(encrypted_ledger_secret, encrypted_shares);
  };

  // DECLARE_JSON_TYPE(KeyShareInfo)
  // DECLARE_JSON_REQUIRED_FIELDS(
  //   KeyShareInfo, encrypted_ledger_secret, encrypted_shares)

  using Shares = Store::Map<KeyShareIndex, KeyShareInfo>;
}