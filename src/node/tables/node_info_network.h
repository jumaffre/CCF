// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <msgpack/msgpack.hpp>
#include <string>

namespace ccf
{
  /** @struct NodeInfoNetwork
   *  @brief Node network information
   */
  struct NodeInfoNetwork
  {
    std::string rpchost; /**< Node local RPC host */
    std::string pubhost; /**< Node RPC host */
    std::string nodehost; /**< Node-to-node local host */
    std::string nodeport; /**< Node-to-node local port */
    std::string rpcport; /**< Node local RPC port */
    std::string pubport; /**< Node RPC host */

    MSGPACK_DEFINE(rpchost, pubhost, nodehost, nodeport, rpcport, pubport);
  };
  DECLARE_JSON_TYPE(NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork, rpchost, pubhost, nodehost, nodeport, rpcport, pubport);
}