// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "kv/map.h"
#include "node_info_network.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  /** @enum NodeStatus
   * @brief NodeStatus enum
   * Indicates whether has been trusted by the consortium to be part of the
   * service.
   */
  enum class NodeStatus
  {
    PENDING = 0, /**< PENDING: The node is not yet trusted by the consortium */
    TRUSTED = 1, /**< TRUSTED: The node has been trusted by the consortiun */
    RETIRED = 2 /**< RETIRED: The node has been retired by the consortium */
  };
  DECLARE_JSON_ENUM(
    NodeStatus,
    {{NodeStatus::PENDING, "PENDING"},
     {NodeStatus::TRUSTED, "TRUSTED"},
     {NodeStatus::RETIRED, "RETIRED"}});
}

MSGPACK_ADD_ENUM(ccf::NodeStatus);

namespace ccf
{
  /** @class NodeInfo
   * @brief Node information
   * Lala
   */
  class NodeInfo : public NodeInfoNetwork
  {
  public:
    tls::Pem cert;
    std::vector<uint8_t> quote;
    tls::Pem encryption_pub_key;
    NodeStatus status = NodeStatus::PENDING;

    MSGPACK_DEFINE(
      MSGPACK_BASE(NodeInfoNetwork), cert, quote, encryption_pub_key, status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, cert, quote, encryption_pub_key, status);

  /** @typedef Nodes
   * @tparam Key: NodeId
   * @tparam: Value: NodeInfo
   */
  using Nodes = kv::Map<NodeId, NodeInfo>;
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::NodeStatus>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::NodeStatus& state, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    switch (state)
    {
      case (ccf::NodeStatus::PENDING):
      {
        return format_to(ctx.out(), "PENDING");
      }
      case (ccf::NodeStatus::TRUSTED):
      {
        return format_to(ctx.out(), "TRUSTED");
      }
      case (ccf::NodeStatus::RETIRED):
      {
        return format_to(ctx.out(), "RETIRED");
      }
    }
  }
};
FMT_END_NAMESPACE
