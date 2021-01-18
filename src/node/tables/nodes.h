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
  /** Nodes table name */
  static constexpr auto NODES_MAP_NAME = "public:ccf.gov.nodes";

  /** @enum NodeStatus
   * @brief Indicates whether has been trusted by the consortium to be part of
   * the service.
   */
  enum class NodeStatus
  {
    PENDING = 0, /**< The node is not yet trusted by the consortium */
    TRUSTED = 1, /**< The node has been trusted by the consortiun */
    RETIRED = 2 /**< The node has been retired by the consortium */
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
  /** @struct NodeInfo
   * @brief Node information...
   */
  struct NodeInfo : public NodeInfoNetwork
  {
    tls::Pem cert; /**< x509 PEM certificate */
    std::vector<uint8_t> quote; /**< Raw SGW Quote */
    tls::Pem
      encryption_pub_key; /**< Node encryption public key (internal use only) */
    NodeStatus status =
      NodeStatus::PENDING; /**< ccf::NodeStatus Status of node */

    MSGPACK_DEFINE(
      MSGPACK_BASE(NodeInfoNetwork), cert, quote, encryption_pub_key, status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, cert, quote, encryption_pub_key, status);

  /** @typedef NodeId
   * @brief Unique node identifier
   * @tparam NodeId Unsigned 64-bit integer
   */
  using NodeId = uint64_t;

  /** @typedef Nodes
   * @brief Nodes table
   * @tparam Key: NodeId
   * @tparam Value: NodeInfo
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
