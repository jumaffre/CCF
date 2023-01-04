// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "status.h"

#include <google/protobuf/empty.pb.h>
#include <optional>
#include <string>
#include <variant>

namespace ccf::grpc
{
  static const http::HeaderMap default_response_headers = {
    {http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC}};

  static constexpr auto TRAILER_STATUS = "grpc-status";
  static constexpr auto TRAILER_MESSAGE = "grpc-message";

  static http::HeaderKeyValue make_status_trailer(int32_t code)
  {
    return {TRAILER_STATUS, std::to_string(code)};
  }

  static http::HeaderKeyValue make_message_trailer(const std::string& msg)
  {
    return {TRAILER_MESSAGE, msg};
  }

  inline void set_grpc_default_headers(
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    for (auto const& h : default_response_headers)
    {
      ctx->set_response_header(h.first, h.second);
    }
  }

  inline void set_grpc_response_trailers(
    const std::shared_ptr<ccf::RpcContext>& ctx,
    const ccf::protobuf::Status& status)
  {
    ctx->set_response_trailer(make_status_trailer(status.code()));
    ctx->set_response_trailer(make_message_trailer(status.message()));
  }
}