// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "ccf/rpc_context.h"
#include "message.h"
#include "node/rpc/rpc_exception.h"
#include "types.h"

#include <memory>

namespace ccf::grpc
{
  template <typename In>
  In get_grpc_payload(const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto& request_body = ctx->get_request_body();
    auto request_content_type =
      ctx->get_request_header(http::headers::CONTENT_TYPE);

    auto data = request_body.data();
    auto size = request_body.size();

    if (request_content_type != http::headervalues::contenttype::GRPC)
    {
      throw RpcException(
        HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
        ccf::errors::UnsupportedContentType,
        fmt::format(
          "Unsupported content type. Only {} is supported ",
          http::headervalues::contenttype::GRPC));
    }

    if constexpr (nonstd::is_std_vector<In>::value)
    {
      using Message = typename In::value_type;
      In messages;
      while (size != 0)
      {
        const auto message_length = impl::read_message_frame(data, size);
        if (message_length > size)
        {
          throw std::logic_error(fmt::format(
            "Error in gRPC frame: only {} bytes remaining but message header "
            "says messages is {} bytes",
            size,
            message_length));
        }

        Message& msg = messages.emplace_back();
        if (!msg.ParseFromArray(data, message_length))
        {
          throw std::logic_error(fmt::format(
            "Error deserialising protobuf payload of type {}, size {} (message "
            "{} in "
            "stream)",
            msg.GetTypeName(),
            size,
            messages.size()));
        }
        data += message_length;
        size -= message_length;
      }
      return messages;
    }
    else
    {
      const auto message_length = impl::read_message_frame(data, size);
      if (size != message_length)
      {
        throw std::logic_error(fmt::format(
          "Error in gRPC frame: frame size is {} but messages is {} bytes",
          size,
          message_length));
      }

      In in;
      if (!in.ParseFromArray(data, message_length))
      {
        throw std::logic_error(fmt::format(
          "Error deserialising protobuf payload of type {}, size {}",
          in.GetTypeName(),
          size));
      }
      return in;
    }
  }

  template <typename Out>
  void set_grpc_response(
    const GrpcAdapterResponse<Out>& r,
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    set_grpc_default_headers(ctx);

    if (auto success_response = std::get_if<SuccessResponse<Out>>(&r))
    {
      std::vector<uint8_t> v;

      if constexpr (nonstd::is_std_vector<Out>::value)
      {
        v = serialise_grpc_messages(success_response->body);
      }
      else
      {
        v = serialise_grpc_message(success_response->body);
      }

      ctx->set_response_body(v);

      set_grpc_response_trailers(ctx, success_response->status);
    }
    else if (std::get_if<ErrorResponse>(&r))
    {
      auto error_response = std::get<ErrorResponse>(r);

      set_grpc_response_trailers(ctx, error_response.status);
    }
  }
}
