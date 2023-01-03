// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
// #include "grpc/status.h" // TODO: Remove once file is split

#include <google/protobuf/empty.pb.h>
#include <string>
#include <variant>

struct grpc_status
{};

namespace ccf::protobuf
{
  struct Status
  {};
}

namespace protobuf
{
  // TODO: Do something with this
  struct Status
  {};
}

namespace ccf
{
  namespace grpchandler
  {
    template <typename T>
    struct SuccessResponse;

    struct ErrorResponse;

    // Used for server streaming endpoints. Successful response bodies are
    // streamed, not returned by the handler.
    struct PendingResponse;

    using EmptyResponse = google::protobuf::Empty;
    using EmptySuccessResponse = SuccessResponse<EmptyResponse>;

    template <typename T>
    using GrpcAdapterResponse = std::variant<ErrorResponse, SuccessResponse<T>>;
    using GrpcAdapterEmptyResponse = GrpcAdapterResponse<EmptyResponse>;
    using GrpcAdapterStreamingResponse =
      std::variant<ErrorResponse, PendingResponse>;
  }

  template <typename T>
  grpchandler::GrpcAdapterResponse<T> make_success(const T& t);
  grpchandler::GrpcAdapterEmptyResponse make_success();
  grpchandler::PendingResponse make_pending();

  template <typename T>
  grpchandler::GrpcAdapterResponse<T> make_error(
    grpc_status code, const std::string& msg);
  grpchandler::ErrorResponse make_error(
    grpc_status code, const std::string& msg);
}