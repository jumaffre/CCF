// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "grpc/status.h"

#include <google/protobuf/empty.pb.h>
#include <string>
#include <variant>

namespace ccf::grpc
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

  template <typename T>
  GrpcAdapterResponse<T> make_success(const T& t);
  GrpcAdapterEmptyResponse make_success();
  PendingResponse make_pending();

  template <typename T>
  GrpcAdapterResponse<T> make_error(grpc_status code, const std::string& msg);
  ErrorResponse make_error(grpc_status code, const std::string& msg);
}