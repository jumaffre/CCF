// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "grpc/status.h" // TODO: Split file
#include "grpc/stream.h" // TODO: Split file
#include "grpc_status.h"

#include <google/protobuf/empty.pb.h>
#include <memory>
#include <string>
#include <variant>

namespace ccf
{
  namespace grpc
  {
    template <typename T>
    struct SuccessResponse
    {
      T body;
      ccf::protobuf::Status status;

      SuccessResponse(const T& body_, ccf::protobuf::Status status_) :
        body(body_),
        status(status_)
      {}
    };

    struct ErrorResponse
    {
      ccf::protobuf::Status status;
      ErrorResponse(ccf::protobuf::Status status_) : status(status_) {}
    };

    // Used for server streaming endpoints. Successful response bodies are
    // streamed, not returned by the handler.
    struct PendingResponse
    {};

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

  template <typename In, typename Out>
  using GrpcEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::EndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcReadOnlyEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::ReadOnlyEndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcCommandEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::CommandEndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcCommandUnaryStreamEndpoint =
    std::function<grpc::GrpcAdapterStreamingResponse(
      endpoints::CommandEndpointContext&, In&&, grpc::StreamPtr<Out>&&)>;

  template <typename In, typename Out>
  endpoints::EndpointFunction grpc_adapter(const GrpcEndpoint<In, Out>& f);

  template <typename In, typename Out>
  endpoints::ReadOnlyEndpointFunction grpc_read_only_adapter(
    const GrpcReadOnlyEndpoint<In, Out>& f);

  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_adapter(
    const GrpcCommandEndpoint<In, Out>& f);

  // Note: For now, only command endpoints (i.e. with no kv::Tx) support gRPC
  // server streaming.
  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_unary_stream_adapter(
    const GrpcCommandUnaryStreamEndpoint<In, Out>& f);
}