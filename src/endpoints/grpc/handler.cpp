// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "endpoints/grpc.h"
#include "serdes.h"
#include "status.h"
#include "types.h"

namespace ccf
{
  namespace grpc
  {
    template <typename T>
    GrpcAdapterResponse<T> make_success(const T& t)
    {
      return SuccessResponse(t, make_grpc_status_ok());
    }

    GrpcAdapterEmptyResponse make_success()
    {
      return SuccessResponse(EmptyResponse{}, make_grpc_status_ok());
    }

    PendingResponse make_pending()
    {
      return PendingResponse{};
    }

    ErrorResponse make_error(grpc_status code, const std::string& msg)
    {
      return ErrorResponse(make_grpc_status(code, msg));
    }

    template <typename T>
    GrpcAdapterResponse<T> make_error(grpc_status code, const std::string& msg)
    {
      return ErrorResponse(make_grpc_status(code, msg));
    }

    template <typename T>
    static StreamPtr<T> make_stream(
      const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
      http_status status = HTTP_STATUS_OK,
      const http::HeaderMap& headers = default_response_headers);
  }

  template <typename In, typename Out>
  endpoints::EndpointFunction grpc_adapter(const GrpcEndpoint<In, Out>& f)
  {
    return [f](endpoints::EndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }

  template <typename In, typename Out>
  endpoints::ReadOnlyEndpointFunction grpc_read_only_adapter(
    const GrpcReadOnlyEndpoint<In, Out>& f)
  {
    return [f](endpoints::ReadOnlyEndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }

  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_adapter(
    const GrpcCommandEndpoint<In, Out>& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }

  // Note: For now, only command endpoints (i.e. with no kv::Tx) support gRPC
  // server streaming.
  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_unary_stream_adapter(
    const GrpcCommandUnaryStreamEndpoint<In, Out>& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      grpc::set_grpc_default_headers(ctx.rpc_ctx);
      const auto result =
        f(ctx,
          grpc::get_grpc_payload<In>(ctx.rpc_ctx),
          grpc::make_stream<Out>(ctx.rpc_ctx));

      if (auto error_response = std::get_if<grpc::ErrorResponse>(&result))
      {
        grpc::set_grpc_response_trailers(ctx.rpc_ctx, error_response->status);
      }
    };
  }
}