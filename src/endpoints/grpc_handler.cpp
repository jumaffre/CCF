// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "grpc_handler.h"

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
// #include "grpc/status.h"

namespace ccf
{
  // TODO: Remove following functions
  static protobuf::Status make_grpc_status_ok()
  {
    return protobuf::Status{};
  }

  static protobuf::Status make_grpc_status(
    grpc_status status, const std::optional<std::string>& msg = std::nullopt)
  {
    return protobuf::Status{};
  }

  namespace grpchandler
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

    struct PendingResponse
    {};
  }

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

  template <typename T>
  grpchandler::GrpcAdapterResponse<T> make_success(const T& t)
  {
    return grpchandler::SuccessResponse(t, make_grpc_status_ok());
  }

  grpchandler::GrpcAdapterEmptyResponse make_success()
  {
    return grpchandler::SuccessResponse(
      grpchandler::EmptyResponse{}, make_grpc_status_ok());
  }

  grpchandler::PendingResponse make_pending()
  {
    return grpchandler::PendingResponse{};
  }

  grpchandler::ErrorResponse make_error(
    grpc_status code, const std::string& msg)
  {
    return grpchandler::ErrorResponse(make_grpc_status(code, msg));
  }

  template <typename T>
  grpchandler::GrpcAdapterResponse<T> make_error(
    grpc_status code, const std::string& msg)
  {
    return grpchandler::ErrorResponse(make_grpc_status(code, msg));
  }
}