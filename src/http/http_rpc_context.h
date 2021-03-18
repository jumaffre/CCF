// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "http_parser.h"
#include "http_sig.h"
#include "node/rpc/error.h"
#include "ws_parser.h"
#include "ws_rpc_context.h"

namespace http
{
  inline static std::optional<std::string> extract_actor(
    enclave::RpcContext& ctx)
  {
    const auto path = ctx.get_method();

    const auto first_slash = path.find_first_of('/');
    const auto second_slash = path.find_first_of('/', first_slash + 1);

    if (first_slash != 0 || second_slash == std::string::npos)
    {
      return std::nullopt;
    }

    const auto actor = path.substr(first_slash + 1, second_slash - 1);
    const auto remaining_path = path.substr(second_slash + 1);

    if (actor.empty() || remaining_path.empty())
    {
      return std::nullopt;
    }

    ctx.set_method(remaining_path);
    return actor;
  }

  inline std::vector<uint8_t> error(ccf::ErrorDetails&& error)
  {
    nlohmann::json body = ccf::ODataErrorResponse{
      ccf::ODataError{std::move(error.code), std::move(error.msg)}};
    const auto s = body.dump();

    std::vector<uint8_t> data(s.begin(), s.end());
    auto response = http::Response(error.status);

    response.set_header(
      http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
    response.set_body(&data);

    return response.build_response();
  }

  inline std::vector<uint8_t> error(
    http_status status, const std::string& code, std::string&& msg)
  {
    return error({status, code, std::move(msg)});
  }

  class HttpRpcContext : public enclave::RpcContext
  {
  private:
    size_t request_index;

    ccf::RESTVerb verb;
    std::string whole_path = {};
    std::string path = {};
    std::string query = {};

    http::HeaderMap request_headers = {};

    std::vector<uint8_t> request_body = {};
    enclave::PathParams path_params = {};

    std::vector<uint8_t> serialised_request = {};

    http::HeaderMap response_headers;
    std::vector<uint8_t> response_body = {};
    http_status response_status = HTTP_STATUS_OK;

    bool canonicalised = false;

    std::optional<bool> explicit_apply_writes = std::nullopt;

    void canonicalise()
    {
      if (!canonicalised)
      {
        // Build a canonical serialization of this request. If the request is
        // signed, then all unsigned headers must be removed
        const auto auth_it = request_headers.find(http::headers::AUTHORIZATION);
        if (auth_it != request_headers.end())
        {
          std::string_view authz_header = auth_it->second;

          if (http::HttpSignatureVerifier::parse_auth_scheme(authz_header))
          {
            auto parsed_sign_params =
              http::HttpSignatureVerifier::parse_signature_params(authz_header);

            if (!parsed_sign_params.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unable to parse signature params from: {}", authz_header));
            }

            // Keep all signed headers, and the auth header containing the
            // signature itself
            auto& signed_headers = parsed_sign_params->signed_headers;
            signed_headers.emplace_back(http::headers::AUTHORIZATION);

            auto it = request_headers.begin();
            while (it != request_headers.end())
            {
              if (
                std::find(
                  signed_headers.begin(), signed_headers.end(), it->first) ==
                signed_headers.end())
              {
                it = request_headers.erase(it);
              }
              else
              {
                ++it;
              }
            }
          }
        }

        const auto canonical_request_header = fmt::format(
          "{} {}{} HTTP/1.1\r\n"
          "{}"
          "\r\n",
          verb.c_str(),
          whole_path,
          query.empty() ? "" : fmt::format("?{}", query),
          http::get_header_string(request_headers));

        serialised_request.resize(
          canonical_request_header.size() + request_body.size());
        ::memcpy(
          serialised_request.data(),
          canonical_request_header.data(),
          canonical_request_header.size());
        if (!request_body.empty())
        {
          ::memcpy(
            serialised_request.data() + canonical_request_header.size(),
            request_body.data(),
            request_body.size());
        }
      }

      canonicalised = true;
    }

  public:
    HttpRpcContext(
      size_t request_index_,
      std::shared_ptr<enclave::SessionContext> s,
      llhttp_method verb_,
      const std::string_view& path_,
      const std::string_view& query_,
      const http::HeaderMap& headers_,
      const std::vector<uint8_t>& body_,
      const std::vector<uint8_t>& raw_request_ = {},
      const std::vector<uint8_t>& raw_bft_ = {}) :
      RpcContext(s, raw_bft_),
      request_index(request_index_),
      verb(verb_),
      path(path_),
      query(query_),
      request_headers(headers_),
      request_body(body_),
      serialised_request(raw_request_)
    {
      whole_path = path;

      if (!serialised_request.empty())
      {
        canonicalised = true;
      }
    }

    virtual enclave::FrameFormat frame_format() const override
    {
      return enclave::FrameFormat::http;
    }

    virtual size_t get_request_index() const override
    {
      return request_index;
    }

    virtual void set_tx_id(const ccf::TxID& tx_id) override
    {
      set_response_header(http::headers::CCF_TX_ID, tx_id.to_str());
    }

    virtual const std::vector<uint8_t>& get_request_body() const override
    {
      return request_body;
    }

    virtual const std::string& get_request_query() const override
    {
      return query;
    }

    virtual enclave::PathParams& get_request_path_params() override
    {
      return path_params;
    }

    virtual const ccf::RESTVerb& get_request_verb() const override
    {
      return verb;
    }

    virtual std::string get_request_path() const override
    {
      return whole_path;
    }

    virtual const std::vector<uint8_t>& get_serialised_request() override
    {
      canonicalise();
      return serialised_request;
    }

    virtual std::string get_method() const override
    {
      return path;
    }

    virtual void set_method(const std::string_view& p) override
    {
      path = p;
    }

    virtual const http::HeaderMap& get_request_headers() const override
    {
      return request_headers;
    }

    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) override
    {
      const auto it = request_headers.find(name);
      if (it != request_headers.end())
      {
        return it->second;
      }

      return std::nullopt;
    }

    virtual void set_response_body(const std::vector<uint8_t>& body) override
    {
      response_body = body;
    }

    virtual void set_response_body(std::vector<uint8_t>&& body) override
    {
      response_body = std::move(body);
    }

    virtual void set_response_body(std::string&& body) override
    {
      response_body = std::vector<uint8_t>(body.begin(), body.end());
      if (
        response_headers.find(http::headers::CONTENT_TYPE) ==
        response_headers.end())
      {
        // Convenient auto-set content type if none have been set yet
        set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
      }
    }

    virtual void set_response_status(int status) override
    {
      response_status = (http_status)status;
    }

    virtual int get_response_status() const override
    {
      return response_status;
    }

    virtual void set_response_header(
      const std::string_view& name, const std::string_view& value) override
    {
      response_headers[std::string(name)] = value;
    }

    virtual void set_apply_writes(bool apply) override
    {
      explicit_apply_writes = apply;
    }

    virtual bool should_apply_writes() const override
    {
      if (explicit_apply_writes.has_value())
      {
        return explicit_apply_writes.value();
      }

      // Default is to apply any 2xx status
      return status_success(response_status);
    }

    virtual std::vector<uint8_t> serialise_response() const override
    {
      auto http_response = http::Response(response_status);

      for (const auto& [k, v] : response_headers)
      {
        http_response.set_header(k, v);
      }

      http_response.set_body(&response_body);
      return http_response.build_response();
    }
  };
}

// https://github.com/microsoft/CCF/issues/844
namespace enclave
{
  inline std::shared_ptr<RpcContext> make_rpc_context(
    std::shared_ptr<enclave::SessionContext> s,
    const std::vector<uint8_t>& packed,
    const std::vector<uint8_t>& raw_bft = {})
  {
    http::SimpleRequestProcessor processor;
    http::RequestParser parser(processor);

    parser.execute(packed.data(), packed.size());

    if (processor.received.size() != 1)
    {
      throw std::logic_error(fmt::format(
        "Expected packed to contain a single complete HTTP message. Actually "
        "parsed {} messages",
        processor.received.size()));
    }

    const auto& msg = processor.received.front();

    return std::make_shared<http::HttpRpcContext>(
      0,
      s,
      msg.method,
      msg.path,
      msg.query,
      msg.headers,
      msg.body,
      packed,
      raw_bft);
  }

  inline std::shared_ptr<enclave::RpcContext> make_fwd_rpc_context(
    std::shared_ptr<enclave::SessionContext> s,
    const std::vector<uint8_t>& packed,
    enclave::FrameFormat frame_format,
    const std::vector<uint8_t>& raw_bft = {})
  {
    switch (frame_format)
    {
      case enclave::FrameFormat::http:
      {
        return make_rpc_context(s, packed, raw_bft);
      }
      case enclave::FrameFormat::ws:
      {
        http::SimpleRequestProcessor processor;
        ws::RequestParser parser(processor);

        auto next_read = ws::INITIAL_READ;
        size_t index = 0;
        while (index < packed.size())
        {
          const auto next_next =
            parser.consume(packed.data() + index, next_read);
          index += next_read;
          next_read = next_next;
        }

        if (processor.received.size() != 1)
        {
          throw std::logic_error(fmt::format(
            "Expected packed to contain a single complete WS message. Actually "
            "parsed {} messages",
            processor.received.size()));
        }

        const auto& msg = processor.received.front();

        return std::make_shared<ws::WsRpcContext>(
          0, s, msg.path, msg.body, packed, raw_bft);
      }
      default:
        throw std::logic_error("Unknown Frame Format");
    }
  }
}