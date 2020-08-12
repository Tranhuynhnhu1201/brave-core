/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "bat/ledger/internal/endpoint/promotion/post_suggestions/post_suggestions.h"

#include <utility>

#include "base/base64.h"
#include "base/json/json_writer.h"
#include "base/strings/stringprintf.h"
#include "bat/ledger/internal/credentials/credentials_util.h"
#include "bat/ledger/internal/endpoint/promotion/promotions_util.h"
#include "bat/ledger/internal/ledger_impl.h"
#include "net/http/http_status_code.h"

using std::placeholders::_1;

// POST /v1/suggestions
//
// Request body:
// {
//   "credentials": credentials": [
//     {
//       "t": "",
//       "publicKey": "",
//       "signature": ""
//     }
//   ],
//   "suggestion": "base64_string"
// }
//
// Success code:
// HTTP_OK (200)
//
// Error codes:
// HTTP_BAD_REQUEST (400)
// HTTP_INTERNAL_SERVER_ERROR (500)
//
// Response body:
// {Empty}

namespace ledger {
namespace endpoint {
namespace promotion {

PostSuggestions::PostSuggestions(bat_ledger::LedgerImpl* ledger):
    ledger_(ledger) {
  DCHECK(ledger_);
}

PostSuggestions::~PostSuggestions() = default;

std::string PostSuggestions::GetUrl() {
  return GetServerUrl("/v1/suggestions");
}

std::string PostSuggestions::GeneratePayload(
    const braveledger_credentials::CredentialsRedeem& redeem) {
  base::Value data(base::Value::Type::DICTIONARY);
  data.SetStringKey(
      "type",
      braveledger_credentials::ConvertRewardTypeToString(redeem.type));
  if (!redeem.order_id.empty()) {
    data.SetStringKey("orderId", redeem.order_id);
  }
  data.SetStringKey("channel", redeem.publisher_key);

  const bool is_sku =
      redeem.processor == ledger::ContributionProcessor::UPHOLD ||
      redeem.processor == ledger::ContributionProcessor::BRAVE_USER_FUNDS;

  std::string data_json;
  base::JSONWriter::Write(data, &data_json);
  std::string data_encoded;
  base::Base64Encode(data_json, &data_encoded);

  base::Value credentials(base::Value::Type::LIST);
  braveledger_credentials::GenerateCredentials(
      redeem.token_list,
      data_encoded,
      &credentials);

  const std::string data_key = is_sku ? "vote" : "suggestion";
  base::Value payload(base::Value::Type::DICTIONARY);
  payload.SetStringKey(data_key, data_encoded);
  payload.SetKey("credentials", std::move(credentials));

  std::string json;
  base::JSONWriter::Write(payload, &json);
  return json;
}

ledger::Result PostSuggestions::CheckStatusCode(const int status_code) {
  if (status_code == net::HTTP_BAD_REQUEST) {
    BLOG(0, "Invalid request");
    return ledger::Result::LEDGER_ERROR;
  }

  if (status_code == net::HTTP_SERVICE_UNAVAILABLE) {
    BLOG(0, "No conversion rate yet in ratios service");
    return ledger::Result::BAD_REGISTRATION_RESPONSE;
  }

  if (status_code != net::HTTP_OK) {
    return ledger::Result::LEDGER_ERROR;
  }

  return ledger::Result::LEDGER_OK;
}

void PostSuggestions::Request(
    const braveledger_credentials::CredentialsRedeem& redeem,
    PostSuggestionsCallback callback) {
  auto url_callback = std::bind(&PostSuggestions::OnRequest,
      this,
      _1,
      callback);

  ledger_->LoadURL(
      GetUrl(),
      {},
      GeneratePayload(redeem),
      "application/json; charset=utf-8",
      ledger::UrlMethod::POST,
      url_callback);
}

void PostSuggestions::OnRequest(
    const ledger::UrlResponse& response,
    PostSuggestionsCallback callback) {
  ledger::LogUrlResponse(__func__, response);
  callback(CheckStatusCode(response.status_code));
}

}  // namespace promotion
}  // namespace endpoint
}  // namespace ledger
