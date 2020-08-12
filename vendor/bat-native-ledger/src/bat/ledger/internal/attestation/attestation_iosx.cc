/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <utility>
#include <vector>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "bat/ledger/internal/attestation/attestation_iosx.h"
#include "bat/ledger/internal/ledger_impl.h"

using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

namespace ledger {
namespace attestation {

AttestationIOS::AttestationIOS(bat_ledger::LedgerImpl* ledger) :
    Attestation(ledger),
    promotion_server_(new endpoint::PromotionServer(ledger)) {
}

AttestationIOS::~AttestationIOS() = default;

std::string AttestationIOS::ParseStartPayload(
    const std::string& response) {
  base::Optional<base::Value> value = base::JSONReader::Read(response);
  if (!value || !value->is_dict()) {
    return "";
  }

  base::DictionaryValue* dictionary = nullptr;
  if (!value->GetAsDictionary(&dictionary)) {
    return "";
  }

  const auto* key = dictionary->FindStringKey("publicKey");
  if (!key) {
    BLOG(0, "Public key is wrong");
    return "";
  }

  return *key;
}

void AttestationIOS::ParseClaimSolution(
    const std::string& response,
    base::Value* result) {
  base::Optional<base::Value> value = base::JSONReader::Read(response);
  if (!value || !value->is_dict()) {
    return;
  }

  base::DictionaryValue* dictionary = nullptr;
  if (!value->GetAsDictionary(&dictionary)) {
    return;
  }

  const auto* nonce = dictionary->FindStringKey("nonce");
  if (!nonce) {
    BLOG(0, "Nonce is wrong");
    return;
  }

  const auto* blob = dictionary->FindStringKey("blob");
  if (!blob) {
    BLOG(0, "Blob is wrong");
    return;
  }

  const auto* signature = dictionary->FindStringKey("signature");
  if (!signature) {
    BLOG(0, "Signature is wrong");
    return;
  }

  result->SetStringKey("nonce", *nonce);
  result->SetStringKey("blob", *blob);
  result->SetStringKey("signature", *signature);
}

void AttestationIOS::Start(
    const std::string& payload,
    StartCallback callback) {
  const std::string key = ParseStartPayload(payload);
  const std::string payment_id = ledger_->state()->GetPaymentId();

  if (key.empty()) {
    BLOG(0, "Key is empty");
    callback(ledger::Result::LEDGER_ERROR, "");
    return;
  }
  auto url_callback = std::bind(&AttestationIOS::OnStart,
      this,
      _1,
      _2,
      callback);

  promotion_server_->post_devicecheck()->Request(key, url_callback);
}

void AttestationIOS::OnStart(
    const ledger::Result result,
    const std::string& nonce,
    StartCallback callback) {
  if (result != ledger::Result::LEDGER_OK) {
    BLOG(0, "Failed to start attestation");
    callback(ledger::Result::LEDGER_ERROR, "");
    return;
  }

  callback(ledger::Result::LEDGER_OK, nonce);
}

void AttestationIOS::Confirm(
    const std::string& solution,
    ConfirmCallback callback) {
  base::Value parsed_solution(base::Value::Type::DICTIONARY);
  ParseClaimSolution(solution, &parsed_solution);

  if (parsed_solution.DictSize() != 3) {
    BLOG(0, "Solution is wrong: " << solution);
    callback(ledger::Result::LEDGER_ERROR);
    return;
  }

  const std::string nonce = *parsed_solution.FindStringKey("nonce");
  const std::string blob = *parsed_solution.FindStringKey("blob");
  const std::string signature = *parsed_solution.FindStringKey("signature");

  auto url_callback = std::bind(&AttestationIOS::OnConfirm,
      this,
      _1,
      callback);

  promotion_server_->put_devicecheck()->Request(
      blob,
      signature,
      nonce,
      url_callback);
}

void AttestationIOS::OnConfirm(
    const ledger::Result result,
    ConfirmCallback callback) {
  if (result != ledger::Result::LEDGER_OK) {
    BLOG(0, "Failed to confirm attestation");
    callback(ledger::Result::LEDGER_ERROR);
    return;
  }

  callback(ledger::Result::LEDGER_OK);
}

}  // namespace attestation
}  // namespace ledger
