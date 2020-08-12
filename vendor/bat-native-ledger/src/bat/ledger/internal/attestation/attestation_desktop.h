/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVELEDGER_ATTESTATION_ATTESTATION_DESKTOP_H_
#define BRAVELEDGER_ATTESTATION_ATTESTATION_DESKTOP_H_

#include <memory>
#include <string>

#include "base/values.h"
#include "bat/ledger/internal/attestation/attestation.h"
#include "bat/ledger/internal/endpoint/promotion/promotion_server.h"

namespace bat_ledger {
class LedgerImpl;
}

namespace ledger {
namespace attestation {

class AttestationDesktop : public Attestation {
 public:
  explicit AttestationDesktop(bat_ledger::LedgerImpl* ledger);
  ~AttestationDesktop() override;

  void Start(const std::string& payload, StartCallback callback) override;

  void Confirm(
      const std::string& solution,
      ConfirmCallback callback) override;

 private:
  void ParseClaimSolution(
      const std::string& response,
      base::Value* result);

  void DownloadCaptchaImage(
      const ledger::Result result,
      const std::string& hint,
      const std::string& captcha_id,
      StartCallback callback);

  void OnDownloadCaptchaImage(
      const ledger::Result result,
      const std::string& image,
      const std::string& hint,
      const std::string& captcha_id,
      StartCallback callback);

  void OnConfirm(
      const ledger::Result result,
      ConfirmCallback callback);

  std::unique_ptr<endpoint::PromotionServer> promotion_server_;
};

}  // namespace attestation
}  // namespace ledger
#endif  // BRAVELEDGER_ATTESTATION_ATTESTATION_DESKTOP_H_
