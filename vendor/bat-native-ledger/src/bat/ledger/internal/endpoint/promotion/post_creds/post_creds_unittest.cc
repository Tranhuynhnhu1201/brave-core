/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "bat/ledger/internal/endpoint/promotion/post_creds/post_creds.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/test/task_environment.h"
#include "bat/ledger/internal/ledger_client_mock.h"
#include "bat/ledger/internal/ledger_impl_mock.h"
#include "bat/ledger/ledger.h"
#include "net/http/http_status_code.h"
#include "testing/gtest/include/gtest/gtest.h"

// npm run test -- brave_unit_tests --filter=PostCredsTest.*

using ::testing::_;
using ::testing::Invoke;

namespace ledger {
namespace endpoint {
namespace promotion {

class PostCredsTest : public testing::Test {
 private:
  base::test::TaskEnvironment scoped_task_environment_;

 protected:
  std::unique_ptr<ledger::MockLedgerClient> mock_ledger_client_;
  std::unique_ptr<bat_ledger::MockLedgerImpl> mock_ledger_impl_;
  std::unique_ptr<PostCreds> creds_;

  PostCredsTest() {
    mock_ledger_client_ = std::make_unique<ledger::MockLedgerClient>();
    mock_ledger_impl_ =
        std::make_unique<bat_ledger::MockLedgerImpl>(mock_ledger_client_.get());
    creds_ = std::make_unique<PostCreds>(mock_ledger_impl_.get());
  }
};

TEST_F(PostCredsTest, ServerOK) {
  ON_CALL(*mock_ledger_client_, LoadURL(_, _, _, _, _, _))
      .WillByDefault(
          Invoke([](
              const std::string& url,
              const std::vector<std::string>& headers,
              const std::string& content,
              const std::string& contentType,
              const ledger::UrlMethod method,
              ledger::LoadURLCallback callback) {
            ledger::UrlResponse response;
            response.status_code = 200;
            response.url = url;
            response.body = R"({
              "claimId": "53714048-9675-419e-baa3-369d85a2facb"
            })";
            callback(response);
          }));

  auto creds = std::make_unique<base::ListValue>();

  creds_->Request(
      "ff50981d-47de-4210-848d-995e186901a1",
      std::move(creds),
      [](const ledger::Result result, const std::string& claim_id) {

  });
}

}  // namespace promotion
}  // namespace endpoint
}  // namespace ledger
