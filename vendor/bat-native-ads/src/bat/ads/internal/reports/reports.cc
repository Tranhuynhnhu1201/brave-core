/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/reports/reports.h"

#include "brave/components/l10n/browser/locale_helper.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "bat/ads/internal/ads_impl.h"
#include "bat/ads/internal/classification/page_classifier/page_classifier.h"
#include "bat/ads/internal/classification/classification_util.h"
#include "bat/ads/internal/search_engine/search_providers.h"
#include "bat/ads/internal/time_util.h"

namespace ads {

Reports::Reports(
    AdsImpl* ads)
    : ads_(ads) {
  DCHECK(ads_);
}

Reports::~Reports() = default;

std::string Reports::GenerateAdNotificationEventReport(
    const AdNotificationInfo& info,
    const AdNotificationEventType event_type) const {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  const base::Time time = base::Time::Now();
  const std::string timestamp = LongFormatFriendlyDateAndTime(time, false);

  writer.StartObject();

  static bool is_first_run = true;
  if (is_first_run) {
    is_first_run = false;

    writer.String("data");
    writer.StartObject();

    writer.String("type");
    writer.String("restart");

    writer.String("timestamp");
    writer.String(timestamp.c_str());

    writer.EndObject();
  }

  writer.String("data");
  writer.StartObject();

  writer.String("type");
  writer.String("notify");

  writer.String("timestamp");
  writer.String(timestamp.c_str());

  writer.String("eventType");
  switch (event_type) {
    case AdNotificationEventType::kViewed: {
      writer.String("generated");
      break;
    }

    case AdNotificationEventType::kClicked: {
      writer.String("clicked");
      break;
    }

    case AdNotificationEventType::kDismissed: {
      writer.String("dismissed");
      break;
    }

    case AdNotificationEventType::kTimedOut: {
      writer.String("timed out");
      break;
    }
  }

  writer.String("classifications");
  writer.StartArray();
  auto classifications = classification::SplitCategory(info.category);
  for (const auto& classification : classifications) {
    writer.String(classification.c_str());
  }
  writer.EndArray();

  writer.String("adCatalog");
  writer.String(info.creative_set_id.c_str());

  writer.String("targetUrl");
  writer.String(info.target_url.c_str());

  writer.EndObject();

  writer.EndObject();

  return buffer.GetString();
}

std::string Reports::GenerateLoadEventReport(
    const LoadInfo& info) const {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  writer.StartObject();

  writer.String("data");
  writer.StartObject();

  writer.String("type");
  writer.String("load");

  writer.String("timestamp");
  const base::Time time = base::Time::Now();
  const std::string timestamp = LongFormatFriendlyDateAndTime(time, false);
  writer.String(timestamp.c_str());

  writer.String("tabId");
  writer.Int(info.tab_id);

  writer.String("tabType");
  if (SearchProviders::IsSearchEngine(info.tab_url)) {
    writer.String("search");
  } else {
    writer.String("click");
  }

  writer.String("tabClassification");
  writer.StartArray();
  auto classifications = classification::SplitCategory(info.tab_classification);
  for (const auto& classification : classifications) {
    writer.String(classification.c_str());
  }
  writer.EndArray();

  auto page_probabilities_cache =
      ads_->get_page_classifier()->get_page_probabilities_cache();
  auto iter = page_probabilities_cache.find(info.tab_url);
  if (iter != page_probabilities_cache.end()) {
    writer.String("pageProbabilities");
    writer.StartArray();

    const classification::PageProbabilitiesMap page_probabilities =
        iter->second;
    for (const auto& page_probability : page_probabilities) {
      writer.StartObject();

      writer.String("category");
      const std::string category = page_probability.first;
      writer.String(category.c_str());

      writer.String("pageScore");
      const double page_score = page_probability.second;
      writer.Double(page_score);

      writer.EndObject();
    }
    writer.EndArray();
  }

  writer.EndObject();

  writer.EndObject();

  return buffer.GetString();
}

std::string Reports::GenerateSettingsEventReport() const {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  writer.StartObject();

  writer.String("data");
  writer.StartObject();

  writer.String("type");
  writer.String("settings");

  writer.String("timestamp");
  const base::Time time = base::Time::Now();
  const std::string timestamp = LongFormatFriendlyDateAndTime(time, false);
  writer.String(timestamp.c_str());

  writer.String("settings");
  writer.StartObject();

  writer.String("locale");
  const std::string locale =
      brave_l10n::LocaleHelper::GetInstance()->GetLocale();
  writer.String(locale.c_str());

  writer.String("notifications");
  writer.StartObject();

  writer.String("shouldShow");
  auto should_show = ads_->get_ads_client()->ShouldShowNotifications();
  writer.Bool(should_show);

  writer.EndObject();

  writer.String("adsPerDay");
  auto ads_per_day = ads_->get_ads_client()->GetAdsPerDay();
  writer.Uint64(ads_per_day);

  writer.String("adsPerHour");
  auto ads_per_hour = ads_->get_ads_client()->GetAdsPerHour();
  writer.Uint64(ads_per_hour);

  writer.EndObject();

  writer.EndObject();

  writer.EndObject();

  return buffer.GetString();
}

}  // namespace ads