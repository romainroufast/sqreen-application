#!/bin/bash
# shellcheck disable=SC2034
for i in {1..100}
do
  curl -H 'X-Sqreen-Integrity: 6ca318aef4a4ed2a29ddf90a4e4e3165a58fe390f7a1c1ccf245da4a912fa938' -H 'Content-Type: application/json' -d '[{"message_id": null, "api_version": "2", "date_created": "2020-06-08T19:30:16.039128+00:00", "message_type": "security_event", "retry_count": 0, "message": {"risk_coefficient": 25, "event_category": "http_error", "event_kind": "waf", "application_id": "5ede853e66ff200020ad47db", "application_name": "romain_test", "environment": "development", "date_occurred": "2020-06-08T18:41:14.475000+00:00", "event_id": "5ede864a699b1000110a9d81", "event_url": "https://my.sqreen.com/application/5ede853e66ff200020ad47db/events/5ede864a699b1000110a9d81", "humanized_description": "Attack tentative from 127.0.0.1", "ips": [{"address": "127.0.0.1", "is_tor": false, "geo": {}, "date_resolved": "2020-06-08T18:41:14.636000+00:00"}]}}]' 'http://127.0.0.1:5000/security_alert'
done