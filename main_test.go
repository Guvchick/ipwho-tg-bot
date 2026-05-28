package main

import (
	"strings"
	"testing"
)

func TestParseSubscriptionBodyArrayOfXrayConfigs(t *testing.T) {
	raw := `[
		{
			"remarks": "first config",
			"outbounds": [
				{
					"tag": "proxy",
					"protocol": "vless",
					"settings": {
						"vnext": [
							{
								"address": "example.com",
								"port": 443,
								"users": [
									{
										"id": "00000000-0000-4000-8000-000000000000",
										"flow": "xtls-rprx-vision"
									}
								]
							}
						]
					},
					"streamSettings": {
						"network": "tcp",
						"security": "reality",
						"realitySettings": {
							"serverName": "example.com",
							"publicKey": "public-key",
							"shortId": "abcd",
							"fingerprint": "chrome"
						}
					}
				},
				{"tag": "direct", "protocol": "freedom"}
			]
		}
	]`

	lines, format := parseSubscriptionBody(raw)
	if format != "xray-json" {
		t.Fatalf("format = %q, want xray-json", format)
	}
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1: %#v", len(lines), lines)
	}

	proxy, err := parseProxyURI(lines[0])
	if err != nil {
		t.Fatalf("parseProxyURI returned error: %v", err)
	}
	if proxy.Proto != "vless" || proxy.Host != "example.com" || proxy.Port != "443" {
		t.Fatalf("proxy = %#v, want vless example.com:443", proxy)
	}
}

func TestSubscriptionClientProfileDoesNotUseBotOrServerIdentifiers(t *testing.T) {
	for _, ua := range subscriptionUAChain {
		if strings.Contains(strings.ToLower(ua), "ipwho-tg-bot") {
			t.Fatalf("subscription UA %q exposes bot identifier", ua)
		}
	}

	headers := subscriptionBaseHeaders(Config{HWID: "test-hwid"})
	if headers["x-device-model"] == "Server" {
		t.Fatal("x-device-model must not be Server")
	}
	if headers["x-hwid"] != "test-hwid" {
		t.Fatalf("x-hwid = %q, want test-hwid", headers["x-hwid"])
	}
}
