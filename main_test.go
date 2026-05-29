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

func TestParseSubscriptionBodyXHTTPTransportDetails(t *testing.T) {
	raw := `{
		"outbounds": [
			{
				"tag": "xhttp-node",
				"protocol": "vless",
				"settings": {
					"vnext": [
						{
							"address": "xhttp.example.com",
							"port": 443,
							"users": [
								{
									"id": "00000000-0000-4000-8000-000000000001",
									"flow": "xtls-rprx-vision"
								}
							]
						}
					]
				},
				"streamSettings": {
					"network": "xhttp",
					"security": "reality",
					"realitySettings": {
						"serverName": "front.example.com",
						"publicKey": "public-key",
						"shortId": "abcd",
						"fingerprint": "chrome"
					},
					"tlsSettings": {
						"alpn": ["h2", "http/1.1"]
					},
					"xhttpSettings": {
						"host": "edge.example.com",
						"path": "/xhttp",
						"mode": "auto"
					}
				}
			}
		]
	}`

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
	if proxy.Network != "xhttp" || proxy.Path != "/xhttp" || proxy.HostHeader != "edge.example.com" || proxy.Mode != "auto" {
		t.Fatalf("proxy transport = %#v, want xhttp /xhttp edge.example.com auto", proxy)
	}
	if proxy.Security != "reality" || proxy.SNI != "front.example.com" || proxy.PublicKey != "public-key" || proxy.ShortID != "abcd" {
		t.Fatalf("proxy tls = %#v, want reality details", proxy)
	}
	if proxy.ALPN != "h2,http/1.1" {
		t.Fatalf("proxy ALPN = %q, want h2,http/1.1", proxy.ALPN)
	}
}

func TestParseSubscriptionBodySingBoxXHTTPTransportDetails(t *testing.T) {
	raw := `{
		"outbounds": [
			{
				"type": "vless",
				"tag": "sing-xhttp",
				"server": "sing.example.com",
				"server_port": 443,
				"uuid": "00000000-0000-4000-8000-000000000003",
				"flow": "xtls-rprx-vision",
				"tls": {
					"enabled": true,
					"server_name": "front.sing.example.com",
					"utls": {
						"fingerprint": "chrome"
					},
					"reality": {
						"enabled": true,
						"public_key": "sing-public-key",
						"short_id": "ef01"
					}
				},
				"transport": {
					"type": "xhttp",
					"host": "edge.sing.example.com",
					"path": "/sing-xhttp",
					"mode": "packet"
				}
			}
		]
	}`

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
	if proxy.Network != "xhttp" || proxy.Path != "/sing-xhttp" || proxy.HostHeader != "edge.sing.example.com" || proxy.Mode != "packet" {
		t.Fatalf("proxy transport = %#v, want sing-box xhttp details", proxy)
	}
	if proxy.Security != "reality" || proxy.SNI != "front.sing.example.com" || proxy.PublicKey != "sing-public-key" || proxy.ShortID != "ef01" {
		t.Fatalf("proxy tls = %#v, want sing-box reality details", proxy)
	}
}

func TestParseAdditionalProxyProtocols(t *testing.T) {
	tests := []struct {
		raw     string
		proto   string
		network string
	}{
		{"hysteria2://secret@example.com:443?sni=hy.example.com&obfs=salamander#hy2", "hysteria2", "udp"},
		{"hy2://secret@example.com:443?sni=hy.example.com#hy2-short", "hysteria2", "udp"},
		{"tuic://00000000-0000-4000-8000-000000000002:secret@example.com:443?sni=tuic.example.com&congestion_control=bbr#tuic", "tuic", "udp"},
	}

	for _, tt := range tests {
		proxy, err := parseProxyURI(tt.raw)
		if err != nil {
			t.Fatalf("parseProxyURI(%q) returned error: %v", tt.raw, err)
		}
		if proxy.Proto != tt.proto || proxy.Network != tt.network || proxy.Host != "example.com" || proxy.Port != "443" {
			t.Fatalf("proxy = %#v, want %s example.com:443 over %s", proxy, tt.proto, tt.network)
		}
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
