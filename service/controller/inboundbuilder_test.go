package controller_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
	. "github.com/XrayR-project/XrayR/service/controller"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestBuildREALITYMinClientVer(t *testing.T) {
	for _, source := range []string{"panel", "local"} {
		for _, version := range []string{"", "26.3.27"} {
			name := version
			if name == "" {
				name = "default"
			}
			t.Run(source+"/"+name, func(t *testing.T) {
				privateKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				config := &Config{}
				node := &api.NodeInfo{
					NodeType: "Vless", Port: 1145, TransportProtocol: "tcp",
				}
				if source == "panel" {
					config.DisableLocalREALITYConfig = true
					node.EnableREALITY = true
					node.REALITYConfig = &api.REALITYConfig{
						Dest: "example.com:443", ServerNames: []string{"example.com"},
						PrivateKey: privateKey, ShortIds: []string{"01020304"}, MinClientVer: version,
					}
				} else {
					config.EnableREALITY = true
					config.REALITYConfigs = &REALITYConfig{
						Dest: "example.com:443", ServerNames: []string{"example.com"},
						PrivateKey: privateKey, ShortIds: []string{"01020304"}, MinClientVer: version,
					}
				}
				inbound, err := InboundBuilder(config, node, "test_reality")
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := inbound.ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				stream := receiver.(*proxyman.ReceiverConfig).StreamSettings
				if len(stream.SecuritySettings) != 1 {
					t.Fatalf("expected one REALITY configuration, got %d", len(stream.SecuritySettings))
				}
				security, err := stream.SecuritySettings[0].GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				r := security.(*reality.Config)
				want := []byte{1, 0, 0}
				if version != "" {
					want = []byte{26, 3, 27}
				}
				if !bytes.Equal(r.MinClientVer, want) {
					t.Fatalf("expected minimum client version %v, got %v", want, r.MinClientVer)
				}
			})
		}
	}
}

func TestBuildSS2022(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		method := "2022-blake3-aes-128-gcm"
		if keySize == 32 {
			method = "2022-blake3-aes-256-gcm"
		}
		t.Run(method, func(t *testing.T) {
			nodeInfo := &api.NodeInfo{
				NodeType: "Shadowsocks", CypherMethod: method,
				Port: 1145, TransportProtocol: "tcp",
				ServerKey: base64.StdEncoding.EncodeToString(make([]byte, keySize)),
			}
			inbound, err := InboundBuilder(&Config{}, nodeInfo, "test_ss2022")
			if err != nil {
				t.Fatal(err)
			}
			// Construct the core to exercise runtime key validation without opening ports.
			coreConfig, err := (&conf.Config{}).Build()
			if err != nil {
				t.Fatal(err)
			}
			coreConfig.Inbound = []*core.InboundHandlerConfig{inbound}
			server, err := core.New(coreConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
		})
	}
}

func TestBuildSS2022InvalidServerKey(t *testing.T) {
	for _, key := range []string{"", "invalid-key", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		nodeInfo := &api.NodeInfo{
			NodeType: "Shadowsocks", CypherMethod: "2022-blake3-aes-128-gcm",
			Port: 1145, TransportProtocol: "tcp", ServerKey: key,
		}
		_, err := InboundBuilder(&Config{}, nodeInfo, "test_ss2022")
		if err == nil || !strings.Contains(err.Error(), "server_key") || !strings.Contains(err.Error(), "16 key bytes") {
			t.Fatalf("expected server key validation error, got %v", err)
		}
	}
}

func TestBuildV2ray(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "ws",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "test.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildTrojan(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Trojan",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "trojan.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildSS(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Shadowsocks",
		CypherMethod:      "aes-128-gcm",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@me.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}
