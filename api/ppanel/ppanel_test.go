package ppanel

import (
	"github.com/XrayR-project/XrayR/api"
	"testing"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://localhost:8080",
		Key:      "12345678",
		NodeID:   3,
		NodeType: "Vless",
	}
	client := New(apiConfig)
	return client
}

func TestGetV2rayNodeInfo(t *testing.T) {
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo.REALITYConfig)
}
