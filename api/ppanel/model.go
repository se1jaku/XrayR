package ppanel

import "encoding/json"

type (
	ServerCommon struct {
		Protocol  string `form:"protocol" json:"protocol"`
		ServerId  int64  `form:"server_id" json:"server_id"`
		SecretKey string `form:"secret_key" json:"secret_key"`
	}

	ServerBasic struct {
		PushInterval int64 `json:"push_interval"`
		PullInterval int64 `json:"pull_interval"`
	}

	GetServerConfigResponse struct {
		Basic       ServerBasic          `json:"basic"`
		Protocol    string               `json:"protocol"`
		Vmess       *VmessProtocol       `json:"vmess,omitempty"`
		Vless       *VlessProtocol       `json:"vless,omitempty"`
		Trojan      *TrojanProtocol      `json:"trojan,omitempty"`
		Shadowsocks *ShadowsocksProtocol `json:"shadowsocks,omitempty"`
	}

	VmessProtocol struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		EnableTLS *bool  `json:"enable_tls"`
		TLSConfig string `json:"tls_config"`
		Network   string `json:"network"`
		Transport string `json:"transport"`
	}
	VlessProtocol struct {
		Host           string `json:"host"`
		Port           int    `json:"port"`
		Network        string `json:"network"`
		Transport      string `json:"transport"`
		Security       string `json:"security"`
		SecurityConfig string `json:"security_config"`
		XTLS           string `json:"xtls"`
	}
	TrojanProtocol struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		EnableTLS *bool  `json:"enable_tls"`
		TLSConfig string `json:"tls_config"`
		Network   string `json:"network"`
		Transport string `json:"transport"`
	}

	ShadowsocksProtocol struct {
		Port   int    `json:"port"`
		Method string `json:"method"`
	}

	Transport struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Key         string           `json:"key"`
		Seed        string           `json:"seed"`
		Header      *json.RawMessage `json:"header"`
		Headers     *json.RawMessage `json:"headers"`
		Response    *json.RawMessage `json:"response"`
		Security    string           `json:"security"`
		ServiceName string           `json:"serviceName"`
	}
	SecurityConfig struct {
		ServerAddress string `json:"server_address"`
		ServerName    string `json:"server_name"`
		ServerPort    uint32 `json:"server_port"`
		Fingerprint   string `json:"fingerprint"`
		PrivateKey    string `json:"private_key"`
		PublicKey     string `json:"public_key"`
		ShortId       string `json:"short_id"`
		AllowInsecure bool   `json:"allow_insecure"`
	}

	GetServerUserListResponse struct {
		Users []ServerUser `json:"users"`
	}
	ServerUser struct {
		Id          int64  `json:"id"`
		UUID        string `json:"uuid"`
		SpeedLimit  int64  `json:"speed_limit"`
		DeviceLimit int64  `json:"device_limit"`
	}
	ServerPushStatusRequest struct {
		Cpu       float64 `json:"cpu"`
		Mem       float64 `json:"mem"`
		Disk      float64 `json:"disk"`
		UpdatedAt int64   `json:"updated_at"`
	}
	ServerPushUserTrafficRequest struct {
		ServerCommon
		Traffic []UserTraffic `json:"traffic"`
	}
	UserTraffic struct {
		UID      int64 `json:"uid"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}
)
