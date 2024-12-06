package ppanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
)

type APIClient struct {
	client   *resty.Client
	APIHost  string
	ServerID int
	Secret   string
	Protocol string
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"server_id":  strconv.Itoa(apiConfig.NodeID),
		"protocol":   apiConfig.NodeType,
		"secret_key": apiConfig.Key,
	})
	return &APIClient{
		client:   client,
		APIHost:  apiConfig.APIHost,
		ServerID: apiConfig.NodeID,
		Secret:   apiConfig.Key,
		Protocol: apiConfig.NodeType,
	}
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.ServerID, Key: c.Secret, NodeType: c.Protocol}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

// assembleURL assemble the URL
func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

// GetNodeInfo get the node info
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	config := GetServerConfigResponse{}
	path := "/v1/server/config"
	resp, err := c.client.R().SetResult(&config).Get(path)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err)
	}
	if resp.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// parse Protocol
	switch config.Protocol {
	case "Shadowsocks":
		return c.parseShadowsocksConfig(config.Shadowsocks)
	case "Vless":
		return c.parseVlessConfig(config.Vless)
	case "Vmess":
		return c.parseVmessConfig(config.Vmess)
	case "Trojan":
		return c.parseTrojanConfig(config.Trojan)
	default:
		msg := fmt.Sprintf("invalid protocol: %v", config.Protocol)
		return nil, errors.New(msg)
	}
}

// parse shadowsocks config
func (c *APIClient) parseShadowsocksConfig(config *ShadowsocksProtocol) (*api.NodeInfo, error) {
	if config == nil {
		return nil, fmt.Errorf("shadowsocks config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}
	return &api.NodeInfo{
		NodeType:          "shadowsocks",
		TransportProtocol: "tcp",
		NodeID:            c.ServerID,
		Port:              uint32(config.Port),
		CypherMethod:      config.Method,
	}, nil
}

// parse vless config
func (c *APIClient) parseVlessConfig(config *VlessProtocol) (*api.NodeInfo, error) {
	var (
		host           string
		header         json.RawMessage
		transport      Transport
		securityConfig SecurityConfig
		enableTLS      bool
		enableReality  bool
		dest           string
	)
	if config == nil {
		return nil, fmt.Errorf("vmess config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}
	if config.Transport != "" {
		err := json.Unmarshal([]byte(config.Transport), &transport)
		if err != nil {
			return nil, fmt.Errorf("parse transport failed: %v", err.Error())
		}
	}
	if config.SecurityConfig != "" {
		err := json.Unmarshal([]byte(config.SecurityConfig), &securityConfig)
		if err != nil {
			return nil, fmt.Errorf("parse security config failed: %v", err.Error())
		}
	}
	if securityConfig.ServerAddress != "" {
		dest = securityConfig.ServerAddress
	} else {
		dest = securityConfig.ServerName
	}
	realityConfig := api.REALITYConfig{
		Dest:             dest + ":" + strconv.Itoa(int(securityConfig.ServerPort)),
		ProxyProtocolVer: 0,
		ServerNames: []string{
			securityConfig.ServerName,
		},
		PrivateKey: securityConfig.PrivateKey,
		ShortIds: []string{
			securityConfig.ShortId,
		},
	}
	switch config.Security {
	case "none":
		enableTLS = false
		enableReality = false

	case "tls":
		enableTLS = true
		enableReality = false

	case "reality":
		enableTLS = true
		enableReality = true
	}
	switch config.Network {
	case "tcp":
		if transport.Header != nil {
			if httpHeader, err := transport.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "websocket":
		if transport.Header != nil {
			if httpHeader, err := transport.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		} else {
			return nil, fmt.Errorf("invalid transport config: %v", transport)
		}
	case "httpupgrade", "splithttp":
		if transport.Headers != nil {
			if httpHeaders, err := transport.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if transport.Host != "" {
			host = transport.Host
		}
	}

	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "V2ray",
		Port:              uint32(config.Port),
		Host:              host,
		Path:              transport.Path,
		AlterID:           0,
		Header:            header,
		ServiceName:       transport.ServiceName,
		TransportProtocol: config.Network,
		EnableTLS:         enableTLS,
		EnableREALITY:     enableReality,
		REALITYConfig:     &realityConfig,
		VlessFlow:         config.XTLS,
	}, nil
}

// parse vmess config
func (c *APIClient) parseVmessConfig(config *VmessProtocol) (*api.NodeInfo, error) {
	var (
		host      string
		header    json.RawMessage
		transport Transport
	)
	if config == nil {
		return nil, fmt.Errorf("vmess config is nil,server id: %v，invalid response: %v", c.ServerID, config)
	}
	if config.Transport != "" {
		err := json.Unmarshal([]byte(config.Transport), &transport)
		if err != nil {
			return nil, fmt.Errorf("parse transport failed: %v", err.Error())
		}
	}
	switch config.Network {
	case "tcp":
		if transport.Header != nil {
			if httpHeader, err := transport.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "ws":
		if transport.Header != nil {
			if httpHeader, err := transport.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		} else {
			return nil, fmt.Errorf("invalid transport config: %v", transport)
		}
	case "httpupgrade", "splithttp":
		if transport.Headers != nil {
			if httpHeaders, err := transport.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if transport.Host != "" {
			host = transport.Host
		}
	}

	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "V2ray",
		Port:              uint32(config.Port),
		Host:              host,
		Path:              transport.Path,
		AlterID:           0,
		Header:            header,
		ServiceName:       transport.ServiceName,
		EnableTLS:         *config.EnableTLS,
		TransportProtocol: config.Network,
	}, nil
}

// parse trojan config
func (c *APIClient) parseTrojanConfig(config *TrojanProtocol) (*api.NodeInfo, error) {
	return &api.NodeInfo{
		NodeID:            c.ServerID,
		NodeType:          "Trojan",
		Port:              uint32(config.Port),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              config.Host,
		ServiceName:       config.Host,
	}, nil
}

func (c *APIClient) GetUserList() (userList *[]api.UserInfo, err error) {
	result := GetServerUserListResponse{}
	path := "/v1/server/user"
	resp, err := c.client.R().SetResult(&result).Get(path)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	if resp.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	users := make([]api.UserInfo, 0)
	for _, user := range result.Users {
		u := api.UserInfo{
			UID:         int(user.Id),
			UUID:        user.UUID,
			SpeedLimit:  uint64(user.SpeedLimit * 1000000 / 8),
			DeviceLimit: int(user.DeviceLimit),
			Email:       user.UUID + "@ppanel.dev",
		}
		if c.Protocol == "Shadowsocks" {
			u.Passwd = user.UUID
		}
		users = append(users, u)
	}
	return &users, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := "/v1/server/status"
	status := ServerPushStatusRequest{
		Cpu:       nodeStatus.CPU,
		Mem:       nodeStatus.Mem,
		Disk:      nodeStatus.Disk,
		UpdatedAt: int64(nodeStatus.Uptime),
	}
	if _, err = c.client.R().SetBody(status).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUser *[]api.OnlineUser) (err error) {
	return nil
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) (err error) {
	path := "/v1/server/push"
	traffic := make([]UserTraffic, 0)
	for _, t := range *userTraffic {
		traffic = append(traffic, UserTraffic{
			UID:      int64(t.UID),
			Upload:   t.Upload,
			Download: t.Download,
		})
	}
	req := ServerPushUserTrafficRequest{
		Traffic: traffic,
	}
	if _, err = c.client.R().SetBody(req).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}

func (c *APIClient) GetNodeRule() (ruleList *[]api.DetectRule, err error) {
	list := make([]api.DetectRule, 0)
	return &list, nil
}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}
