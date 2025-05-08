package v4

import (
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/v2fly/v2ray-core/v5/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks"
	ss2022 "github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	_ "github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/inbound"  // Ensure SS2022 server config is registered
	_ "github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/outbound" // Ensure SS2022 client config is registered
)

type ShadowsocksServerConfig struct {
	Cipher         string                 `json:"method"`
	Password       string                 `json:"password"`
	UDP            bool                   `json:"udp"`
	Level          byte                   `json:"level"`
	Email          string                 `json:"email"`
	NetworkList    *cfgcommon.NetworkList `json:"network"`
	IVCheck        bool                   `json:"ivCheck"`    // Not used by SS2022
	PacketEncoding string                 `json:"packetEncoding"` // Not used by SS2022
	Psk            string                 `json:"psk"`        // Added field for SS2022 PSK
}

func (v *ShadowsocksServerConfig) Build() (proto.Message, error) {
	// Handle Shadowsocks 2022 Server Config
	if strings.HasPrefix(v.Cipher, "2022-") {
		if v.Psk == "" {
			return nil, newError("Shadowsocks 2022 PSK (key) is not specified for inbound.")
		}
		config := new(ss2022.ServerConfig)
		config.Method = v.Cipher
		config.Key = v.Psk // Map JSON 'psk' to proto 'Key'
		config.Network = v.NetworkList.Build()
		config.Email = v.Email
		config.Level = uint32(v.Level)
		// Note: UDP is implicitly handled by SS2022 protocol itself, no UdpEnabled field.
		// Note: IVCheck and PacketEncoding are not applicable to SS2022.
		return config, nil
	}

	// --- Original Shadowsocks Server Config Logic ---
	config := new(shadowsocks.ServerConfig)
	config.UdpEnabled = v.UDP
	config.Network = v.NetworkList.Build()

	// Build original shadowsocks.Account
	// Password validation should be handled by the specific proxy implementation if needed.
	account := &shadowsocks.Account{
		Password: v.Password,
		IvCheck:  v.IVCheck,
	}
	account.CipherType = shadowsocks.CipherFromString(v.Cipher)
	if account.CipherType == shadowsocks.CipherType_UNKNOWN {
		return nil, newError("unknown cipher method: ", v.Cipher)
	}

	config.User = &protocol.User{
		Email:   v.Email,
		Level:   uint32(v.Level),
		Account: serial.ToTypedMessage(account),
	}

	switch v.PacketEncoding {
	case "Packet":
		config.PacketEncoding = packetaddr.PacketAddrType_Packet
	case "", "None":
		config.PacketEncoding = packetaddr.PacketAddrType_None
	}

	return config, nil
}

type ShadowsocksServerTarget struct {
	Address  *cfgcommon.Address `json:"address"`
	Port     uint16             `json:"port"`
	Cipher   string             `json:"method"`
	Password string             `json:"password"`
	Email    string             `json:"email"`
	Ota      bool               `json:"ota"` // Note: Ota is not used in SS2022
	Level    byte               `json:"level"`
	IVCheck  bool               `json:"ivCheck"`
	Psk      string             `json:"psk"` // Added field for SS2022 PSK
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	if len(v.Servers) == 0 {
		return nil, newError("0 Shadowsocks server configured.")
	}

	// Handle Shadowsocks 2022 specifically if it's the only server
	if len(v.Servers) == 1 {
		server := v.Servers[0]
		if strings.HasPrefix(server.Cipher, "2022-") {
			if server.Address == nil {
				return nil, newError("Shadowsocks 2022 server address is not set.")
			}
			if server.Port == 0 {
				return nil, newError("Invalid Shadowsocks 2022 port.")
			}
			if server.Psk == "" { // Check Psk field for SS2022
				return nil, newError("Shadowsocks 2022 PSK is not specified.")
			}

			// Build SS2022 ClientConfig
			config := new(ss2022.ClientConfig)
			config.Address = server.Address.Build()
			config.Port = uint32(server.Port)
			config.Method = server.Cipher
			config.Psk = []byte(server.Psk) // Convert Psk string to bytes
			// config.Ipsk = ... // TODO: How to configure IPSK in JSON? Assume empty for now.
			return config, nil
		}
	}

	// --- Original Shadowsocks logic for multiple servers or non-SS2022 single server ---
	config := new(shadowsocks.ClientConfig)
	serverSpecs := make([]*protocol.ServerEndpoint, len(v.Servers))

	for idx, server := range v.Servers {
		// Explicitly disallow SS2022 in multi-server config
		if strings.HasPrefix(server.Cipher, "2022-") {
			return nil, newError("Shadowsocks 2022 does not support multiple servers in a single outbound.")
		}

		if server.Address == nil {
			return nil, newError("Shadowsocks server address is not set.")
		}
		if server.Port == 0 {
			return nil, newError("Invalid Shadowsocks port.")
		}
		// Check Password only for non-SS2022
		if server.Password == "" {
			return nil, newError("Shadowsocks password is not specified.")
		}

		// Build original shadowsocks.Account
		account := &shadowsocks.Account{
			Password: server.Password,
		}
		account.CipherType = shadowsocks.CipherFromString(server.Cipher)
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, newError("unknown cipher method: ", server.Cipher)
		}
		account.IvCheck = server.IVCheck

		ss := &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: []*protocol.User{
				{
					Level:   uint32(server.Level),
					Email:   server.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = ss
	}

	config.Server = serverSpecs

	return config, nil
}
