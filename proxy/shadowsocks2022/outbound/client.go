package outbound

import (
	"context"
	gonet "net"

	"sync"
	"time"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	commonErrors "github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/environment"
	"github.com/v2fly/v2ray-core/v5/common/environment/envctx"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v5/common/retry"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"crypto/sha256" 
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/crypto"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/encoding"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022/shared"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/udp"
)

type Client struct {
	config *shadowsocks2022.ClientConfig
	ctx    context.Context
}

const UDPConnectionState = "UDPConnectionState"

type ClientUDPConnState struct {
	session  *ClientUDPSession
	initOnce *sync.Once
}

func (c *ClientUDPConnState) GetOrCreateSession(create func() (*ClientUDPSession, error)) (*ClientUDPSession, error) {
	var errOuter error
	c.initOnce.Do(func() {
		sessionState, err := create()
		if err != nil {
			errOuter = commonErrors.New("failed to create UDP session").Base(err)
			return
		}
		c.session = sessionState
	})
	if errOuter != nil {
		return nil, commonErrors.New("failed to initialize UDP State").Base(errOuter)
	}
	return c.session, nil
}

func NewClientUDPConnState() (*ClientUDPConnState, error) {
	return &ClientUDPConnState{initOnce: &sync.Once{}}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return commonErrors.New("target not specified")
	}
	destination := outbound.Target
	network := destination.Network

	var method shared.Method // Use shared.Method
	switch c.config.Method {
	case "2022-blake3-aes-128-gcm":
		method = crypto.NewAES128GCMMethod()
	case "2022-blake3-aes-256-gcm":
		method = crypto.NewAES256GCMMethod()
	case "2022-blake3-chacha20-poly1305":
		method = crypto.NewChaCha20Poly1305Method()
	default:
		return commonErrors.New("unknown or unsupported method: ", c.config.Method)
	}

	effectivePsk := c.config.Psk 

	methodInfo, ok := shadowsocks2022.MethodMap[c.config.Method]
	if !ok {
		return commonErrors.New("method info not found for: ", c.config.Method)
	}

	if len(effectivePsk) != methodInfo.KeySize {
		if len(effectivePsk) < methodInfo.KeySize {
			return commonErrors.New("PSK is shorter than required key size: ", len(effectivePsk), " < ", methodInfo.KeySize, ". This is considered an error (ErrBadKey in sing-shadowsocks).")
		}

		commonErrors.New("PSK length mismatch for client: expected ", methodInfo.KeySize, " got ", len(effectivePsk), ". Deriving key with SHA256.").AtWarning().WriteToLog(session.ExportIDToError(ctx))
		hashedPsk := sha256.Sum256(effectivePsk)
		effectivePsk = hashedPsk[:methodInfo.KeySize]
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, time.Minute)

	decodedIpsk := c.config.Ipsk

	if packetConn, err := packetaddr.ToPacketAddrConn(link, destination); err == nil {
		udpSession, err := c.getUDPSession(c.ctx, network, dialer, method, effectivePsk, decodedIpsk)
		if err != nil {
			return commonErrors.New("failed to get UDP udpSession").Base(err)
		}
		requestDone := func() error {
			return udp.CopyPacketConn(udpSession, packetConn, udp.UpdateActivity(timer))
		}
		responseDone := func() error {
			return udp.CopyPacketConn(packetConn, udpSession, udp.UpdateActivity(timer))
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return commonErrors.New("connection ends").Base(err)
		}
		return nil
	}

	if network == net.Network_TCP {
		var conn internet.Connection
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			dest := net.TCPDestination(c.config.Address.AsAddress(), net.Port(c.config.Port))
			dest.Network = network
			rawConn, err := dialer.Dial(ctx, dest)
			if err != nil {
				return err
			}
			conn = rawConn

			return nil
		})
		if err != nil {
			return commonErrors.New("failed to find an available destination").AtWarning().Base(err)
		}
		commonErrors.New("tunneling request to ", destination, " via ", network, ":", net.TCPDestination(c.config.Address.AsAddress(), net.Port(c.config.Port)).NetAddr()).WriteToLog(session.ExportIDToError(ctx))
		defer conn.Close()

		request := &encoding.TCPRequest{
			// Initialize the method field directly, as it exists in the encoding.TCPRequest struct
			Method:        method,
		}
		TCPRequestBuffer := buf.New()
		defer TCPRequestBuffer.Release()
		// Pass effectivePsk and decodedIpsk to EncodeTCPRequestHeader
		err = request.EncodeTCPRequestHeader(effectivePsk, decodedIpsk, destination.Address,
			int(destination.Port), nil, TCPRequestBuffer)
		if err != nil {
			return commonErrors.New("failed to encode TCP request header").Base(err)
		}
		_, err = conn.Write(TCPRequestBuffer.Bytes())
		if err != nil {
			return commonErrors.New("failed to write TCP request header").Base(err)
		}
		requestDone := func() error {
			encodedWriter := request.CreateClientC2SWriter(conn)
			return buf.Copy(link.Reader, encodedWriter, buf.UpdateActivity(timer))
		}
		responseDone := func() error {
			err = request.DecodeTCPResponseHeader(effectivePsk, conn)
			if err != nil {
				return commonErrors.New("failed to decode TCP response header").Base(err)
			}
			if err = request.CheckC2SConnectionConstraint(); err != nil {
				return commonErrors.New("C2S connection constraint violation").Base(err)
			}
			initialPayload := buf.NewWithSize(65535)
			encodedReader, err := request.CreateClientS2CReader(conn, initialPayload)
			if err != nil {
				return commonErrors.New("failed to create client S2C reader").Base(err)
			}
			err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{initialPayload})
			if err != nil {
				return commonErrors.New("failed to write initial payload").Base(err)
			}
			return buf.Copy(encodedReader, link.Writer, buf.UpdateActivity(timer))
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return commonErrors.New("connection ends").Base(err)
		}
		return nil
	} else {
	// Pass effectivePsk and decodedIpsk to getUDPSession for non-packetaddr UDP
	udpSession, err := c.getUDPSession(c.ctx, network, dialer, method, effectivePsk, decodedIpsk)
	if err != nil {
		return commonErrors.New("failed to get UDP udpSession").Base(err)
	}
	monoDestUDPConn := udp.NewMonoDestUDPConn(udpSession, &gonet.UDPAddr{IP: destination.Address.IP(), Port: int(destination.Port)})
	requestDone := func() error {
		return buf.Copy(link.Reader, monoDestUDPConn, buf.UpdateActivity(timer))
		}
		responseDone := func() error {
			return buf.Copy(monoDestUDPConn, link.Writer, buf.UpdateActivity(timer))
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return commonErrors.New("connection ends").Base(err)
		}
		return nil
	}
}

func (c *Client) getUDPSession(ctx context.Context, network net.Network, dialer internet.Dialer, method shared.Method, effectivePSK []byte, decodedIPSK [][]byte) (internet.AbstractPacketConn, error) {
	storage := envctx.EnvironmentFromContext(ctx).(environment.ProxyEnvironment).TransientStorage()
	clientUDPStateIfce, err := storage.Get(ctx, UDPConnectionState)
	if err != nil {
		return nil, commonErrors.New("failed to get UDP connection state").Base(err)
	}
	clientUDPState, ok := clientUDPStateIfce.(*ClientUDPConnState)
	if !ok {
		return nil, commonErrors.New("failed to cast UDP connection state")
	}

	sessionState, err := clientUDPState.GetOrCreateSession(func() (*ClientUDPSession, error) {
		var conn internet.Connection
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			dest := net.TCPDestination(c.config.Address.AsAddress(), net.Port(c.config.Port))
			dest.Network = network
			rawConn, err := dialer.Dial(ctx, dest)
			if err != nil {
				return err
			}
			conn = rawConn

			return nil
		})
		if err != nil {
			return nil, commonErrors.New("failed to find an available destination").AtWarning().Base(err)
		}
		commonErrors.New("creating udp session to ", network, ":", c.config.Address).WriteToLog(session.ExportIDToError(ctx))
		// Use passed-in effectivePSK and decodedIPSK
		packetProcessor, err := method.GetUDPClientProcessor(decodedIPSK, effectivePSK)
		if err != nil {
			return nil, commonErrors.New("failed to create UDP client packet processor").Base(err)
		}
		return NewClientUDPSession(ctx, conn, packetProcessor), nil
	})
	if err != nil {
		return nil, commonErrors.New("failed to create UDP session").Base(err)
	}
	sessionConn, err := sessionState.NewSessionConn()
	if err != nil {
		return nil, commonErrors.New("failed to create UDP session connection").Base(err)
	}
	return sessionConn, nil
}

func NewClient(ctx context.Context, config *shadowsocks2022.ClientConfig) (*Client, error) {
	storage := envctx.EnvironmentFromContext(ctx).(environment.ProxyEnvironment).TransientStorage()

	udpState, err := NewClientUDPConnState()
	if err != nil {
		return nil, commonErrors.New("failed to create UDP connection state").Base(err)
	}
	storage.Put(ctx, UDPConnectionState, udpState)

	return &Client{
		config: config,
		ctx:    ctx,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*shadowsocks2022.ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		clientConfig, ok := config.(*shadowsocks2022.ClientConfig)
		if !ok {
			return nil, commonErrors.New("not a ClientConfig")
		}
		return NewClient(ctx, clientConfig)
	}))
}
