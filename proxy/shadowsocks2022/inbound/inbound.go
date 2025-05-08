package inbound

import (
	"context" // Import context package
	"errors"  // Standard library errors
	"io"      // For io.ReadFull
	gonet "net" // Standard library net for ErrClosed

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayErrors "github.com/v2fly/v2ray-core/v5/common/errors" // v2ray errors with alias
	"github.com/v2fly/v2ray-core/v5/common/log"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net" // v2ray net with alias
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks2022"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*shadowsocks2022.ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*shadowsocks2022.ServerConfig))
	}))
}

type Inbound struct {
	networks []v2rayNet.Network // Use alias
	service  shadowsocks2022.Shadowsocks2022Service
	email    string
	level    uint32
	tag      string // Added field to potentially store the tag later
}

// Start implements common.Runnable.
func (i *Inbound) Start() error {
	// TODO: Add any necessary startup logic for the inbound handler if needed.
	return nil
}

// Tag implements features/inbound.Handler.
func (i *Inbound) Tag() string {
	// TODO: This should ideally return the actual tag assigned by the config manager.
	// The factory function currently doesn't receive the tag.
	return i.tag // Return the stored tag, might be empty initially.
}

// GetRandomInboundProxy implements features/inbound.Handler. Deprecated.
func (i *Inbound) GetRandomInboundProxy() (interface{}, v2rayNet.Port, int) {
	return nil, 0, 0
}

func (i *Inbound) Process(ctx context.Context, network v2rayNet.Network, connection internet.Connection, dispatcher routing.Dispatcher) error { // Use alias
	sess := session.InboundFromContext(ctx)
	if sess == nil {
		sess = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, sess)
	}
	sess.Gateway = v2rayNet.TCPDestination(v2rayNet.IPAddress(gonet.IP{127, 0, 0, 1}), 0) // Use alias

	sess.User = &protocol.MemoryUser{
		Email: i.email,
		Level: i.level,
	}

	var source v2rayNet.Destination // Use alias
	if remoteAddr := connection.RemoteAddr(); remoteAddr != nil {
		source = v2rayNet.DestinationFromAddr(remoteAddr) // Use alias
	} else {
		source = v2rayNet.TCPDestination(v2rayNet.IPAddress(gonet.IP{0, 0, 0, 0}), 0) // Use alias
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Failed to get remote address for connection", // Corrected Message to Content
		})
	}
	sess.Source = source

	return i.service.ProcessConnection(ctx, connection, network, source, dispatcher)
}

func (i *Inbound) Close() error {
	return nil
}

func (i *Inbound) HandleTCPConnection(ctx context.Context, conn internet.Connection, source v2rayNet.Destination, destination v2rayNet.Destination, dispatcher routing.Dispatcher) error { // Use alias
	sess := session.InboundFromContext(ctx)
	if sess == nil {
		sess = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, sess)
	}
	sess.User = &protocol.MemoryUser{
		Email: i.email,
		Level: i.level,
	}
	sess.Source = source

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
		Email:  i.email,
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "tunnelling request to tcp: " + destination.String(),
	})

	// The following logic (salt, key derivation, AEAD creation, header read)
	// should be handled by the service implementation (protocol.go)
	// before calling this handler. This handler receives the wrappedConn.

	// Assume conn is already the ss2022WrappedConnection passed from protocol.go
	wrappedConn, ok := conn.(*shadowsocks2022.Ss2022WrappedConnection)
	if !ok {
		// This should ideally not happen if protocol.go calls correctly
		return v2rayErrors.New("HandleTCPConnection expects *shadowsocks2022.Ss2022WrappedConnection")
	}

	link, err := dispatcher.Dispatch(ctx, destination) // Use the destination passed in
	if err != nil {
		i.service.NewError(ctx, v2rayErrors.New("failed to dispatch TCP connection").Base(err))
		return err
	}

	request := link.Reader
	response := link.Writer

	requestDone := make(chan error, 1)
	responseDone := make(chan error, 1)

	// Copy data
	go func() {
		err := buf.Copy(request, wrappedConn)
		requestDone <- err
	}()

	go func() {
		err := buf.Copy(wrappedConn, response)
		responseDone <- err
	}()

	// Wait for copy to finish
	select {
	case err1 := <-requestDone:
		err2 := <-responseDone
		if err1 != nil {
			i.service.NewError(ctx, v2rayErrors.New("TCP copy request failed").Base(err1))
			return err1
		}
		if err2 != nil {
			i.service.NewError(ctx, v2rayErrors.New("TCP copy response failed").Base(err2))
			return err2
		}
	case err2 := <-responseDone:
		err1 := <-requestDone
		if err1 != nil {
			i.service.NewError(ctx, v2rayErrors.New("TCP copy request failed").Base(err1))
			return err1
		}
		if err2 != nil {
			i.service.NewError(ctx, v2rayErrors.New("TCP copy response failed").Base(err2))
			return err2
		}
	}

	return nil
}

func (i *Inbound) HandleUDPPacket(ctx context.Context, packet *buf.Buffer, source v2rayNet.Destination, destination v2rayNet.Destination, dispatcher routing.Dispatcher) error { // Use alias
	sess := session.InboundFromContext(ctx)
	if sess == nil {
		sess = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, sess)
	}
	sess.User = &protocol.MemoryUser{
		Email: i.email,
		Level: i.level,
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
		Email:  i.email,
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "tunnelling request to udp: " + destination.String(), // Corrected Message to Content
	})

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		packet.Release()
		return v2rayErrors.New("failed to dispatch UDP packet").Base(err)
	}

	var mb buf.MultiBuffer
	mb = append(mb, packet) // Append packet to MultiBuffer
	err = link.Writer.WriteMultiBuffer(mb)
	if err != nil {
		buf.ReleaseMulti(mb) // Release MultiBuffer
		return v2rayErrors.New("failed to write decrypted UDP packet to dispatched link").Base(err)
	}

	return nil
}

func (i *Inbound) HandleError(ctx context.Context, err error) {
	// Check for context canceled or connection closed errors
	if errors.Is(err, context.Canceled) || errors.Is(err, gonet.ErrClosed) || errors.Is(err, io.EOF) {
		return
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Warning,
		Content:  err.Error(),
	})
}

func NewServer(ctx context.Context, config *shadowsocks2022.ServerConfig) (*Inbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []v2rayNet.Network{ // Use alias
			v2rayNet.Network_TCP,
			v2rayNet.Network_UDP,
		}
	}

	var supportedNetworks []v2rayNet.Network // Use alias
	for _, n := range networks {
		if n == v2rayNet.Network_TCP || n == v2rayNet.Network_UDP { // Use alias
			supportedNetworks = append(supportedNetworks, n)
		} else {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Warning,
				Content:  "Shadowsocks 2022 inbound does not support network " + n.String(),
			})
		}
	}
	if len(supportedNetworks) == 0 {
		return nil, v2rayErrors.New("no supported network specified for shadowsocks 2022 inbound")
	}

	inbound := &Inbound{
		networks: supportedNetworks,
		email:    config.Email,
		level:    config.Level,
	}

	// Pass the inbound handler to the service constructor
	// Assuming NewShadowsocks2022ServiceWithPassword and Shadowsocks2022Service are in the parent shadowsocks2022 package
	service, err := shadowsocks2022.NewShadowsocks2022ServiceWithPassword(config.Method, config.Key, 500, inbound, nil)
	if err != nil {
		return nil, v2rayErrors.New("create shadowsocks2022 service").Base(err)
	}
	inbound.service = service

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Shadowsocks 2022 inbound created",
	})

	return inbound, nil
}

func (i *Inbound) Network() []v2rayNet.Network { // Changed return type to []v2rayNet.Network
	networksCopy := make([]v2rayNet.Network, len(i.networks))
	copy(networksCopy, i.networks)
	return networksCopy
}

// Placeholder for ss2022WrappedConnection if it's not imported correctly.
// This might be defined in proxy/shadowsocks2022/protocol.go or similar.
// type ss2022WrappedConnection struct {
// 	io.ReadWriteCloser
// }
