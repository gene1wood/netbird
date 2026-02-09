package peer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

const (
	defaultWgKeepAlive = 25 * time.Second
	fallbackDelay      = 5 * time.Second
)

type EndpointUpdater struct {
	log       *logrus.Entry
	wgConfig  WgConfig
	initiator bool

	// mu protects cancelFunc
	mu         sync.Mutex
	cancelFunc func()
	updateWg   sync.WaitGroup
}

func NewEndpointUpdater(log *logrus.Entry, wgConfig WgConfig, initiator bool) *EndpointUpdater {
	return &EndpointUpdater{
		log:       log,
		wgConfig:  wgConfig,
		initiator: initiator,
	}
}

// ConfigureWGEndpoint sets up the WireGuard endpoint configuration.
// The initiator immediately configures the endpoint, while the non-initiator
// waits for a fallback period before configuring to avoid handshake congestion.
//
// If wgProxy is non-nil, Work() is called at the correct time relative to the
// WireGuard peer update: before for the initiator (so the proxy is ready to
// process the immediate handshake) and after for the non-initiator.
func (e *EndpointUpdater) ConfigureWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key, wgProxy wgproxy.Proxy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.initiator {
		e.log.Debugf("configure up WireGuard as initiator")
		return e.configureAsInitiator(addr, presharedKey, wgProxy)
	}

	e.log.Debugf("configure up WireGuard as responder")
	return e.configureAsResponder(addr, presharedKey, wgProxy)
}

func (e *EndpointUpdater) SwitchWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key, wgProxy wgproxy.Proxy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	// Makes no sense to distinguish initiator and responder because the roaming feature in WG will overwrite the endpoint
	if wgProxy != nil {
		wgProxy.Work()
	}

	return e.updateWireGuardPeer(addr, presharedKey)
}

func (e *EndpointUpdater) RemoveWgPeer() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.waitForCloseTheDelayedUpdate()
	return e.wgConfig.WgInterface.RemovePeer(e.wgConfig.RemoteKey)
}

func (e *EndpointUpdater) configureAsInitiator(addr *net.UDPAddr, presharedKey *wgtypes.Key, wgProxy wgproxy.Proxy) error {
	if wgProxy != nil {
		wgProxy.Work()
	}

	if err := e.updateWireGuardPeer(addr, presharedKey); err != nil {
		return err
	}

	wgConfigWorkaround()
	return nil
}

func (e *EndpointUpdater) configureAsResponder(addr *net.UDPAddr, presharedKey *wgtypes.Key, wgProxy wgproxy.Proxy) error {
	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	var ctx context.Context
	ctx, e.cancelFunc = context.WithCancel(context.Background())
	e.updateWg.Add(1)
	go e.scheduleDelayedUpdate(ctx, addr, presharedKey)

	e.log.Debugf("configure up WireGuard and wait for handshake")
	if err := e.updateWireGuardPeer(nil, presharedKey); err != nil {
		e.waitForCloseTheDelayedUpdate()
		return err
	}
	wgConfigWorkaround()

	if wgProxy != nil {
		wgProxy.Work()
	}
	return nil
}

func (e *EndpointUpdater) waitForCloseTheDelayedUpdate() {
	if e.cancelFunc == nil {
		return
	}

	e.cancelFunc()
	e.cancelFunc = nil
	e.updateWg.Wait()
}

// scheduleDelayedUpdate waits for the fallback period before updating the endpoint
func (e *EndpointUpdater) scheduleDelayedUpdate(ctx context.Context, addr *net.UDPAddr, presharedKey *wgtypes.Key) {
	defer e.updateWg.Done()
	t := time.NewTimer(fallbackDelay)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return
	case <-t.C:
		if err := e.updateWireGuardPeer(addr, presharedKey); err != nil {
			e.log.Errorf("failed to update WireGuard peer, address: %s, error: %v", addr, err)
		}
	}
}

func (e *EndpointUpdater) updateWireGuardPeer(endpoint *net.UDPAddr, presharedKey *wgtypes.Key) error {
	return e.wgConfig.WgInterface.UpdatePeer(
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		endpoint,
		presharedKey,
	)
}

// wgConfigWorkaround is a workaround for the issue with WireGuard configuration update
// When update a peer configuration in near to each other time, the second update can be ignored by WireGuard
func wgConfigWorkaround() {
	time.Sleep(100 * time.Millisecond)
}
