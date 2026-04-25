package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

// NylonMobile is the gomobile-facing wrapper for the nylon mesh VPN engine.
// It manages the lifecycle of the nylon engine and provides status query methods.
//
// Usage from Swift:
//
//	let nylon = NylonmobileNewNylonMobile()
//	nylon.start(centralYAML, nodeYAML, tunFd)
//	nylon.stop()
type NylonMobile struct {
	mu      sync.Mutex
	running bool
	state   *state.State
}

type trafficStats struct {
	TxBytes uint64 `json:"tx_bytes"`
	RxBytes uint64 `json:"rx_bytes"`
}

// NewNylonMobile creates a new NylonMobile instance.
func NewNylonMobile() *NylonMobile {
	return &NylonMobile{}
}

func parseLogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Start launches the nylon engine in a background goroutine.
// centralYAML and nodeYAML are raw YAML config strings matching the
// state.CentralCfg and state.LocalCfg formats.
// tunFd is the file descriptor from NEPacketTunnelProvider (0 to create TUN internally).
// Returns when initialisation completes or on init error.
func (n *NylonMobile) Start(centralYAML, nodeYAML string, tunFd int32) error {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return errors.New("nylon is already running")
	}
	n.mu.Unlock()

	var localCfg state.LocalCfg
	if err := yaml.Unmarshal([]byte(nodeYAML), &localCfg); err != nil {
		return fmt.Errorf("failed to parse node config: %w", err)
	}

	var centralCfg state.CentralCfg
	if strings.TrimSpace(centralYAML) == "" {
		if localCfg.Dist == nil {
			return errors.New("central config is empty and node config has no dist config")
		}
		cfg, err := core.FetchConfig(localCfg.Dist.Url, localCfg.Dist.Key)
		if err != nil {
			return fmt.Errorf("failed to fetch central config from distribution: %w", err)
		}
		centralCfg = *cfg
	} else if err := yaml.Unmarshal([]byte(centralYAML), &centralCfg); err != nil {
		return fmt.Errorf("failed to parse central config: %w", err)
	}

	state.ExpandCentralConfig(&centralCfg)
	if err := state.CentralConfigValidator(&centralCfg); err != nil {
		return fmt.Errorf("invalid central config: %w", err)
	}
	if err := state.NodeConfigValidator(&localCfg); err != nil {
		return fmt.Errorf("invalid node config: %w", err)
	}

	// Critical for iOS: prevent exec.Command calls for ifconfig/route
	localCfg.NoNetConfigure = true
	if localCfg.InterfaceName == "" {
		if runtime.GOOS == "ios" || runtime.GOOS == "darwin" {
			localCfg.InterfaceName = "utun"
		} else {
			localCfg.InterfaceName = "nylon"
		}
	}

	// Inject TUN device via AuxConfig if fd is provided
	aux := map[string]any{"isMobile": true}
	if tunFd > 0 {
		// iOS owns NetworkExtension utun configuration. Passing mtu=0 avoids
		// SIOCSIFMTU, which is rejected for provider-managed utun interfaces.
		tdev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(tunFd), ""), 0)
		if err != nil {
			return fmt.Errorf("failed to create TUN from fd %d: %w", tunFd, err)
		}
		aux["tunDevice"] = tdev
	}

	initResult := make(chan error, 1)
	var st *state.State

	n.mu.Lock()
	n.running = true
	n.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("nylon engine panic: %v\n%s", r, debug.Stack())

				n.mu.Lock()
				n.running = false
				n.state = nil
				n.mu.Unlock()

				select {
				case initResult <- err:
				default:
				}
			}
		}()

		_, err := core.Start(centralCfg, localCfg, parseLogLevel(localCfg.LogLevel), "", aux, &st)
		// Start only returns when the engine stops or init fails.
		n.mu.Lock()
		n.running = false
		n.state = nil
		n.mu.Unlock()

		if err != nil {
			// Non-blocking send: if nobody is listening, drop it
			select {
			case initResult <- err:
			default:
			}
		}
	}()

	// Wait for either init error, the main loop start signal, or timeout.
	// core.Start blocks while the engine is running, so a fixed timeout here
	// would unnecessarily slow down iOS VPN connection establishment.
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-initResult:
			return err
		case <-ticker.C:
			if st != nil && st.Env != nil && st.Started.Load() {
				n.mu.Lock()
				n.state = st
				n.mu.Unlock()
				return nil
			}
		case <-timeout:
			n.mu.Lock()
			n.state = st
			n.mu.Unlock()
			return nil
		}
	}
}

// Stop shuts down the nylon engine gracefully.
func (n *NylonMobile) Stop() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.running || n.state == nil || n.state.Env == nil {
		return
	}
	n.state.Env.Cancel(context.Canceled)
	n.running = false
}

// IsRunning returns whether the nylon engine is currently running.
func (n *NylonMobile) IsRunning() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.running
}

// GetSystemRoutes returns computed system routes as a JSON array of CIDR strings.
// Called from Swift to configure NEPacketTunnelNetworkSettings.
func (n *NylonMobile) GetSystemRoutes() string {
	n.mu.Lock()
	st := n.state
	n.mu.Unlock()

	if st == nil || st.Env == nil {
		return "[]"
	}

	result := make(chan []string, 1)
	st.Env.Dispatch(func(s *state.State) error {
		router := core.Get[*core.NylonRouter](s)
		if router == nil {
			result <- []string{}
			return nil
		}
		sysRoutes := router.ComputeSysRouteTable()
		routes := make([]string, 0, len(sysRoutes))
		for _, p := range sysRoutes {
			routes = append(routes, p.String())
		}
		result <- routes
		return nil
	})

	select {
	case routes := <-result:
		data, _ := json.Marshal(routes)
		return string(data)
	case <-time.After(5 * time.Second):
		return "[]"
	}
}

// GetSelfAddresses returns the node's own mesh addresses as a JSON string array.
func (n *NylonMobile) GetSelfAddresses() string {
	n.mu.Lock()
	env := n.state.Env
	n.mu.Unlock()

	if env == nil {
		return "[]"
	}

	node := env.TryGetNode(env.LocalCfg.Id)
	if node == nil {
		return "[]"
	}

	addrs := make([]string, 0)
	for _, pfx := range node.Prefixes {
		addr := pfx.GetPrefix().Addr()
		if addr.IsValid() {
			addrs = append(addrs, addr.String())
		}
	}
	for _, addr := range node.Addresses {
		addrs = append(addrs, addr.String())
	}

	data, _ := json.Marshal(addrs)
	return string(data)
}

// GetTrafficStats returns aggregate WireGuard peer transfer counters.
func (n *NylonMobile) GetTrafficStats() string {
	n.mu.Lock()
	st := n.state
	n.mu.Unlock()

	if st == nil || st.Env == nil {
		data, _ := json.Marshal(trafficStats{})
		return string(data)
	}

	result := make(chan trafficStats, 1)
	st.Env.Dispatch(func(s *state.State) error {
		nylon := core.Get[*core.Nylon](s)
		if nylon == nil || nylon.Device == nil {
			result <- trafficStats{}
			return nil
		}

		uapi, err := nylon.Device.IpcGet()
		if err != nil {
			result <- trafficStats{}
			return nil
		}

		var stats trafficStats
		for _, line := range strings.Split(uapi, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			bytes, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "tx_bytes":
				stats.TxBytes += bytes
			case "rx_bytes":
				stats.RxBytes += bytes
			}
		}

		result <- stats
		return nil
	})

	select {
	case stats := <-result:
		data, _ := json.Marshal(stats)
		return string(data)
	case <-time.After(5 * time.Second):
		data, _ := json.Marshal(trafficStats{})
		return string(data)
	}
}
