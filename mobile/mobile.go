package mobile

import (
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
	nylon   *core.Nylon
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
		cfg, err := core.FetchConfig(localCfg.Dist.Url, localCfg.Dist.Key, state.DefaultRouterTunables().MaxConfigSize)
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
	if err := state.NodeConfigValidator(&centralCfg, &localCfg); err != nil {
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

	n.mu.Lock()
	n.running = true
	n.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("nylon engine panic: %v\n%s", r, debug.Stack())

				n.mu.Lock()
				n.running = false
				n.nylon = nil
				n.mu.Unlock()

				select {
				case initResult <- err:
				default:
				}
			}
		}()

		engine, err := core.NewNylon(
			centralCfg,
			localCfg,
			parseLogLevel(localCfg.LogLevel),
			"",
			aux,
			state.DefaultNylonOptions(),
			nil,
		)
		if err == nil {
			n.mu.Lock()
			n.nylon = engine
			n.mu.Unlock()
			select {
			case initResult <- nil:
			default:
			}
			err = engine.Start()
		}
		n.mu.Lock()
		n.running = false
		n.nylon = nil
		n.mu.Unlock()

		if err != nil {
			// Non-blocking send: if nobody is listening, drop it
			select {
			case initResult <- err:
			default:
			}
		}
	}()

	// Wait for initialization, not for the engine main loop to exit.
	timeout := time.After(10 * time.Second)
	for {
		select {
		case err := <-initResult:
			return err
		case <-timeout:
			return errors.New("timed out initializing nylon engine")
		}
	}
}

// Stop shuts down the nylon engine gracefully.
func (n *NylonMobile) Stop() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.running || n.nylon == nil {
		return
	}
	n.nylon.Stop()
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
	engine := n.nylon
	n.mu.Unlock()

	if engine == nil {
		return "[]"
	}

	result := make(chan []string, 1)
	engine.Dispatch(func() error {
		sysRoutes := engine.ComputeSysRouteTable()
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
	engine := n.nylon
	n.mu.Unlock()

	if engine == nil {
		return "[]"
	}

	node := engine.TryGetNode(engine.LocalCfg.Id)
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
	engine := n.nylon
	n.mu.Unlock()

	if engine == nil {
		data, _ := json.Marshal(trafficStats{})
		return string(data)
	}

	result := make(chan trafficStats, 1)
	engine.Dispatch(func() error {
		if engine.Device == nil {
			result <- trafficStats{}
			return nil
		}

		uapi, err := engine.Device.IpcGet()
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
