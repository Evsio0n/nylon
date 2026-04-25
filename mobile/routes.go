package mobile

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/state"
)

type MobileTunnelRoutes struct {
	IncludedRoutes []string `json:"included_routes"`
	ExcludedRoutes []string `json:"excluded_routes"`
	IPv6Enabled    bool     `json:"ipv6_enabled"`
	ExitNode       string   `json:"exit_node,omitempty"`
}

// GetTunnelRoutes returns NetworkExtension-ready IPv4 route policy for iOS.
func (n *NylonMobile) GetTunnelRoutes() string {
	n.mu.Lock()
	st := n.state
	n.mu.Unlock()

	if st == nil || st.Env == nil {
		return marshalTunnelRoutes(MobileTunnelRoutes{})
	}

	result := make(chan MobileTunnelRoutes, 1)
	st.Env.Dispatch(func(s *state.State) error {
		result <- BuildTunnelRoutes(s)
		return nil
	})

	select {
	case routes := <-result:
		return marshalTunnelRoutes(routes)
	case <-time.After(5 * time.Second):
		return marshalTunnelRoutes(MobileTunnelRoutes{})
	}
}

func marshalTunnelRoutes(routes MobileTunnelRoutes) string {
	data, _ := json.Marshal(routes)
	return string(data)
}

func BuildTunnelRoutes(s *state.State) MobileTunnelRoutes {
	if s == nil || s.Env == nil {
		return MobileTunnelRoutes{}
	}

	included := make([]netip.Prefix, 0)
	if s.ExitNode != "" {
		included = append(included, netip.MustParsePrefix("0.0.0.0/0"))
	} else if router := getRouter(s); router != nil {
		included = append(included, router.ComputeSysRouteTable()...)
	}

	excluded := buildIPv4Excludes(s.Env)
	return MobileTunnelRoutes{
		IncludedRoutes: prefixStrings(filterIPv4Prefixes(included)),
		ExcludedRoutes: prefixStrings(excluded),
		IPv6Enabled:    false,
		ExitNode:       string(s.ExitNode),
	}
}

func getRouter(s *state.State) *core.NylonRouter {
	if s == nil || s.Modules == nil {
		return nil
	}
	module, ok := s.Modules[reflect.TypeFor[*core.NylonRouter]().String()]
	if !ok {
		return nil
	}
	router, _ := module.(*core.NylonRouter)
	return router
}

func buildIPv4Excludes(env *state.Env) []netip.Prefix {
	excluded := make([]netip.Prefix, 0)
	defaultExcludes := state.SubtractPrefix(env.CentralCfg.ExcludeIPs, env.LocalCfg.UnexcludeIPs)
	excluded = append(excluded, defaultExcludes...)
	excluded = append(excluded, env.LocalCfg.ExcludeIPs...)
	excluded = append(excluded,
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	)

	for _, router := range env.CentralCfg.Routers {
		for _, endpoint := range router.Endpoints {
			excluded = append(excluded, resolveEndpointIPv4(endpoint)...)
		}
	}

	if env.LocalCfg.Dist != nil {
		excluded = append(excluded, resolveURLHostIPv4(env.LocalCfg.Dist.Url)...)
	}

	for _, resolver := range env.LocalCfg.DnsResolvers {
		if addrPort, err := netip.ParseAddrPort(resolver); err == nil {
			excluded = append(excluded, addrToIPv4Prefix(addrPort.Addr())...)
		}
	}

	return filterIPv4Prefixes(state.CoalescePrefix(excluded))
}

func resolveEndpointIPv4(endpoint *state.DynamicEndpoint) []netip.Prefix {
	if endpoint == nil {
		return nil
	}

	host, _, err := endpoint.Parse()
	if err != nil {
		return nil
	}
	return resolveHostIPv4(host)
}

func resolveURLHostIPv4(rawURL string) []netip.Prefix {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return resolveHostIPv4(parsed.Hostname())
}

func resolveHostIPv4(host string) []netip.Prefix {
	if host == "" {
		return nil
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return addrToIPv4Prefix(addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}

	prefixes := make([]netip.Prefix, 0, len(ips))
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			prefixes = append(prefixes, addrToIPv4Prefix(addr)...)
		}
	}
	return prefixes
}

func addrToIPv4Prefix(addr netip.Addr) []netip.Prefix {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() {
		return nil
	}
	return []netip.Prefix{netip.PrefixFrom(addr, 32)}
}

func filterIPv4Prefixes(prefixes []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Addr().Unmap().Is4() {
			result = append(result, netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()))
		}
	}
	return result
}

func prefixStrings(prefixes []netip.Prefix) []string {
	seen := make(map[string]struct{}, len(prefixes))
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		value := prefix.String()
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
