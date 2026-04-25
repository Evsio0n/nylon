package core

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/encodeous/nylon/polyamide/ipc"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
)

func InitUAPI(e *state.Env, itfName string) (net.Listener, error) {
	fileUAPI, err := ipc.UAPIOpen(itfName)

	uapi, err := ipc.UAPIListen(itfName, fileUAPI)
	if err != nil {
		return nil, err
	}
	return uapi, nil
}

func InitInterface(logger *slog.Logger, ifName string, fwmark uint32) error {
	if err := Exec(logger, "ip", "link", "set", ifName, "up"); err != nil {
		return err
	}
	// Policy routing: packets NOT carrying Nylon's fwmark go through Nylon's route table.
	// Nylon's own WireGuard UDP socket carries the fwmark and falls through to the main table,
	// preventing routing loops when other VPNs (e.g. Tailscale) share the same host.
	table := fmt.Sprintf("%d", fwmark)
	return Exec(logger, "ip", "rule", "add", "not", "fwmark", table, "table", table, "priority", "32764")
}

func CleanupInterface(logger *slog.Logger, ifName string, fwmark uint32) {
	table := fmt.Sprintf("%d", fwmark)
	if err := Exec(logger, "ip", "rule", "del", "not", "fwmark", table, "table", table, "priority", "32764"); err != nil {
		logger.Error("failed to remove ip rule", "err", err)
	}
	if err := Exec(logger, "ip", "route", "flush", "table", table); err != nil {
		logger.Error("failed to flush route table", "table", table, "err", err)
	}
}

func ConfigureAlias(logger *slog.Logger, ifName string, addr netip.Addr) error {
	return Exec(logger, "ip", "addr", "add", addr.String(), "dev", ifName)
}

func ConfigureRoute(logger *slog.Logger, dev tun.Device, itfName string, route netip.Prefix, fwmark uint32) error {
	table := fmt.Sprintf("%d", fwmark)
	return Exec(logger, "ip", "route", "add", route.String(), "dev", itfName, "table", table)
}

func RemoveRoute(logger *slog.Logger, dev tun.Device, itfName string, route netip.Prefix, fwmark uint32) error {
	table := fmt.Sprintf("%d", fwmark)
	return Exec(logger, "ip", "route", "del", route.String(), "dev", itfName, "table", table)
}

func SetupExitNode(logger *slog.Logger, ifName string, sourcePrefixes []netip.Prefix) error {
	// Enable IP forwarding
	if err := Exec(logger, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if err := Exec(logger, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
	}
	// Setup MASQUERADE
	// We use iptables for now, as it is most commonly available.
	// We try both iptables and nftables if possible, but iptables is a safe bet for compatibility.
	cleanupLegacyExitNodeRules(logger, ifName)
	// This prevents masquerading traffic destined for the nylon interface itself if it somehow ends up in POSTROUTING.
	if err := ensureIptablesRule(logger, "-t", "nat", "-A", "POSTROUTING", "-o", ifName, "-j", "RETURN"); err != nil {
		return err
	}
	for _, prefix := range exitMasqueradePrefixes(sourcePrefixes) {
		if err := ensureIptablesRule(logger, "-t", "nat", "-A", "POSTROUTING", "-s", prefix.String(), "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	return nil
}

func CleanupExitNode(logger *slog.Logger, ifName string, sourcePrefixes []netip.Prefix) {
	for _, prefix := range exitMasqueradePrefixes(sourcePrefixes) {
		_ = Exec(logger, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", prefix.String(), "-j", "MASQUERADE")
	}
	_ = Exec(logger, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ifName, "-j", "RETURN")
	cleanupLegacyExitNodeRules(logger, ifName)
}

func ensureIptablesRule(logger *slog.Logger, args ...string) error {
	checkArgs := append([]string{}, args...)
	for i, arg := range checkArgs {
		if arg == "-A" {
			checkArgs[i] = "-C"
			break
		}
	}
	if err := execIptables(logger, checkArgs...); err == nil {
		return nil
	}
	return execIptables(logger, args...)
}

func execIptables(logger *slog.Logger, args ...string) error {
	return Exec(logger, "iptables", args...)
}

func cleanupLegacyExitNodeRules(logger *slog.Logger, ifName string) {
	for Exec(logger, "iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE") == nil {
	}
	for Exec(logger, "iptables", "-t", "nat", "-D", "POSTROUTING", "!", "-o", "lo", "-j", "MASQUERADE") == nil {
	}
	for Exec(logger, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ifName, "-j", "RETURN") == nil {
	}
}

func exitMasqueradePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		addr := prefix.Addr().Unmap()
		if !prefix.IsValid() || !addr.Is4() || prefix.Bits() == 0 {
			continue
		}
		normalized := netip.PrefixFrom(addr, prefix.Bits()).Masked()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return state.CoalescePrefix(result)
}
