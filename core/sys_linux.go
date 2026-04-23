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
