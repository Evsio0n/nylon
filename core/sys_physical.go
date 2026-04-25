//go:build !integration

package core

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
)

func NewWireGuardDevice(s *state.State, n *Nylon) (dev *device.Device, tunDevice tun.Device, realItf string, err error) {
	itfName := s.InterfaceName // attempt to name the interface

	var tdev tun.Device
	isMobile, _ := s.AuxConfig["isMobile"].(bool)

	// Check for pre-created TUN device (mobile / NetworkExtension)
	if preTUN, ok := s.AuxConfig["tunDevice"].(tun.Device); ok {
		tdev = preTUN
	} else {
		if runtime.GOOS == "darwin" {
			itfName = "utun"
		}
		tdev, err = tun.CreateTUN(itfName, device.DefaultMTU)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create TUN: %v. Check if an interface with the name nylon exists already", err)
		}
	}

	realInterfaceName, err := tdev.Name()
	if err == nil {
		itfName = realInterfaceName
	}

	// setup WireGuard
	dev = device.NewDevice(tdev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(format string, args ...any) {
			if state.DBG_log_wireguard {
				s.Log.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			if strings.Contains(format, "Failed to send PolySock packets") {
				return
			}
			s.Log.Error(fmt.Sprintf(format, args...))
		},
	})

	// Apply mobile-specific WireGuard quirks
	if isMobile {
		dev.DisableSomeRoamingForBrokenMobileSemantics()
	}

	// start uapi for wg command (skip on mobile)
	if !isMobile {
		n.wgUapi, err = InitUAPI(s.Env, itfName)
		if err != nil {
			return nil, nil, "", err
		}

		if n.wgUapi != nil {
			go func() {
				for s.Context.Err() == nil {
					accept, err := n.wgUapi.Accept()
					if err != nil {
						s.Env.Log.Debug(err.Error())
						continue
					}
					go dev.IpcHandle(accept)
				}
			}()
		}
	}

	s.Log.Info("Created WireGuard interface", "name", itfName, "mobile", isMobile)
	return dev, tdev, itfName, nil
}

func CleanupWireGuardDevice(s *state.State, n *Nylon) error {
	n.Device.Close()
	if n.wgUapi != nil {
		err := n.wgUapi.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
