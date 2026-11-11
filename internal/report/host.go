package report

import (
	"regexp"
	"strings"

	"github.com/njvack/openconnect-hipreports/internal/checks"
)

// Interface is one hardware network port.
type Interface struct {
	Device string   `json:"device"`
	MAC    string   `json:"mac"`
	IPv4   []string `json:"ipv4,omitempty"`
	IPv6   []string `json:"ipv6,omitempty"`
}

// Interfaces lists hardware ports only: GP skips lo0, utun*, awdl0 and
// similar.
func Interfaces(e *checks.Env) []Interface {
	out, _ := e.Run(0, "/usr/sbin/networksetup", "-listallhardwareports")
	var ifs []Interface
	for _, line := range strings.Split(out, "\n") {
		dev, ok := strings.CutPrefix(strings.TrimSpace(line), "Device:")
		if !ok {
			continue
		}
		dev = strings.TrimSpace(dev)
		if dev == "" {
			continue
		}
		ifs = append(ifs, Interface{
			Device: dev,
			MAC:    HardwareMAC(e, dev),
			IPv4:   addrs(e, dev, "inet"),
			IPv6:   addrs(e, dev, "inet6"),
		})
	}
	return ifs
}

var macLike = regexp.MustCompile(`.*:.*:`)

// HardwareMAC is an interface's burned-in address, not the private
// per-network Wi-Fi address; GP reports the burned-in one too.
func HardwareMAC(e *checks.Env, dev string) string {
	out, _ := e.Run(0, "/usr/sbin/networksetup", "-getmacaddress", dev)
	mac := field(out, 2)
	if !macLike.MatchString(mac) { // e.g. bridge0
		mac = ""
		ifc, _ := e.Run(0, "/sbin/ifconfig", dev)
		for _, l := range strings.Split(ifc, "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "ether" {
				mac = f[1]
				break
			}
		}
	}
	return mac
}

func field(s string, i int) string {
	f := strings.Fields(s)
	if i < len(f) {
		return f[i]
	}
	return ""
}

func addrs(e *checks.Env, dev, family string) []string {
	out, _ := e.Run(0, "/sbin/ifconfig", dev)
	var a []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == family {
			addr, _, _ := strings.Cut(f[1], "%")
			a = append(a, addr)
		}
	}
	return a
}
