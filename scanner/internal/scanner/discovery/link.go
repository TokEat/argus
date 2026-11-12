package discovery

import (
	"net"
	"strings"
)

// LinkNet is a local IPv4 network that can carry ARP.
type LinkNet struct {
	Iface net.Interface
	SrcIP net.IP
	Net   *net.IPNet
}

// LocalIPv4Nets returns up, non-loopback IPv4 networks with a 6-byte MAC
// and a mask shorter than /31. Point-to-point /31 and /32 links cannot ARP.
func LocalIPv4Nets() []LinkNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var nets []LinkNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones >= 31 {
				continue
			}
			nets = append(nets, LinkNet{
				Iface: iface,
				SrcIP: ip4,
				Net: &net.IPNet{
					IP:   ip4.Mask(ipnet.Mask),
					Mask: ipnet.Mask,
				},
			})
		}
	}
	return nets
}

// Partition splits IPs into on-link (share a local L2 subnet) and off-link.
func Partition(ips []string, nets []LinkNet) (onLink, offLink []string) {
	for _, raw := range ips {
		ip := parseIPv4(raw)
		if ip == nil || matchingNet(ip, nets) == nil {
			offLink = append(offLink, raw)
			continue
		}
		onLink = append(onLink, raw)
	}
	return onLink, offLink
}

// GroupByNet assigns on-link IPs to the first matching local network.
func GroupByNet(ips []string, nets []LinkNet) [][]string {
	if len(nets) == 0 {
		return nil
	}
	buckets := make([][]string, len(nets))
	for _, raw := range ips {
		ip := parseIPv4(raw)
		if ip == nil {
			continue
		}
		for i := range nets {
			if nets[i].Net != nil && nets[i].Net.Contains(ip) {
				buckets[i] = append(buckets[i], raw)
				break
			}
		}
	}
	var groups [][]string
	for _, bucket := range buckets {
		if len(bucket) > 0 {
			groups = append(groups, bucket)
		}
	}
	return groups
}

func matchingNet(ip net.IP, nets []LinkNet) *LinkNet {
	for i := range nets {
		if nets[i].Net != nil && nets[i].Net.Contains(ip) {
			return &nets[i]
		}
	}
	return nil
}

func parseIPv4(raw string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return nil
	}
	return ip.To4()
}
