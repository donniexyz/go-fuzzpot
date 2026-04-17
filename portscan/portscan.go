package portscan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// GetUsedPorts reads /proc/net/tcp and /proc/net/tcp6 to find all
// TCP ports in LISTEN state (state 0A).
func GetUsedPorts() map[int]bool {
	used := make(map[int]bool)
	mergeFile(used, "/proc/net/tcp")
	mergeFile(used, "/proc/net/tcp6")
	return used
}

func mergeFile(used map[int]bool, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// State field (index 3): 0A = LISTEN
		if fields[3] != "0A" {
			continue
		}
		// Local address field (index 1): format "IP:PORT" in hex
		port, err := parseHexPort(fields[1])
		if err != nil {
			continue
		}
		used[port] = true
	}
}

func parseHexPort(addr string) (int, error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("bad addr format: %s", addr)
	}
	p, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return 0, err
	}
	return int(p), nil
}

// EphemeralRange returns the Linux default ephemeral port range
// by reading /proc/sys/net/ipv4/ip_local_port_range.
func EphemeralRange() (int, int, error) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		// Linux default: 32768-60999
		return 32768, 60999, nil
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 2 {
		return 32768, 60999, nil
	}
	lo, err1 := strconv.Atoi(fields[0])
	hi, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 32768, 60999, nil
	}
	return lo, hi, nil
}

// IsEphemeral checks if a port falls within the ephemeral range.
func IsEphemeral(port int, ephLo, ephHi int) bool {
	return port >= ephLo && port <= ephHi
}

// PortManager manages the set of honeypot listener ports,
// handling conflict detection and dynamic refresh.
type PortManager struct {
	mu            sync.RWMutex
	listenPorts   map[int]struct{}  // ports we're currently listening on
	excludePorts  map[int]struct{}  // user-configured excludes
	ephLo, ephHi  int               // ephemeral range
}

func NewPortManager(exclude []int) *PortManager {
	pm := &PortManager{
		listenPorts:  make(map[int]struct{}),
		excludePorts: make(map[int]struct{}),
	}
	for _, p := range exclude {
		pm.excludePorts[p] = struct{}{}
	}
	pm.ephLo, pm.ephHi, _ = EphemeralRange()
	return pm
}

// TargetPorts returns the ports we should listen on:
// union of all configured ranges, minus used ports, minus excludes, minus ephemeral.
func (pm *PortManager) TargetPorts(ranges [][2]int) []int {
	used := GetUsedPorts()
	pm.mu.Lock()
	defer pm.mu.Unlock()

	result := make(map[int]struct{})
	for _, r := range ranges {
		for p := r[0]; p <= r[1]; p++ {
			if used[p] {
				continue
			}
			if _, ok := pm.excludePorts[p]; ok {
				continue
			}
			if IsEphemeral(p, pm.ephLo, pm.ephHi) {
				continue
			}
			result[p] = struct{}{}
		}
	}

	ports := make([]int, 0, len(result))
	for p := range result {
		ports = append(ports, p)
	}
	return ports
}

// SetListening marks a port as being listened on.
func (pm *PortManager) SetListening(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.listenPorts[port] = struct{}{}
}

// ClearListening removes a port from the listened set.
func (pm *PortManager) ClearListening(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.listenPorts, port)
}

// ListeningCount returns the number of ports currently being listened on.
func (pm *PortManager) ListeningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.listenPorts)
}

// DetectConflicts checks if any of our listen ports have been claimed
// by a new system service. Returns ports that should be released.
func (pm *PortManager) DetectConflicts() []int {
	used := GetUsedPorts()
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var conflicts []int
	for p := range pm.listenPorts {
		if used[p] {
			conflicts = append(conflicts, p)
		}
	}
	return conflicts
}

// RefreshEphemeralRange re-reads the ephemeral range from procfs.
func (pm *PortManager) RefreshEphemeralRange() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.ephLo, pm.ephHi, _ = EphemeralRange()
}
