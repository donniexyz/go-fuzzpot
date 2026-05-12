//go:build !linux && !windows && !freebsd

package portscan

import (
        "fmt"
        "net"
        "sync"
)

func init() {
        GetUsedPorts = getUsedPortsOther
}

// getUsedPortsOther uses a net.Listen probe as cross-platform fallback.
// It briefly attempts to bind each port to check if it's in use.
// This is slower than platform-specific methods but works everywhere.
func getUsedPortsOther() map[int]bool {
        return probeUsedPorts(probeDefaultRanges())
}

// EphemeralRange returns a sensible default for unknown platforms.
func EphemeralRange() (int, int, error) {
        return 32768, 60999, nil
}

// probeDefaultRanges returns the port ranges to probe on fallback platforms.
func probeDefaultRanges() [][2]int {
        return [][2]int{
                {1, 1024},
                {2000, 10000},
                {32768, 61000},
        }
}

// probeUsedPorts tries to bind each port to detect if it's in use.
func probeUsedPorts(ranges [][2]int) map[int]bool {
        used := make(map[int]bool)
        var mu sync.Mutex
        var wg sync.WaitGroup

        for _, r := range ranges {
                for p := r[0]; p <= r[1]; p++ {
                        wg.Add(1)
                        go func(port int) {
                                defer wg.Done()
                                ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
                                if err != nil {
                                        mu.Lock()
                                        used[port] = true
                                        mu.Unlock()
                                } else {
                                        ln.Close()
                                }
                        }(p)
                }
        }

        wg.Wait()
        return used
}
