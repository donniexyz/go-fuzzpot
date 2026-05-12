package portscan

import (
	"testing"
)

func TestPortManager_TargetPorts_ExcludesCorrectly(t *testing.T) {
	// Setup: exclude ports 80, 443; ephemeral 32768-60999
	pm := NewPortManager([]int{80, 443})
	pm.ephLo, pm.ephHi = 32768, 60999

	// Mock used ports: 22, 8080
	// We'll override GetUsedPorts via test helper
	original := GetUsedPorts
	GetUsedPorts = func() map[int]bool {
		return map[int]bool{22: true, 8080: true}
	}
	t.Cleanup(func() { GetUsedPorts = original })

	ranges := [][2]int{{1, 100}, {8000, 8100}, {32768, 32770}}
	targets := pm.TargetPorts(ranges)

	// Should exclude: 22 (used), 80/443 (config), 32768-32770 (ephemeral)
	wantExcluded := map[int]bool{22: true, 80: true, 443: true, 8080: true}
	for _, p := range []int{32768, 32769, 32770} {
		wantExcluded[p] = true
	}

	for _, port := range targets {
		if wantExcluded[port] {
			t.Errorf("TargetPorts() included excluded port %d", port)
		}
		if port < 1 || port > 65535 {
			t.Errorf("TargetPorts() returned invalid port %d", port)
		}
	}

	// Should include: 1-79 (except 22), 81-100, 8000-8079, 8081-8100
	if len(targets) == 0 {
		t.Error("TargetPorts() returned empty list")
	}
}

func TestPortManager_DetectConflicts(t *testing.T) {
	pm := NewPortManager(nil)

	// Simulate listening on ports 8080, 9090
	pm.SetListening(8080)
	pm.SetListening(9090)
	pm.SetListening(7777) // not in used map

	// Mock used ports: 8080 now claimed by system
	original := GetUsedPorts
	GetUsedPorts = func() map[int]bool {
		return map[int]bool{8080: true} // 9090 and 7777 not used
	}
	t.Cleanup(func() { GetUsedPorts = original })

	conflicts := pm.DetectConflicts()

	if len(conflicts) != 1 || conflicts[0] != 8080 {
		t.Errorf("DetectConflicts() = %v, want [8080]", conflicts)
	}
}

func TestPortManager_RefreshEphemeralRange(t *testing.T) {
	pm := NewPortManager(nil)
	originalLo, originalHi := pm.ephLo, pm.ephHi

	// On non-linux, EphemeralRange returns defaults, so just verify no panic
	pm.RefreshEphemeralRange()

	// Should still be valid range
	if pm.ephLo > pm.ephHi {
		t.Errorf("RefreshEphemeralRange() produced invalid range: %d-%d", pm.ephLo, pm.ephHi)
	}

	// Restore for other tests
	pm.ephLo, pm.ephHi = originalLo, originalHi
}

func TestIsEphemeral_Boundaries(t *testing.T) {
	tests := []struct {
		port, lo, hi int
		want         bool
	}{
		{32768, 32768, 60999, true},  // low boundary
		{60999, 32768, 60999, true},  // high boundary
		{32767, 32768, 60999, false}, // just below
		{61000, 32768, 60999, false}, // just above
		{1000, 32768, 60999, false},  // well below
		{0, 0, 0, true},              // edge: zero range
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := IsEphemeral(tt.port, tt.lo, tt.hi); got != tt.want {
				t.Errorf("IsEphemeral(%d, %d, %d) = %v, want %v",
					tt.port, tt.lo, tt.hi, got, tt.want)
			}
		})
	}
}
