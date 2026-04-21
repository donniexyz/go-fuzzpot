package capture

import (
	"testing"
)

// FuzzExtractPrintable tests extractPrintable with arbitrary byte sequences
// to discover edge cases that could cause panics or unexpected behavior.
func FuzzExtractPrintable(f *testing.F) {
	// Seed with some initial test cases
	testSeeds := [][]byte{
		{},                                    // empty input
		[]byte("hello"),                       // all printable
		[]byte{0x00, 0x01, 0x7F, 0xFF},        // non-printable bytes
		[]byte("Hello\nWorld\r\tTest"),        // mixed with special chars
		[]byte{32, 33, 126, 127},              // boundary values
		make([]byte, 1000),                    // large buffer of zeros
	}

	for _, seed := range testSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		result := extractPrintable(data)

		// Verify result is always valid UTF-8 string
		if len(result) > 256 {
			t.Errorf("extractPrintable returned string longer than 256 chars: %d", len(result))
		}

		// Verify only printable ASCII or allowed special chars
		for i, c := range result {
			isValid := (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t'
			if !isValid {
				t.Errorf("invalid character at position %d: %c (%d)", i, c, c)
			}
		}
	})
}

// FuzzEventJSONLine tests Event.JSONLine with various event data
// to ensure JSON serialization doesn't panic on edge cases.
func FuzzEventJSONLine(f *testing.F) {
	testSeeds := []struct {
		sourceIP   string
		sourcePort int
		destPort   int
		proto      string
		size       int
		hex        string
		printable  string
	}{
		{"192.168.1.1", 12345, 80, "tcp", 100, "48656c6c6f", "Hello"},
		{"", 0, 0, "", 0, "", ""},
		{"::1", 65535, 65535, "tcp", 0, "", ""},
		{"0.0.0.0", 1, 1, "udp", 1, "00", "."},
		{"256.256.256.256", -1, -1, "", -1, "invalid", "\x00\x01"},
	}

	for _, seed := range testSeeds {
		f.Add(seed.sourceIP, seed.sourcePort, seed.destPort, seed.proto, seed.size, seed.hex, seed.printable)
	}

	f.Fuzz(func(t *testing.T, sourceIP string, sourcePort, destPort int, proto string, size int, hexStr, printable string) {
		event := Event{
			SourceIP:   sourceIP,
			SourcePort: sourcePort,
			DestPort:   destPort,
			Proto:      proto,
			Size:       size,
			Hex:        hexStr,
			Printable:  printable,
		}

		// Should not panic
		jsonLine := event.JSONLine()

		// Verify it produces valid output (non-empty for valid events)
		if len(jsonLine) == 0 {
			t.Error("JSONLine produced empty output")
		}
	})
}
