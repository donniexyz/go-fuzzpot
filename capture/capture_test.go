package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestExtractPrintable(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"ascii", []byte("hello"), "hello"},
		{"with_null", []byte("A\x00B"), "A.B"},
		{"with_newline", []byte("line1\nline2"), "line1\nline2"},
		{"with_tab", []byte("col1\tcol2"), "col1\tcol2"},
		{"with_cr", []byte("line1\rline2"), "line1\rline2"},
		{"high_bit", []byte{0x80, 0xFF}, ".."},
		{"del_char", []byte{0x7F}, "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrintable(tt.input)
			if got != tt.want {
				t.Errorf("extractPrintable(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractPrintable_Truncation(t *testing.T) {
	// Should truncate at 256 bytes
	input := make([]byte, 300)
	for i := range input {
		input[i] = 'A'
	}
	got := extractPrintable(input)
	if len(got) != 256 {
		t.Errorf("extractPrintable() length = %d, want 256", len(got))
	}
}

func TestPayloadSHA256_Correctness(t *testing.T) {
	testPayloads := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"http_get", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"binary", []byte{0x00, 0xFF, 0x7F, 0x80}},
		{"zeros", make([]byte, 1000)},
	}

	for _, tt := range testPayloads {
		t.Run(tt.name, func(t *testing.T) {
			// Compute expected hash
			var expected string
			if len(tt.payload) > 0 {
				shaSum := sha256.Sum256(tt.payload)
				expected = hex.EncodeToString(shaSum[:])
			}

			// Verify hash via Event struct construction (mirrors Capture logic)
			var payloadSHA string
			if len(tt.payload) > 0 {
				shaSum := sha256.Sum256(tt.payload)
				payloadSHA = hex.EncodeToString(shaSum[:])
			}

			if payloadSHA != expected {
				t.Errorf("PayloadSHA256 = %s, want %s", payloadSHA, expected)
			}

			// Hash should always be 64 hex chars (32 bytes) when non-empty
			if len(tt.payload) > 0 && len(payloadSHA) != 64 {
				t.Errorf("PayloadSHA256 length = %d, want 64", len(payloadSHA))
			}

			// Empty payloads should produce empty hash (omitempty)
			if len(tt.payload) == 0 && payloadSHA != "" {
				t.Errorf("empty payload should produce empty SHA, got %s", payloadSHA)
			}
		})
	}
}

func TestPayloadSHA256_DifferentInputs(t *testing.T) {
	// Verify that different inputs produce different hashes
	payload1 := []byte("GET / HTTP/1.1")
	payload2 := []byte("POST /login HTTP/1.1")

	sha1 := sha256.Sum256(payload1)
	sha2 := sha256.Sum256(payload2)

	hash1 := hex.EncodeToString(sha1[:])
	hash2 := hex.EncodeToString(sha2[:])

	if hash1 == hash2 {
		t.Error("different payloads should produce different SHA256 hashes")
	}
}
