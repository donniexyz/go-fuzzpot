package logger

import (
	"encoding/json"
	"os"
	"testing"
)

func TestWriteEventTyped_JSONEscaping(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "test.log", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Test event with characters that require JSON escaping
	type TestEvent struct {
		Msg string `json:"msg"`
	}

	testCases := []struct {
		name         string
		input        string
		wantContains string
	}{
		{"quote", `hello"world`, `\"`},
		{"backslash", `path\to\file`, `\\`},
		{"newline", "line1\nline2", `\n`},
		{"tab", "col1\tcol2", `\t`},
		{"unicode", "café", "café"}, // UTF-8 should pass through
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := TestEvent{Msg: tc.input}
			if err := log.WriteEventTyped(event); err != nil {
				t.Errorf("WriteEventTyped() error = %v", err)
			}

			// Read back and verify JSON is valid
			content, err := os.ReadFile(log.Path())
			if err != nil {
				t.Fatal(err)
			}

			// Should be valid JSON line
			if !contains(string(content), tc.wantContains) {
				t.Errorf("expected %q in output, got: %s", tc.wantContains, string(content))
			}
		})
	}
}

func TestWriteEventTyped_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "test.log", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	type TestEvent struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	event := TestEvent{Name: "test", Value: 42}
	if err := log.WriteEventTyped(event); err != nil {
		t.Fatalf("WriteEventTyped() error = %v", err)
	}

	content, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}

	// Verify the output is valid JSON
	var result TestEvent
	if err := json.Unmarshal(content, &result); err != nil {
		t.Errorf("output is not valid JSON: %v, got: %s", err, string(content))
	}

	if result.Name != "test" || result.Value != 42 {
		t.Errorf("unmarshal mismatch: got %+v", result)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return len(substr) == 0
}
