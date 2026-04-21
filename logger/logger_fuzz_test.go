package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzWriteEvent tests WriteEvent with various event data
// to ensure it handles edge cases without panicking.
func FuzzWriteEvent(f *testing.F) {
	testSeeds := []string{
		`{"timestamp": "2024-01-01T00:00:00Z", "source_ip": "192.168.1.1", "source_port": 12345, "dest_port": 80, "proto": "tcp", "size": 100, "hex": "48656c6c6f", "printable": "Hello"}`,
		`{}`,
		`{"key": null}`,
		`{"nested": {"inner": "value"}}`,
		`{"array": [1, 2, 3]}`,
		`{"special": "\u0000\u0001\u007f\ufffd"}`,
		`{"unicode": "Hello 世界 🌍"}`,
	}

	for _, seed := range testSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, jsonStr string) {
		// Create a temporary directory and log file for each fuzz iteration
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "test.log")

		l, err := New(tmpDir, "test.log", 1) // 1MB rotation
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}
		defer l.Close()

		// Parse the JSON string into map[string]interface{}
		var eventData map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &eventData); err != nil {
			// Invalid JSON is acceptable input, just skip
			return
		}

		// Should not panic
		err = l.WriteEvent(eventData)
		
		// We accept that some invalid data might cause JSON marshal errors
		// but it should not panic
		if err != nil {
			// Error is acceptable for invalid data, just shouldn't panic
			return
		}

		// Verify the file exists and has content
		info, statErr := os.Stat(logPath)
		if statErr != nil {
			t.Errorf("Log file was not created: %v", statErr)
		} else if info.Size() == 0 {
			t.Error("Log file is empty after WriteEvent")
		}
	})
}

// FuzzNewLogger tests Logger creation with various directory and filename inputs
// to discover path traversal or invalid path issues.
func FuzzNewLogger(f *testing.F) {
	testSeeds := []struct {
		dir      string
		filename string
		rotSize  int
	}{
		{"/tmp", "test.log", 1},
		{"", "test.log", 1},
		{"/tmp/testdir", "", 1},
		{"/tmp/../tmp", "test.log", 1},
		{"/tmp", "../../../etc/passwd", 1},
		{"/tmp", "test.log", 0},
		{"/tmp", "test.log", -1},
	}

	for _, seed := range testSeeds {
		f.Add(seed.dir, seed.filename, seed.rotSize)
	}

	f.Fuzz(func(t *testing.T, dir, filename string, rotSize int) {
		// Skip paths that would require elevated permissions
		if dir == "" || filename == "" {
			return
		}

		// Use temp directory as base to avoid permission issues
		tmpBase := t.TempDir()
		testDir := filepath.Join(tmpBase, dir)
		
		// Create logger - should not panic even with invalid paths
		l, err := New(testDir, filename, rotSize)
		if err != nil {
			// Error is acceptable for invalid paths
			return
		}
		defer l.Close()

		// Verify logger was created successfully
		if l == nil {
			t.Error("Logger is nil despite no error")
		}
	})
}
