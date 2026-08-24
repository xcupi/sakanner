package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf})

	logger.Info("hello", slog.String("k", "v"))

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("expected valid JSON log line, got error: %v (line: %s)", err, buf.String())
	}
	if record["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", record["msg"])
	}
	if record["k"] != "v" {
		t.Errorf("k = %v, want v", record["k"])
	}
}

func TestNewTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "info", Format: "text", Output: &buf})

	logger.Info("hello")

	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("expected text log line to contain message, got: %s", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "warn", Format: "text", Output: &buf})

	logger.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("expected info to be filtered at warn level, got: %s", buf.String())
	}

	logger.Warn("should appear")
	if buf.Len() == 0 {
		t.Errorf("expected warn to be logged at warn level")
	}
}

func TestWithScanJobTagsRecords(t *testing.T) {
	var buf bytes.Buffer
	base := New(Options{Level: "info", Format: "json", Output: &buf})
	logger := WithScanJob(base, "scan-123")

	logger.Info("probing target")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record["scan_job_id"] != "scan-123" {
		t.Errorf("scan_job_id = %v, want scan-123", record["scan_job_id"])
	}
}
