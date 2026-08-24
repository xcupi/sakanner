package ports

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"sakanner/internal/testutil"
)

func TestNaabuScanner_ParsesOpenPorts(t *testing.T) {
	binary := testutil.WriteScript(t, "naabu", `
echo '{"ip":"203.0.113.5","port":80}'
echo 'a stray banner line'
echo '{"ip":"203.0.113.5","port":443}'
exit 0
`)
	s := NewNaabuScanner(binary, &fakeValidator{allowed: true}, nil)
	if s.Name() != "naabu" {
		t.Errorf("Name() = %q, want naabu", s.Name())
	}

	results, err := s.Scan(context.Background(), "example.com", net.ParseIP("203.0.113.5"), []int{80, 443})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var ports []int
	for r := range results {
		if !r.Open {
			t.Errorf("Result %+v, want Open=true", r)
		}
		ports = append(ports, r.Port)
	}
	if len(ports) != 2 {
		t.Fatalf("got %d results, want 2: %v", len(ports), ports)
	}
}

func TestNaabuScanner_DeniedScopeReturnsErrorWithoutRunning(t *testing.T) {
	binary := testutil.WriteScript(t, "naabu", `echo '{"ip":"203.0.113.5","port":80}'`+"\n")
	s := NewNaabuScanner(binary, &fakeValidator{allowed: false}, nil)

	_, err := s.Scan(context.Background(), "example.com", net.ParseIP("203.0.113.5"), []int{80})
	if err == nil {
		t.Fatal("expected an error for a denied scope check")
	}
}

func TestNewScanner_BackendSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	s, err := NewScanner("native", &fakeValidator{allowed: true}, time.Second, 4, nil, logger)
	if err != nil {
		t.Fatalf("NewScanner(native): %v", err)
	}
	if s.Name() != "tcp-connect" {
		t.Errorf("backend=native: Name() = %q, want tcp-connect", s.Name())
	}

	if _, err := NewScanner("not-a-real-backend", &fakeValidator{allowed: true}, time.Second, 4, nil, logger); err == nil {
		t.Error("NewScanner(garbage backend) = nil error, want an error")
	}
}

func TestNewScanner_AutoUsesNaabuWhenPresent(t *testing.T) {
	binary := testutil.WriteScript(t, "naabu", "exit 0\n")
	t.Setenv("PATH", filepath.Dir(binary))

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	s, err := NewScanner("auto", &fakeValidator{allowed: true}, time.Second, 4, nil, logger)
	if err != nil {
		t.Fatalf("NewScanner(auto): %v", err)
	}
	if s.Name() != "naabu" {
		t.Errorf("Name() = %q, want naabu when it's present on PATH", s.Name())
	}
}

func TestNewScanner_AutoFallsBackWhenNaabuAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	s, err := NewScanner("auto", &fakeValidator{allowed: true}, time.Second, 4, nil, logger)
	if err != nil {
		t.Fatalf("NewScanner(auto): %v", err)
	}
	if s.Name() != "tcp-connect" {
		t.Errorf("Name() = %q, want tcp-connect when naabu is absent", s.Name())
	}
}
