package plugins

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain implements the standard Go "re-exec the test binary as a fake
// subprocess" pattern (see the exec.Command example in the standard
// library), so RunJSONLines can be tested against a real subprocess with
// controllable behavior, without depending on any actual external tool
// being installed.
func TestMain(m *testing.M) {
	if os.Getenv("SAKANNER_HELPER_PROCESS") == "1" {
		helperProcess()
		return
	}
	os.Exit(m.Run())
}

// helperProcess's behavior is selected by SAKANNER_HELPER_MODE.
func helperProcess() {
	switch os.Getenv("SAKANNER_HELPER_MODE") {
	case "lines":
		os.Stdout.WriteString(`{"name":"a"}` + "\n")
		os.Stdout.WriteString("banner text that is not JSON\n") // simulates banner/update-check noise
		os.Stdout.WriteString(`{"name":"b"}` + "\n")
		os.Stdout.WriteString("\n") // blank line
		os.Stdout.WriteString(`{"name":"c"}` + "\n")
		os.Exit(0)
	case "empty-success":
		os.Exit(0)
	case "fail":
		os.Stderr.WriteString("something went wrong\n")
		os.Exit(1)
	case "hang":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "oversized-line-then-more-output":
		// One line over maxJSONLineSize, then keep writing indefinitely.
		// Reproduces the scenario where bufio.Scanner gives up early
		// (bufio.ErrTooLong) while the subprocess is still alive and
		// still trying to write -- RunJSONLines must kill it rather than
		// block in cmd.Wait() waiting for a pipe nobody is draining.
		os.Stdout.WriteString(strings.Repeat("a", maxJSONLineSize+1024))
		os.Stdout.WriteString("\n")
		for {
			if _, err := os.Stdout.WriteString(strings.Repeat("b", 4096) + "\n"); err != nil {
				os.Exit(0)
			}
		}
	default:
		os.Exit(1)
	}
}

// runHelper invokes this package's own test binary as the "external
// tool", selecting helperProcess's behavior via SAKANNER_HELPER_MODE in
// the current (test) process's environment -- exec.CommandContext
// inherits it automatically since RunJSONLines never sets cmd.Env.
func runHelper[T any](ctx context.Context, t *testing.T, mode string, onLine func(T) error) error {
	t.Helper()
	t.Setenv("SAKANNER_HELPER_PROCESS", "1")
	t.Setenv("SAKANNER_HELPER_MODE", mode)
	return RunJSONLines(ctx, os.Args[0], []string{"-test.run=^TestMain$"}, onLine)
}

type nameOnly struct {
	Name string `json:"name"`
}

func TestRunJSONLines_DecodesValidLinesSkipsMalformed(t *testing.T) {
	var got []string
	err := runHelper(context.Background(), t, "lines", func(v nameOnly) error {
		got = append(got, v.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("RunJSONLines: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunJSONLines_EmptyOutputWithExitZeroIsSuccess(t *testing.T) {
	var callCount int
	err := runHelper(context.Background(), t, "empty-success", func(v nameOnly) error {
		callCount++
		return nil
	})
	if err != nil {
		t.Fatalf("RunJSONLines: %v, want nil (a tool finding nothing and exiting 0 is success)", err)
	}
	if callCount != 0 {
		t.Errorf("onLine called %d times, want 0", callCount)
	}
}

func TestRunJSONLines_NonZeroExitIsError(t *testing.T) {
	err := runHelper(context.Background(), t, "fail", func(v nameOnly) error { return nil })
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Errorf("error %v does not include stderr content", err)
	}
}

func TestRunJSONLines_ContextCancellationKillsProcessPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := runHelper(ctx, t, "hang", func(v nameOnly) error { return nil })
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected an error from a cancelled/killed subprocess")
	}
	if elapsed > 5*time.Second {
		t.Errorf("RunJSONLines took %v after cancellation at 100ms, want well under 5s (subprocess must be killed promptly, not left to hang)", elapsed)
	}
}

// TestRunJSONLines_OversizedLineKillsSubprocessRatherThanHanging is a
// regression test for a real bug found during Phase 2 adversarial
// testing: when bufio.Scanner gives up on a line exceeding
// maxJSONLineSize, the scan loop used to exit without killing the still
// -running subprocess, so cmd.Wait() below it could hang forever if the
// subprocess kept writing to a stdout pipe nobody was draining anymore
// -- independent of the caller's ctx, since ctx was never cancelled in
// this scenario. Reverting the fix and re-running this test reproduces
// a hang past 15s; with the fix, RunJSONLines returns in low single
// digits of seconds (bounded by cmd.WaitDelay).
func TestRunJSONLines_OversizedLineKillsSubprocessRatherThanHanging(t *testing.T) {
	start := time.Now()
	err := runHelper(context.Background(), t, "oversized-line-then-more-output", func(v nameOnly) error { return nil })
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected an error for a line exceeding maxJSONLineSize")
	}
	if elapsed > 12*time.Second {
		t.Errorf("RunJSONLines took %v against a subprocess that kept writing after an oversized line, want well under 12s -- it must kill the subprocess, not wait for it to finish on its own", elapsed)
	}
}

func TestRunJSONLines_CallbackErrorStopsProcessingEarly(t *testing.T) {
	sentinel := errors.New("stop here")
	var got []string
	err := runHelper(context.Background(), t, "lines", func(v nameOnly) error {
		got = append(got, v.Name)
		if v.Name == "b" {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got %v, want exactly [a b] (must stop at the erroring line, not continue to c)", got)
	}
}
