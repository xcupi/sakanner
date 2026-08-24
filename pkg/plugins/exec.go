package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// maxJSONLineSize bounds a single stdout line, since these tools can
// legitimately emit large JSON objects (e.g. a full response body field)
// but must not be allowed to exhaust memory on a hostile or malfunctioning
// process.
const maxJSONLineSize = 4 * 1024 * 1024

// RunJSONLines runs binary with args and decodes each line of its stdout
// as a JSON value of type T, calling onLine for each one as it arrives.
// Lines that aren't valid JSON (banner/update-check text some of these
// tools print even with -silent, in older versions) are skipped, not
// fatal. A subprocess that exits 0 having found nothing produces no
// lines at all -- that's success, not an error; only a non-zero exit
// (with any stderr output attached for context) is treated as failure.
//
// ctx cancellation kills the subprocess (via Cmd.Cancel/WaitDelay, so a
// stdout pipe that never drains after Kill can't hang Wait()). If onLine
// returns an error, RunJSONLines stops reading, kills the subprocess, and
// returns that error.
//
// binary and args are passed to exec.CommandContext directly (argv form)
// -- never through a shell -- so args are never subject to shell
// interpretation regardless of their content.
func RunJSONLines[T any](ctx context.Context, binary string, args []string, onLine func(T) error) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 5 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("plugins: stdout pipe for %s: %w", binary, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("plugins: starting %s: %w", binary, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), maxJSONLineSize)

	var callbackErr error
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			continue // skip malformed/non-JSON output lines
		}
		if err := onLine(v); err != nil {
			callbackErr = err
			break
		}
	}
	scanErr := scanner.Err()

	// Kill the subprocess whenever the scan loop stopped for any reason
	// OTHER than the subprocess itself closing stdout (clean EOF) --
	// callbackErr is one such reason, but scanErr (e.g. bufio.ErrTooLong,
	// when a single line exceeds maxJSONLineSize) is another, and was
	// previously missed here. Without this, a still-running subprocess
	// that keeps writing after we've stopped reading its stdout can
	// block forever on a full OS pipe buffer nobody is draining, and
	// cmd.Wait() below would then hang indefinitely waiting for a
	// process that can never exit on its own -- regardless of the
	// caller's ctx, since ctx was never cancelled in this scenario.
	if callbackErr != nil || scanErr != nil {
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()

	if callbackErr != nil {
		return callbackErr
	}
	if scanErr != nil {
		return fmt.Errorf("plugins: reading %s output: %w", binary, scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("plugins: %s exited with error: %w (stderr: %s)", binary, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}
