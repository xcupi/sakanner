// Package logging provides sakanner's structured logging setup. Every
// logger used within a scan is tagged with a scan_job_id so that every
// log line -- and by extension every request the platform makes -- is
// attributable to the scan job that produced it.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// Options configures New.
type Options struct {
	Level  string // debug, info, warn, error
	Format string // text, json
	Output io.Writer
}

// New builds a slog.Logger from Options. An unrecognized Level defaults to
// info; an unrecognized Format defaults to text.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{Level: parseLevel(opts.Level)}

	var handler slog.Handler
	if opts.Format == "json" {
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}

	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithScanJob returns a logger derived from base with scan_job_id attached
// to every subsequent log record. Every scanner module that performs work
// on behalf of a scan job must use a logger built this way, so log output
// (and the requests it documents) stays attributable to that job.
func WithScanJob(base *slog.Logger, scanJobID string) *slog.Logger {
	return base.With(slog.String("scan_job_id", scanJobID))
}
