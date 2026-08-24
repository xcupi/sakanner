// Command scanner is sakanner's CLI entrypoint.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if ec, ok := err.(*exitCodeErr); ok {
			os.Exit(ec.code)
		}
		os.Exit(1)
	}
}
