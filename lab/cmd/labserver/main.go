// Command labserver runs sakanner's Test Laboratory as a standalone,
// long-lived process, for manually driving `scanner` (or curl) against
// it during development. `go test ./lab/...` does NOT use this
// binary -- the test suite starts and stops the lab in-process, per
// test, via the lab package directly. This binary exists purely for
// interactive use (`make lab-up` / `make lab-down`).
//
// By default it starts only the Phase 2 lab (unchanged from before
// Phase 3 existed). Set LAB_PHASE3=1 to additionally start the Phase 3
// vulnerable/safe fixture pairs (see harness_vuln.go) -- this is opt-in
// so `make lab-up`'s existing behavior is untouched.
//
// It prints every service's resolved address on startup and blocks
// until SIGINT/SIGTERM.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"

	lab "sakanner/lab"
)

func main() {
	gt, err := lab.LoadGroundTruth()
	if err != nil {
		log.Fatalf("labserver: %v", err)
	}

	phase3 := os.Getenv("LAB_PHASE3") == "1"
	var l *lab.Lab
	if phase3 {
		l, err = lab.StartWithVulnerabilities(gt)
	} else {
		l, err = lab.Start(gt)
	}
	if err != nil {
		log.Fatalf("labserver: %v", err)
	}
	defer l.Close()

	if phase3 {
		fmt.Println("sakanner Test Laboratory is running (Phase 2 + Phase 3 fixtures).")
	} else {
		fmt.Println("sakanner Phase 2 Test Laboratory is running. (Set LAB_PHASE3=1 for Phase 3 vulnerable/safe fixtures too.)")
	}
	fmt.Println()
	hosts := make([]string, 0, len(gt.DNS))
	for h := range gt.DNS {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	ctx := context.Background()
	for _, host := range hosts {
		ips, err := l.Resolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			fmt.Printf("  %-24s (no address -- IPv6-unavailable sandbox?)\n", host)
			continue
		}
		fmt.Printf("  %-24s -> %s\n", host, ips[0])
	}
	if phase3 {
		fmt.Printf("  %-24s -> %s (Phase 3 vulnerable/safe fixtures)\n", "vuln.scanner.test", l.VulnAddr)
		fmt.Printf("  %-24s -> %s (SSRF-only target, see docs/phase-3-test-lab.md)\n", "ssrf-internal.scanner.test", l.SSRFInternalAddr)
	}
	fmt.Println()
	fmt.Println("These are dns.FakeResolver entries, not real DNS -- sakanner itself must")
	fmt.Println("be given this same resolver to reach them (see lab/lab_test.go);")
	fmt.Println("a plain curl/browser can instead dial the addresses printed above directly.")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("stopping...")
}
