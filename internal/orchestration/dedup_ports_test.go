package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestRun_DuplicatePortsInListAreScannedOnce is a regression test for a
// real bug found during Phase 2 acceptance testing: a duplicate port
// number in the requested port list (an operator typo in --ports, or a
// custom list that happens to overlap the configured defaults) produced
// one Service/HTTPService row PER occurrence of that port, not one --
// the same port was redundantly scanned and probed multiple times.
func TestRun_DuplicatePortsInListAreScannedOnce(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	p, cleanup := newTestPipeline(t)
	defer cleanup()

	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port, port, port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	services, err := p.Store.Services().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Services().ListByScanJob: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("services = %+v, want exactly 1 (a port repeated 3x in the request must still scan once)", services)
	}

	httpServices, err := p.Store.HTTPServices().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("HTTPServices().ListByScanJob: %v", err)
	}
	if len(httpServices) != 1 {
		t.Fatalf("httpServices = %+v, want exactly 1", httpServices)
	}
}

func TestDedupInts(t *testing.T) {
	tests := []struct {
		in   []int
		want []int
	}{
		{nil, []int{}},
		{[]int{80}, []int{80}},
		{[]int{80, 80, 80}, []int{80}},
		{[]int{443, 80, 443, 8080, 80}, []int{443, 80, 8080}},
	}
	for _, tt := range tests {
		got := dedupInts(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("dedupInts(%v) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("dedupInts(%v) = %v, want %v", tt.in, got, tt.want)
				break
			}
		}
	}
}
