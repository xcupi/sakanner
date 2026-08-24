package orchestrator

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/scope"
	"sakanner/internal/target"
	"sakanner/pkg/models"
)

func parseIPStrict(s string) net.IP {
	return net.ParseIP(s)
}

// resolveAndRegisterTarget implements task section 5 (target
// validation, reusing internal/target.Parse -- "do not expand target
// parsing unnecessarily") and task section 6 (scope enforcement,
// reusing internal/scope.Validator against the CURRENT rule snapshot --
// "any scope bypass is an automatic PHASE 3.11 FAIL"). It is a fast
// pre-flight check performed BEFORE the far more expensive
// orchestration.Pipeline.Run call; Pipeline.Run performs its own,
// authoritative scope check internally regardless (see pipeline.go),
// so this is defense-in-depth, never a replacement for it.
//
// On success, a fresh models.Target row is persisted (every scan gets
// its own Target row, matching `scanner target add`'s own existing
// always-create convention -- see cmd/scanner/target.go) and its ID
// returned for orchestration.RunOptions.TargetIDs.
func (o *Orchestrator) resolveAndRegisterTarget(ctx context.Context, raw string) (models.Target, error) {
	value, typ, err := target.Parse(raw)
	if err != nil {
		return models.Target{}, fmt.Errorf("orchestrator: invalid target %q: %w", raw, err)
	}

	rules, err := o.Store.ScopeRules().List(ctx)
	if err != nil {
		return models.Target{}, fmt.Errorf("orchestrator: loading scope rules: %w", err)
	}
	validator := scope.NewValidator(rules, o.allowReservedRanges())

	var decision scope.Decision
	switch typ {
	case models.TargetTypeIP:
		ip := parseIPStrict(value)
		if ip == nil {
			return models.Target{}, fmt.Errorf("orchestrator: target %q classified as IP but did not parse", raw)
		}
		decision, err = validator.CheckIP(ctx, ip)
	default:
		decision, err = validator.CheckHost(ctx, value)
	}
	if err != nil {
		return models.Target{}, fmt.Errorf("orchestrator: scope check for target %q: %w", raw, err)
	}
	if !decision.Allowed {
		return models.Target{}, fmt.Errorf("orchestrator: target %q is out of scope: %s", raw, decision.Reason)
	}

	t := models.Target{ID: uuid.NewString(), Value: value, Type: typ, Note: "orchestrator", CreatedAt: time.Now().UTC()}
	if err := o.Store.Targets().Create(ctx, t); err != nil {
		return models.Target{}, fmt.Errorf("orchestrator: registering target: %w", err)
	}
	return t, nil
}

func (o *Orchestrator) allowReservedRanges() bool {
	if o.Pipeline == nil {
		return false
	}
	return o.Pipeline.AllowReservedRanges
}
