package scheduler

import (
	"errors"
	"math"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestPolicyCannotRaiseAdminLimits(t *testing.T) {
	limits := DefaultLimits()
	policy, err := NewPolicy(limits)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.ExecutionPlan{Concurrency: 100, MaxRetries: 2, Budget: domain.ExecutionBudget{MaxRequests: 100000, MaxTokens: 1_000_000_000, TimeoutSeconds: 999999}}
	clamped, got, err := policy.Apply(plan)
	if err != nil || clamped.Concurrency != 3 || clamped.Budget.MaxRequests != limits.MaxRequests || clamped.Budget.MaxTokens != limits.MaxTokens || clamped.Budget.TimeoutSeconds != 2700 || got != limits {
		t.Fatal("admin bound not enforced")
	}
	if _, _, err := (Policy{}).Apply(plan); !errors.Is(err, ErrPolicy) {
		t.Fatal("zero policy was trusted")
	}
	zero := int64(0)
	plan.Budget.MaxCostMicros = &zero
	if _, _, err := policy.Apply(plan); !errors.Is(err, ErrUnknownPrice) {
		t.Fatal("unknown pricing treated as free")
	}
	limits.Target = limits.Organization + 1
	if _, err := NewPolicy(limits); !errors.Is(err, ErrPolicy) {
		t.Fatal("invalid hierarchy")
	}
}

func TestExactCostsOverflowAndConservativeEstimates(t *testing.T) {
	price := int64(1)
	pricing := domain.ExecutionPricing{InputMicrosPerMillion: &price, OutputMicrosPerMillion: &price}
	cost, err := Cost(pricing, 1, 1)
	if err != nil || cost == nil || *cost != 2 {
		t.Fatal("fractional costs not rounded up independently")
	}
	if cost, err := Cost(domain.ExecutionPricing{}, 100, 100); err != nil || cost != nil {
		t.Fatal("unknown cost must remain nil")
	}
	price = math.MaxInt64
	if _, err := Cost(pricing, math.MaxInt64, math.MaxInt64); !errors.Is(err, ErrOverflow) {
		t.Fatal("cost overflow")
	}
	if _, err := Add(math.MaxInt64, 1); !errors.Is(err, ErrOverflow) {
		t.Fatal("counter overflow")
	}
	if _, err := UncertainTokens(math.MaxInt64); !errors.Is(err, ErrOverflow) {
		t.Fatal("uncertain overflow")
	}
	for n, want := range map[int64]int64{0: 0, 1: 2, 4: 5, 100: 125} {
		got, err := UncertainTokens(n)
		if err != nil || got != want {
			t.Fatal("uncertainty factor")
		}
	}
}

func TestRetryPolicyClosedAndBounded(t *testing.T) {
	for _, code := range []string{"MI_NETWORK_TEMPORARY", "MI_CONNECTION_RESET", "MI_TIMEOUT", "MI_RATE_LIMITED", "MI_SERVICE_UNAVAILABLE"} {
		delay, ok := RetryDelay(code, 1, 2, 10, 1000)
		if !ok || delay != 10*time.Second {
			t.Fatal("retry-after not honored")
		}
		if _, ok := RetryDelay(code, 3, 2, 0, 0); ok {
			t.Fatal("third retry accepted")
		}
	}
	for _, code := range []string{"MI_AUTH_FAILED", "MI_MODEL_NOT_FOUND", "MI_PROTOCOL_UNSUPPORTED", "MI_CLIENT_SAFETY_LIMIT", "MI_SAFETY_REFUSAL", "MI_UNCERTAIN_ATTEMPT", "HTTP_409", "body: secret"} {
		if _, ok := RetryDelay(code, 1, 2, 0, 0); ok {
			t.Fatal("unsafe retry")
		}
	}
	if _, ok := RetryDelay("MI_RATE_LIMITED", 1, 2, 3601, 0); ok {
		t.Fatal("unbounded delay")
	}
}
