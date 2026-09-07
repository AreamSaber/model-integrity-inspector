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

func TestPolicyKnownPricesAlwaysFreezeMonetaryCeiling(t *testing.T) {
	price := int64(123)
	for _, ceiling := range []int64{0, 2000000, 1000000000} {
		limits := DefaultLimits()
		limits.MaxCostMicros = ceiling
		policy, err := NewPolicy(limits)
		if err != nil {
			t.Fatal(err)
		}
		for _, requested := range []*int64{nil, new(int64), &price} {
			plan := domain.ExecutionPlan{Concurrency: 1, Budget: domain.ExecutionBudget{MaxRequests: 10, MaxTokens: 10000, TimeoutSeconds: 60, MaxCostMicros: requested}, Pricing: domain.ExecutionPricing{InputMicrosPerMillion: &price, OutputMicrosPerMillion: &price}}
			got, _, err := policy.Apply(plan)
			want := ceiling
			if requested != nil {
				want = min(want, *requested)
			}
			if err != nil || got.Budget.MaxCostMicros == nil || *got.Budget.MaxCostMicros != want {
				t.Fatalf("ceiling=%d not enforced: %v", ceiling, err)
			}
			if requested != nil && got.Budget.MaxCostMicros == requested {
				t.Fatal("frozen budget aliases caller pointer")
			}
			again, _, err := policy.Apply(got)
			if err != nil || *again.Budget.MaxCostMicros != want {
				t.Fatal("frozen policy application not idempotent")
			}
		}
	}
}

func TestPolicyUnknownAndOneSidedPricesCannotClaimMonetaryBudget(t *testing.T) {
	price, negative := int64(0), int64(-1)
	policy, err := NewPolicy(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, pricing := range []domain.ExecutionPricing{{}, {InputMicrosPerMillion: &price}, {OutputMicrosPerMillion: &price}} {
		plan := domain.ExecutionPlan{Concurrency: 1, Budget: domain.ExecutionBudget{MaxRequests: 10, MaxTokens: 1000, TimeoutSeconds: 60}, Pricing: pricing}
		got, _, err := policy.Apply(plan)
		if err != nil || got.Budget.MaxCostMicros != nil {
			t.Fatal("unknown price fabricated a monetary guarantee")
		}
		plan.Budget.MaxCostMicros = &price
		if _, _, err := policy.Apply(plan); !errors.Is(err, ErrUnknownPrice) {
			t.Fatal("explicit zero money with unknown pricing accepted")
		}
	}
	plan := domain.ExecutionPlan{Concurrency: 1, Budget: domain.ExecutionBudget{MaxRequests: 1, MaxTokens: 1, TimeoutSeconds: 1}, Pricing: domain.ExecutionPricing{InputMicrosPerMillion: &negative, OutputMicrosPerMillion: &price}}
	if _, _, err := policy.Apply(plan); !errors.Is(err, ErrPolicy) {
		t.Fatal("negative price accepted")
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
