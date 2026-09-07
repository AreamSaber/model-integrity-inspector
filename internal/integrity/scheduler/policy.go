package scheduler

import (
	"errors"
	"math"
	"math/big"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var ErrPolicy = errors.New("MI_EXECUTION_POLICY_INVALID")
var ErrOverflow = errors.New("MI_BUDGET_OVERFLOW")
var ErrUnknownPrice = errors.New("MI_PRICE_UNKNOWN")

// Policy can only be constructed from trusted server/admin limits. Apply clamps
// user requests; no exported field lets a JSON decoder construct authority.
type Policy struct{ limits domain.ExecutionLimits }

func DefaultLimits() domain.ExecutionLimits {
	return domain.ExecutionLimits{Global: 100, Organization: 20, Target: 3, Run: 3, TargetRPM: 30, MaxRequests: 1000, MaxTokens: 10_000_000, MaxCostMicros: 1_000_000_000, MaxDurationSeconds: 2700}
}

func NewPolicy(limits domain.ExecutionLimits) (Policy, error) {
	if limits.Global < 1 || limits.Global > 10000 || limits.Organization < 1 || limits.Organization > limits.Global || limits.Target < 1 || limits.Target > limits.Organization || limits.Run < 1 || limits.Run > limits.Target || limits.TargetRPM < 1 || limits.TargetRPM > 100000 || limits.MaxRequests < 1 || limits.MaxRequests > 100000 || limits.MaxTokens < 1 || limits.MaxTokens > 1_000_000_000_000 || limits.MaxCostMicros < 0 || limits.MaxCostMicros > math.MaxInt64/4 || limits.MaxDurationSeconds < 1 || limits.MaxDurationSeconds > 86400 {
		return Policy{}, ErrPolicy
	}
	return Policy{limits: limits}, nil
}

func (p Policy) Apply(plan domain.ExecutionPlan) (domain.ExecutionPlan, domain.ExecutionLimits, error) {
	if _, err := NewPolicy(p.limits); err != nil {
		return plan, domain.ExecutionLimits{}, err
	}
	if plan.Concurrency < 1 || plan.Budget.MaxRequests < 1 || plan.Budget.MaxTokens < 1 || plan.Budget.TimeoutSeconds < 1 || plan.MaxRetries < 0 || plan.MaxRetries > 2 {
		return plan, p.limits, ErrPolicy
	}
	plan.Concurrency = min(plan.Concurrency, p.limits.Run)
	plan.Budget.MaxRequests = min(plan.Budget.MaxRequests, p.limits.MaxRequests)
	plan.Budget.MaxTokens = min(plan.Budget.MaxTokens, p.limits.MaxTokens)
	plan.Budget.TimeoutSeconds = min(plan.Budget.TimeoutSeconds, p.limits.MaxDurationSeconds)
	if plan.Budget.MaxCostMicros != nil {
		if *plan.Budget.MaxCostMicros < 0 {
			return plan, p.limits, ErrPolicy
		}
		cost := min(*plan.Budget.MaxCostMicros, p.limits.MaxCostMicros)
		plan.Budget.MaxCostMicros = &cost
		if plan.Pricing.InputMicrosPerMillion == nil || plan.Pricing.OutputMicrosPerMillion == nil {
			return plan, p.limits, ErrUnknownPrice
		}
	}
	for _, price := range []*int64{plan.Pricing.InputMicrosPerMillion, plan.Pricing.OutputMicrosPerMillion} {
		if price != nil && *price < 0 {
			return plan, p.limits, ErrPolicy
		}
	}
	return plan, p.limits, nil
}

// Cost uses exact integer arithmetic and rounds each component upwards. Unknown
// price is nil (never a misleading zero); overflow is a hard failure.
func Cost(pricing domain.ExecutionPricing, input, output int64) (*int64, error) {
	if input < 0 || output < 0 {
		return nil, ErrPolicy
	}
	if pricing.InputMicrosPerMillion == nil || pricing.OutputMicrosPerMillion == nil {
		return nil, nil
	}
	total := new(big.Int)
	for i, price := range []*int64{pricing.InputMicrosPerMillion, pricing.OutputMicrosPerMillion} {
		if *price < 0 {
			return nil, ErrPolicy
		}
		tokens := input
		if i == 1 {
			tokens = output
		}
		component := new(big.Int).Mul(big.NewInt(tokens), big.NewInt(*price))
		component.Add(component, big.NewInt(999999)).Div(component, big.NewInt(1000000))
		total.Add(total, component)
	}
	if !total.IsInt64() {
		return nil, ErrOverflow
	}
	result := total.Int64()
	return &result, nil
}

func Add(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, ErrOverflow
	}
	return a + b, nil
}

// UncertainTokens charges ceil(1.25 * reservation), including a missing usage
// estimate. A recovery must never refund a possibly billed request.
func UncertainTokens(tokens int64) (int64, error) {
	if tokens < 0 || tokens > math.MaxInt64-3 {
		return 0, ErrOverflow
	}
	extra := (tokens + 3) / 4
	return Add(tokens, extra)
}

// RetryDelay is pure, bounded, and accepts explicit jitter (0..1000) so tests
// never sleep. Only the closed transient classification list is retryable.
func RetryDelay(code string, attempt, maxRetries int, retryAfterSeconds int64, jitter int) (time.Duration, bool) {
	if attempt < 1 || attempt > maxRetries || maxRetries > 2 || jitter < 0 || jitter > 1000 || retryAfterSeconds < 0 || retryAfterSeconds > 3600 {
		return 0, false
	}
	switch code {
	case "MI_NETWORK_TEMPORARY", "MI_CONNECTION_RESET", "MI_TIMEOUT", "MI_RATE_LIMITED", "MI_SERVICE_UNAVAILABLE":
	default:
		return 0, false
	}
	delay := time.Duration(1<<uint(attempt-1))*time.Second + time.Duration(jitter)*time.Millisecond
	if retryAfterSeconds > 0 {
		delay = max(delay, time.Duration(retryAfterSeconds)*time.Second)
	}
	return delay, true
}
