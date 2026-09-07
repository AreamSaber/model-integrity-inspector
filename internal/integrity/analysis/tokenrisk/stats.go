package tokenrisk

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"slices"
	"sort"
)

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copy := slices.Clone(values)
	sort.Float64s(copy)
	n := len(copy)
	if n%2 == 1 {
		return copy[n/2]
	}
	return copy[n/2-1]/2 + copy[n/2]/2
}
func mad(values []float64) float64 {
	m := median(values)
	deviations := make([]float64, len(values))
	for i, value := range values {
		deviations[i] = math.Abs(value - m)
	}
	return median(deviations)
}
func robustCV(values []float64) float64 { return 1.4826 * mad(values) / math.Max(median(values), 1) }

type deterministicRandom struct {
	key     [32]byte
	counter uint64
}

func (r *deterministicRandom) index(n int) int {
	// All production callers pass the validated number of logical samples.
	// Keep conversions bounded even when this private helper is tested alone.
	if n < 1 || n > MaxSamples {
		return 0
	}
	var input [40]byte
	copy(input[:32], r.key[:])
	// Rejection avoids modulo bias; SHA is for reproducibility, not security
	// randomness or a confidence guarantee. No global RNG is changed.
	limit := uint64(math.MaxUint64) - uint64(math.MaxUint64)%uint64(n)
	for {
		binary.BigEndian.PutUint64(input[32:], r.counter)
		r.counter++
		sum := sha256.Sum256(input[:])
		value := binary.BigEndian.Uint64(sum[:8])
		if value < limit {
			index := value % uint64(n)
			if index >= MaxSamples {
				return 0
			}
			return int(index)
		}
	}
}
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := p * float64(len(sorted)-1)
	left := int(math.Floor(index))
	right := int(math.Ceil(index))
	return sorted[left] + (sorted[right]-sorted[left])*(index-float64(left))
}

// bootstrap resamples independent blocks. A paired block contributes both
// arms jointly; missing paired blocks are not silently turned into unpaired
// observations. Every caller sorts identifiers before deriving these blocks.
func bootstrap(left, right [][]float64, paired bool, key string) Interval {
	return builtinEngine().bootstrap(left, right, paired, key)
}
func (e *Engine) bootstrap(left, right [][]float64, paired bool, key string) Interval {
	result := Interval{Paired: paired, Units: min(len(left), len(right)), Replicates: e.rules.BootstrapReplicates, Method: "exploratory_percentile_cluster_bootstrap"}
	if len(left) < e.rules.MinBootstrapGroups || len(right) < e.rules.MinBootstrapGroups || (paired && len(left) != len(right)) {
		return result
	}
	// The RNG domain identifies the installed algorithm, not the candidate's
	// display/version label. Renaming unchanged rules must not select a new CI.
	random := deterministicRandom{key: sha256.Sum256([]byte(Version + "/bootstrap/" + key))}
	values := make([]float64, result.Replicates)
	for i := range values {
		l, r := []float64{}, []float64{}
		for range left {
			index := random.index(len(left))
			l = append(l, left[index]...)
			if paired {
				r = append(r, right[index]...)
			}
		}
		if !paired {
			for range right {
				r = append(r, right[random.index(len(right))]...)
			}
		}
		values[i] = median(r) - median(l)
	}
	sort.Float64s(values)
	result.Lower = percentile(values, e.rules.Alpha/2)
	result.Upper = percentile(values, 1-e.rules.Alpha/2)
	result.Available = true
	return result
}

func bounded(value float64) float64 { return math.Max(0, math.Min(100, value)) }
func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
