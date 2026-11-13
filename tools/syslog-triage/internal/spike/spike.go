// Package spike finds bursts in per-interval message counts with a robust
// trailing baseline (median and median absolute deviation), so that a few
// earlier bursts or a quiet night do not distort the threshold.
package spike

import (
	"math"
	"sort"
)

// Params control detection.
type Params struct {
	// Window is the number of preceding non-spike buckets in the baseline.
	Window int
	// MinBaseline is the number of baseline buckets required before a
	// bucket is evaluated.
	MinBaseline int
	// K is the number of robust standard deviations above the median.
	K float64
	// MinCount is the minimum count of a spike bucket.
	MinCount int64
	// MinRatio is the minimum count / max(median, 1) ratio.
	MinRatio float64
}

// DefaultParams suit 5-minute buckets over a few hours to a few days.
func DefaultParams() Params {
	return Params{Window: 24, MinBaseline: 6, K: 5, MinCount: 10, MinRatio: 3}
}

// Spike is a run of consecutive anomalous buckets [Start, End].
type Spike struct {
	Start, End int
	Peak       int64
	PeakIndex  int
	Total      int64   // messages in the spike buckets
	Baseline   float64 // median of the baseline at the first spike bucket
	Threshold  float64 // count needed to be a spike at the first bucket
	// Sustained is set when the burst lasted a whole window: the new level
	// is then accepted as the baseline (level shift) and the spike closed.
	Sustained bool
}

// Ratio returns peak / max(baseline, 1).
func (s Spike) Ratio() float64 { return float64(s.Peak) / math.Max(s.Baseline, 1) }

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// Baseline returns the median and the robust sigma of values: the scaled
// MAD, floored by the Poisson standard deviation sqrt(median) and by 1, so
// that a flat series of zeros or of identical counts still needs a real
// jump to trigger.
func Baseline(values []float64) (med, sigma float64) {
	s := append([]float64(nil), values...)
	sort.Float64s(s)
	med = median(s)
	dev := make([]float64, len(s))
	for i, v := range s {
		dev[i] = math.Abs(v - med)
	}
	sort.Float64s(dev)
	mad := median(dev)
	sigma = math.Max(1.4826*mad, math.Max(math.Sqrt(med), 1))
	return med, sigma
}

// Detect returns the spikes of series.
func Detect(series []int64, p Params) []Spike {
	if p.Window < 1 {
		p.Window = 1
	}
	if p.MinBaseline < 1 {
		p.MinBaseline = 1
	}
	if p.MinBaseline > p.Window {
		p.MinBaseline = p.Window
	}
	var spikes []Spike
	history := make([]float64, 0, len(series)) // non-spike buckets
	var cur *Spike
	for i, v := range series {
		isSpike := false
		var med, thr float64
		if len(history) >= p.MinBaseline {
			base := history[max(0, len(history)-p.Window):]
			var sigma float64
			med, sigma = Baseline(base)
			thr = med + p.K*sigma
			isSpike = v >= p.MinCount && float64(v) > thr && float64(v) >= p.MinRatio*math.Max(med, 1)
		}
		if isSpike && cur != nil && i-cur.Start >= p.Window {
			// Level shift: stop excluding these buckets from the baseline.
			cur.Sustained = true
			for _, x := range series[cur.Start:i] {
				history = append(history, float64(x))
			}
			cur = nil
			isSpike = false
		}
		if isSpike {
			if cur == nil {
				spikes = append(spikes, Spike{Start: i, End: i, Peak: v, PeakIndex: i, Baseline: med, Threshold: thr})
				cur = &spikes[len(spikes)-1]
			}
			cur.End = i
			cur.Total += v
			if v > cur.Peak {
				cur.Peak, cur.PeakIndex = v, i
			}
			continue
		}
		cur = nil
		history = append(history, float64(v))
	}
	return spikes
}
