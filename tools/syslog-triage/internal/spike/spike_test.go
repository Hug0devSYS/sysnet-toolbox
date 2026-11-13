package spike

import (
	"math"
	"testing"
)

func flat(n int, v int64) []int64 {
	s := make([]int64, n)
	for i := range s {
		s[i] = v
	}
	return s
}

func TestBaseline(t *testing.T) {
	med, sigma := Baseline([]float64{10, 12, 11, 9, 10, 100})
	if med != 10.5 || sigma < math.Sqrt(10.5)-1e-9 {
		t.Fatalf("med %v sigma %v", med, sigma)
	}
	if med, sigma := Baseline([]float64{0, 0, 0}); med != 0 || sigma != 1 {
		t.Fatalf("zeros: %v %v", med, sigma)
	}
}

func TestDetectSingleBurst(t *testing.T) {
	s := flat(30, 10)
	s[20], s[21] = 200, 150
	sp := Detect(s, DefaultParams())
	if len(sp) != 1 {
		t.Fatalf("spikes: %+v", sp)
	}
	g := sp[0]
	if g.Start != 20 || g.End != 21 || g.Peak != 200 || g.PeakIndex != 20 || g.Total != 350 || g.Baseline != 10 || g.Sustained {
		t.Fatalf("%+v", g)
	}
	if g.Ratio() != 20 {
		t.Fatalf("ratio %v", g.Ratio())
	}
}

func TestNoSpikeOnNoise(t *testing.T) {
	// Poisson-like noise around 100 must not trigger.
	s := []int64{}
	for i := 0; i < 200; i++ {
		s = append(s, 100+int64((i*37)%21)-10)
	}
	if sp := Detect(s, DefaultParams()); len(sp) != 0 {
		t.Fatalf("false positives: %+v", sp)
	}
}

func TestMinCountAndRatio(t *testing.T) {
	s := flat(20, 0)
	s[15] = 9 // below MinCount
	if sp := Detect(s, DefaultParams()); len(sp) != 0 {
		t.Fatalf("below min count: %+v", sp)
	}
	s[15] = 10
	if sp := Detect(s, DefaultParams()); len(sp) != 1 {
		t.Fatalf("new burst from zero not detected: %+v", sp)
	}
	// Large absolute jump but small ratio: 1000 -> 2500 with MinRatio 3.
	s = flat(20, 1000)
	s[15] = 2500
	if sp := Detect(s, DefaultParams()); len(sp) != 0 {
		t.Fatalf("ratio below min: %+v", sp)
	}
	p := DefaultParams()
	p.MinRatio = 2
	if sp := Detect(s, p); len(sp) != 1 {
		t.Fatalf("ratio 2.5 with min 2: %+v", sp)
	}
}

func TestNotEvaluatedWithoutHistory(t *testing.T) {
	s := []int64{500, 0, 0, 0, 0, 0, 0, 0}
	if sp := Detect(s, DefaultParams()); len(sp) != 0 {
		t.Fatalf("first bucket evaluated: %+v", sp)
	}
}

func TestSpikesExcludedFromBaseline(t *testing.T) {
	s := flat(60, 5)
	for i := 30; i < 40; i++ {
		s[i] = 300
	}
	sp := Detect(s, DefaultParams())
	if len(sp) != 1 || sp[0].Start != 30 || sp[0].End != 39 {
		t.Fatalf("%+v", sp)
	}
}

func TestLevelShift(t *testing.T) {
	p := DefaultParams()
	p.Window = 10
	s := flat(60, 5)
	for i := 20; i < 60; i++ {
		s[i] = 300
	}
	sp := Detect(s, p)
	if len(sp) != 1 || !sp[0].Sustained || sp[0].Start != 20 || sp[0].End != 29 {
		t.Fatalf("%+v", sp)
	}
}

func TestDegenerateParams(t *testing.T) {
	s := []int64{1, 1, 1, 50}
	sp := Detect(s, Params{Window: 0, MinBaseline: 5, K: 3, MinCount: 1, MinRatio: 1})
	if len(sp) != 1 || sp[0].Start != 3 {
		t.Fatalf("%+v", sp)
	}
	if len(Detect(nil, DefaultParams())) != 0 {
		t.Fatal("nil series")
	}
}
