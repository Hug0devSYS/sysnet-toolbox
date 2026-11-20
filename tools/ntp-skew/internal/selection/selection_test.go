package selection

import (
	"math"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

func ids(v []int) []int {
	out := append([]int(nil), v...)
	sort.Ints(out)
	return out
}

func TestSelectBasic(t *testing.T) {
	cases := []struct {
		name   string
		cands  []Candidate
		ok     bool
		true_  []int
		false_ []int
	}{
		{"single", []Candidate{{1, 0.5, 0.01}}, true, []int{1}, nil},
		{"agree", []Candidate{{1, 0.001, 0.01}, {2, -0.002, 0.01}, {3, 0.0, 0.02}}, true, []int{1, 2, 3}, nil},
		{"one falseticker", []Candidate{{1, 0.001, 0.01}, {2, -0.002, 0.01}, {3, 0.0, 0.02}, {4, 0.8, 0.01}}, true, []int{1, 2, 3}, []int{4}},
		{"two of five", []Candidate{{1, 0, 0.01}, {2, 0.003, 0.01}, {3, -0.003, 0.01}, {4, 2, 0.01}, {5, -2, 0.01}}, true, []int{1, 2, 3}, []int{4, 5}},
		{"two disagree", []Candidate{{1, 0, 0.01}, {2, 1, 0.01}}, false, nil, []int{1, 2}},
		{"no majority", []Candidate{{1, 0, 0.01}, {2, 1, 0.01}, {3, 2, 0.01}}, false, nil, []int{1, 2, 3}},
		{"two-two split", []Candidate{{1, 0, 0.01}, {2, 0.001, 0.01}, {3, 1, 0.01}, {4, 1.001, 0.01}}, false, nil, []int{1, 2, 3, 4}},
		{"touching intervals", []Candidate{{1, 0, 0.5}, {2, 1, 0.5}, {3, 0.5, 0.01}}, true, []int{1, 2, 3}, nil},
		// A wide interval reaching the intersection is not a falseticker
		// (it gets little weight in the combined offset).
		{"wide interval", []Candidate{{1, 0, 0.01}, {2, 0.001, 0.01}, {3, 0.9, 1.0}}, true, []int{1, 2, 3}, nil},
		// The narrow-interval case the RFC 5905 pseudo-code gets wrong:
		// three correct sources whose midpoints fall outside the common
		// overlap must all survive.
		{"narrow correct", []Candidate{{1, -0.009, 0.01}, {2, 0.009, 0.01}, {3, 0.0, 0.0015}, {4, 5, 0.01}}, true, []int{1, 2, 3}, []int{4}},
	}
	for _, tc := range cases {
		r := Select(tc.cands)
		if r.OK != tc.ok {
			t.Errorf("%s: ok=%v want %v (%+v)", tc.name, r.OK, tc.ok, r)
			continue
		}
		if !reflect.DeepEqual(ids(r.Truechimers), ids(tc.true_)) && !(len(r.Truechimers) == 0 && len(tc.true_) == 0) {
			t.Errorf("%s: truechimers %v want %v", tc.name, r.Truechimers, tc.true_)
		}
		if !reflect.DeepEqual(ids(r.Falsetickers), ids(tc.false_)) && !(len(r.Falsetickers) == 0 && len(tc.false_) == 0) {
			t.Errorf("%s: falsetickers %v want %v", tc.name, r.Falsetickers, tc.false_)
		}
		if r.OK && (r.Low > r.High) {
			t.Errorf("%s: empty intersection [%v,%v]", tc.name, r.Low, r.High)
		}
	}
	if r := Select(nil); r.OK {
		t.Fatal("empty input selected")
	}
}

func TestCombineWeighted(t *testing.T) {
	r := Select([]Candidate{{1, 0.010, 0.01}, {2, 0.000, 0.04}})
	if !r.OK {
		t.Fatal("not ok")
	}
	// Weights 100 and 25: (100*0.010 + 25*0)/125 = 0.008.
	if math.Abs(r.Offset-0.008) > 1e-12 {
		t.Fatalf("combined offset %v", r.Offset)
	}
	if math.Abs(r.Spread-0.010) > 1e-12 {
		t.Fatalf("spread %v", r.Spread)
	}
}

// Property: with a strict majority of correct sources (true time 0 inside
// their intervals) and liars far away, every liar is a falseticker, no
// correct source is, and the intersection contains the true time.
func TestSelectProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 2000; iter++ {
		good := 1 + rng.Intn(7)
		bad := rng.Intn(good) // bad < good: strict majority
		var cands []Candidate
		for i := 0; i < good; i++ {
			rd := 0.001 + rng.Float64()*0.05
			cands = append(cands, Candidate{ID: i, Offset: (rng.Float64()*2 - 1) * rd * 0.9, RootDist: rd})
		}
		for i := 0; i < bad; i++ {
			sign := 1.0
			if rng.Intn(2) == 0 {
				sign = -1
			}
			// Liars disagree with each other too.
			cands = append(cands, Candidate{ID: 100 + i, Offset: sign * (1 + float64(i)*3 + rng.Float64()), RootDist: 0.01 + rng.Float64()*0.05})
		}
		rng.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
		r := Select(cands)
		if !r.OK {
			t.Fatalf("iter %d: no majority with %d good / %d bad: %+v", iter, good, bad, cands)
		}
		if r.Low > 0 || r.High < 0 {
			t.Fatalf("iter %d: true time outside [%v,%v]", iter, r.Low, r.High)
		}
		for _, id := range r.Falsetickers {
			if id < 100 {
				t.Fatalf("iter %d: correct source %d rejected", iter, id)
			}
		}
		for _, id := range r.Truechimers {
			if id >= 100 {
				t.Fatalf("iter %d: liar %d accepted", iter, id)
			}
		}
		if len(r.Falsetickers) < bad {
			t.Fatalf("iter %d: %d falsetickers for %d liars", iter, len(r.Falsetickers), bad)
		}
	}
}
