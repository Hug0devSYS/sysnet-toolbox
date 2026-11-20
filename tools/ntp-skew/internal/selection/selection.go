// Package selection implements the NTP clock selection (intersection)
// algorithm, a variant of Marzullo's algorithm, and the combine step that
// derives the ensemble offset.
//
// Every candidate is a correctness interval [offset - λ, offset + λ], λ
// being its root distance: the true time lies in it if the server is
// correct. The algorithm looks for the interval where the intervals of a
// majority of candidates overlap (allowing f falsetickers, with 2f < n),
// increasing f until such a majority exists. Candidates whose interval
// does not reach that intersection are falsetickers.
//
// This follows ntpd 4.2.8 (ntp_proto.c, clock_select) rather than the
// pseudo-code of RFC 5905 section 11.2.1: the RFC version also counts
// interval midpoints outside the intersection and rejects correct sources
// whenever their intervals are narrow, a known defect that ntpd dropped.
package selection

import (
	"math"
	"sort"
)

// Candidate is one usable source.
type Candidate struct {
	ID       int     // caller's identifier
	Offset   float64 // seconds, server minus local clock
	RootDist float64 // seconds, half-width of the correctness interval
}

// Result of the selection.
type Result struct {
	// OK is false when no majority of candidates agrees (no clique of
	// more than n/2 overlapping intervals): the true time cannot be
	// established.
	OK bool
	// Low and High bound the intersection interval (seconds).
	Low, High float64
	// Allowed is the number of falsetickers the final iteration tolerated.
	Allowed int
	// Truechimers and Falsetickers hold candidate IDs.
	Truechimers  []int
	Falsetickers []int
	// Offset is the combined offset of the truechimers, weighted by the
	// inverse of their root distance (RFC 5905 section 11.2.3).
	Offset float64
	// Spread is the largest offset difference between two truechimers.
	Spread float64
}

type edge struct {
	val  float64
	kind int // -1 lower bound, +1 upper bound
}

// Select runs the intersection algorithm over the candidates.
func Select(cands []Candidate) Result {
	n := len(cands)
	if n == 0 {
		return Result{}
	}
	edges := make([]edge, 0, 2*n)
	for _, c := range cands {
		rd := math.Abs(c.RootDist)
		edges = append(edges, edge{c.Offset - rd, -1}, edge{c.Offset + rd, +1})
	}
	// At equal values, lower bounds come first so that touching intervals
	// count as overlapping.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].val != edges[j].val {
			return edges[i].val < edges[j].val
		}
		return edges[i].kind < edges[j].kind
	})

	var res Result
	for allow := 0; 2*allow < n; allow++ {
		need := n - allow
		low, high := math.Inf(1), math.Inf(-1)
		chime := 0
		for _, e := range edges {
			chime -= e.kind
			if chime >= need {
				low = e.val
				break
			}
		}
		chime = 0
		for i := len(edges) - 1; i >= 0; i-- {
			chime += edges[i].kind
			if chime >= need {
				high = edges[i].val
				break
			}
		}
		if high >= low {
			res = Result{OK: true, Low: low, High: high, Allowed: allow}
			break
		}
	}
	if !res.OK {
		for _, c := range cands {
			res.Falsetickers = append(res.Falsetickers, c.ID)
		}
		return res
	}
	var wsum, osum float64
	minOff, maxOff := math.Inf(1), math.Inf(-1)
	for _, c := range cands {
		rd := math.Abs(c.RootDist)
		if c.Offset+rd < res.Low || c.Offset-rd > res.High {
			res.Falsetickers = append(res.Falsetickers, c.ID)
			continue
		}
		res.Truechimers = append(res.Truechimers, c.ID)
		w := 1 / math.Max(math.Abs(c.RootDist), 1e-9)
		wsum += w
		osum += w * c.Offset
		minOff = math.Min(minOff, c.Offset)
		maxOff = math.Max(maxOff, c.Offset)
	}
	if len(res.Truechimers) == 0 {
		// Cannot happen with a consistent intersection, but never report
		// success without a survivor.
		res.OK = false
		return res
	}
	res.Offset = osum / wsum
	res.Spread = maxOff - minOff
	return res
}
