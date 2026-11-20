// Package check turns raw NTP measurements into a verdict: per-server
// state, clock selection (truechimers and falsetickers), the local clock
// offset against the consensus, and configuration hazards visible from
// the outside (synchronisation loops, no upstream diversity, stale
// references, leap indicator disagreement).
package check

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/ntp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/selection"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/sources"
)

// Severity of a finding; the numeric value is the Nagios exit code.
type Severity int

// Severities.
const (
	OK       Severity = 0
	Warning  Severity = 1
	Critical Severity = 2
	Unknown  Severity = 3
)

func (s Severity) String() string {
	switch s {
	case OK:
		return "OK"
	case Warning:
		return "WARNING"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// MarshalText makes severities readable in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Worse returns the more severe of a and b. UNKNOWN ranks between WARNING
// and CRITICAL, as in most Nagios plugins: a confirmed critical problem
// wins over missing data.
func Worse(a, b Severity) Severity {
	rank := func(s Severity) int {
		switch s {
		case OK:
			return 0
		case Warning:
			return 1
		case Unknown:
			return 2
		default:
			return 3
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Server states.
const (
	StateTruechimer     = "truechimer"
	StateFalseticker    = "falseticker"
	StateUnreachable    = "unreachable"
	StateKoD            = "kiss-o-death"
	StateUnsynchronised = "unsynchronised"
	StateTooFar         = "too-far"
	StateBogus          = "bogus"
	StateUnresolved     = "unresolved"
	StateCandidate      = "candidate" // usable, selection not run
)

// localRefID is the refid of a server synchronised to its own local clock
// (chrony "local" directive, ntpd LOCAL(1) driver).
var localRefID = [4]byte{127, 127, 1, 1}

// Config holds the thresholds.
type Config struct {
	WarnOffset  time.Duration // |local offset vs consensus|
	CritOffset  time.Duration
	MaxSkew     time.Duration // per-server distance to consensus (0: off)
	MaxDistance time.Duration // root distance above which a source is not selectable
	MaxStratum  int           // 0: off
	MaxRefAge   time.Duration // 0: off
	MinSources  int           // CRITICAL when fewer usable sources
	// AllowCommonUpstream turns the "no upstream diversity" warning into a note.
	AllowCommonUpstream bool
	// LocalAddrs are this host's addresses (refid loop detection).
	LocalAddrs []netip.Addr
	Now        time.Time
}

// Input is one measured source.
type Input struct {
	Source sources.Source
	M      *ntp.Measurement
}

// Finding is one problem or observation.
type Finding struct {
	Severity Severity `json:"severity"`
	Server   string   `json:"server,omitempty"` // "name (address)" or empty for global findings
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

// Server is the per-source part of the report.
type Server struct {
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	Origin          string   `json:"origin,omitempty"`
	State           string   `json:"state"`
	Reachable       bool     `json:"reachable"`
	Sent            int      `json:"sent"`
	Received        int      `json:"received"`
	Stratum         int      `json:"stratum,omitempty"`
	RefID           string   `json:"refid,omitempty"`
	RefIDServer     string   `json:"refid_matches,omitempty"` // a measured server or "this host"
	Leap            int      `json:"leap,omitempty"`
	Version         int      `json:"version,omitempty"`
	Offset          *float64 `json:"offset_seconds,omitempty"` // server minus local clock
	OffsetConsensus *float64 `json:"offset_vs_consensus_seconds,omitempty"`
	Delay           *float64 `json:"delay_seconds,omitempty"`
	Jitter          *float64 `json:"jitter_seconds,omitempty"`
	RootDelay       *float64 `json:"root_delay_seconds,omitempty"`
	RootDispersion  *float64 `json:"root_dispersion_seconds,omitempty"`
	RootDistance    *float64 `json:"root_distance_seconds,omitempty"`
	RefAge          *float64 `json:"reference_age_seconds,omitempty"`
	Precision       *float64 `json:"precision_seconds,omitempty"`
	KissCode        string   `json:"kiss_code,omitempty"`
	Errors          []string `json:"errors,omitempty"`

	refid [4]byte
	addr  netip.Addr
	cand  bool
}

// Selection summarises the clock selection.
type Selection struct {
	Candidates   int      `json:"candidates"`
	Truechimers  int      `json:"truechimers"`
	Falsetickers int      `json:"falsetickers"`
	Majority     bool     `json:"majority"`
	Low          *float64 `json:"intersection_low_seconds,omitempty"`
	High         *float64 `json:"intersection_high_seconds,omitempty"`
	Offset       *float64 `json:"consensus_offset_seconds,omitempty"` // consensus minus local clock (server-minus-local convention)
	Spread       *float64 `json:"truechimer_spread_seconds,omitempty"`
}

// Report is the complete result.
type Report struct {
	Time      time.Time `json:"time"`
	Status    Severity  `json:"status"`
	Servers   []*Server `json:"servers"`
	Selection Selection `json:"selection"`
	Findings  []Finding `json:"findings"`
	Notes     []string  `json:"notes,omitempty"`
}

func fp(d time.Duration) *float64 { v := d.Seconds(); return &v }
func ff(v float64) *float64       { return &v }

// Unresolved records a spec whose name could not be resolved.
type Unresolved struct {
	Spec sources.Spec
	Err  error
}

// Analyse builds the report.
func Analyse(inputs []Input, unresolved []Unresolved, cfg Config) *Report {
	r := &Report{Time: cfg.Now.UTC(), Findings: []Finding{}}
	if cfg.MaxDistance <= 0 {
		cfg.MaxDistance = time.Duration(ntp.MaxDist * float64(time.Second))
	}
	add := func(sev Severity, srv *Server, code, format string, a ...any) {
		f := Finding{Severity: sev, Code: code, Message: fmt.Sprintf(format, a...)}
		if srv != nil {
			f.Server = srv.label()
		}
		r.Findings = append(r.Findings, f)
	}

	for _, u := range unresolved {
		s := &Server{Name: u.Spec.String(), Origin: u.Spec.Origin, State: StateUnresolved, Errors: []string{u.Err.Error()}}
		r.Servers = append(r.Servers, s)
		add(Warning, s, "unresolved", "cannot resolve: %v", u.Err)
	}

	var cands []selection.Candidate
	for _, in := range inputs {
		m := in.M
		s := &Server{
			Name: in.Source.Spec.Host, Address: in.Source.Addr.String(), Origin: in.Source.Spec.Origin,
			Sent: m.Sent, Received: m.Received, Errors: m.Errors, addr: in.Source.Addr.Addr(),
		}
		if in.Source.Addr.Port() == sources.DefaultPort {
			s.Address = in.Source.Addr.Addr().String()
		}
		r.Servers = append(r.Servers, s)
		s.Reachable = m.Received > 0
		if m.KoD != "" {
			s.State, s.KissCode = StateKoD, m.KoD
			switch m.KoD {
			case "RATE":
				add(Warning, s, "kod-rate", "rate limited by the server (kiss code RATE): use fewer --samples or a longer --interval")
			case "DENY", "RSTR":
				add(Warning, s, "kod-deny", "server refuses to serve this client (kiss code %s): access control", m.KoD)
			default:
				add(Warning, s, "kod", "kiss-o'-death %q", m.KoD)
			}
			if !m.Usable() {
				continue
			}
		}
		if !m.Usable() {
			if m.Unsync {
				s.State = StateUnsynchronised
				add(Warning, s, "unsynchronised", "%s: clients will not use it", strings.Join(m.Errors, "; "))
				continue
			}
			if m.Received > 0 {
				s.State = StateBogus
				add(Warning, s, "bogus", "only invalid answers: %s", strings.Join(m.Errors, "; "))
			} else {
				s.State = StateUnreachable
				msg := "no answer"
				if len(m.Errors) > 0 {
					msg = strings.Join(m.Errors, "; ")
				}
				add(Warning, s, "unreachable", "%s", msg)
			}
			continue
		}
		if m.Received < m.Sent && m.KoD == "" {
			r.Notes = append(r.Notes, fmt.Sprintf("%s: %d of %d requests answered (rate limiting or packet loss)", s.label(), m.Received, m.Sent))
		}
		b := m.Best
		p := b.Packet
		s.Stratum, s.Leap, s.Version = int(p.Stratum), int(p.Leap), int(p.Version)
		s.RefID, s.refid = p.RefIDString(), p.RefID
		s.Offset, s.Delay, s.Jitter = fp(b.Offset), fp(b.Delay), fp(m.Jitter)
		s.RootDelay = fp(ntp.ShortToDuration(p.RootDelay))
		s.RootDispersion = fp(ntp.ShortToDuration(p.RootDispersion))
		s.RootDistance = fp(m.RootDist)
		s.Precision = fp(ntp.PrecisionDuration(p.Precision))
		if p.RefTime != 0 {
			ref := ntp.NTPToTime(p.RefTime, b.T3)
			s.RefAge = fp(b.T3.Sub(ref))
		}
		if s.State == "" {
			s.State = StateCandidate
		}

		switch {
		case p.Leap == ntp.LeapUnknown || int(p.Stratum) >= ntp.MaxStratum:
			s.State = StateUnsynchronised
			add(Warning, s, "unsynchronised", "server is not synchronised (leap indicator %d, stratum %d): clients will not use it", p.Leap, p.Stratum)
			continue
		case m.RootDist > cfg.MaxDistance:
			s.State = StateTooFar
			add(Warning, s, "too-far", "root distance %s exceeds %s: not selectable (upstream too far or too unstable)", fmtDur(m.RootDist), fmtDur(cfg.MaxDistance))
			continue
		}
		if cfg.MaxStratum > 0 && int(p.Stratum) > cfg.MaxStratum {
			add(Warning, s, "stratum", "stratum %d is above --max-stratum %d", p.Stratum, cfg.MaxStratum)
		}
		if cfg.MaxRefAge > 0 && s.RefAge != nil && *s.RefAge > cfg.MaxRefAge.Seconds() {
			add(Warning, s, "stale-reference", "last update from its own source was %s ago (> %s): the server may be free-running", fmtDur(secs(*s.RefAge)), fmtDur(cfg.MaxRefAge))
		}
		if s.RefAge != nil && *s.RefAge < -1 {
			add(Warning, s, "reference-in-future", "reference timestamp is %s in the future of its own clock", fmtDur(secs(-*s.RefAge)))
		}
		if b.Inconsistent {
			add(Warning, s, "inconsistent-timestamps", "server processing time %s is longer than the round trip %s: its receive and transmit timestamps disagree (two clocks, broken timestamping, or a proxy rewriting one of them)",
				fmtDur(b.T3.Sub(b.T2)), fmtDur(b.T4.Sub(b.T1)))
		}
		if p.Stratum >= 2 && p.RefID == localRefID {
			add(Warning, s, "local-reference", "server is serving its own undisciplined local clock (refid 127.127.1.1: chrony 'local' or ntpd LOCAL driver): acceptable as a last resort, not as a time source")
		}
		s.cand = true
		cands = append(cands, selection.Candidate{ID: len(r.Servers) - 1, Offset: b.Offset.Seconds(), RootDist: m.RootDist.Seconds()})
	}

	// Clock selection.
	r.Selection.Candidates = len(cands)
	usable := len(cands)
	switch {
	case usable == 0:
		add(Unknown, nil, "no-source", "no usable NTP source")
	case usable < cfg.MinSources:
		add(Critical, nil, "min-sources", "%d usable source(s), at least %d required", usable, cfg.MinSources)
	}
	if usable > 0 && usable < 3 {
		r.Notes = append(r.Notes, fmt.Sprintf("only %d usable source(s): a falseticker can only be identified with at least 3 (with 2, a disagreement cannot be attributed)", usable))
	}
	if usable > 0 {
		sel := selection.Select(cands)
		r.Selection.Majority = sel.OK
		for _, id := range sel.Falsetickers {
			r.Servers[id].State = StateFalseticker
		}
		if !sel.OK {
			add(Critical, nil, "no-majority", "no majority of sources agrees on the time (%d candidates, no overlapping majority of correctness intervals)", usable)
		} else {
			r.Selection.Truechimers = len(sel.Truechimers)
			r.Selection.Falsetickers = len(sel.Falsetickers)
			r.Selection.Low, r.Selection.High = ff(sel.Low), ff(sel.High)
			r.Selection.Offset, r.Selection.Spread = ff(sel.Offset), ff(sel.Spread)
			for _, id := range sel.Truechimers {
				r.Servers[id].State = StateTruechimer
			}
			for _, srv := range r.Servers {
				if srv.cand {
					srv.OffsetConsensus = ff(*srv.Offset - sel.Offset)
				}
			}
			for _, id := range sel.Falsetickers {
				srv := r.Servers[id]
				add(Critical, srv, "falseticker", "falseticker: %s from the consensus; its correctness interval (+/- %s) does not overlap the one shared by the majority (%d of %d sources)",
					fmtSigned(secs(*srv.OffsetConsensus)), fmtDur(secs(*srv.RootDistance)), len(sel.Truechimers), usable)
			}
			if cfg.MaxSkew > 0 {
				for _, id := range sel.Truechimers {
					srv := r.Servers[id]
					if d := math.Abs(*srv.OffsetConsensus); d > cfg.MaxSkew.Seconds() {
						add(Warning, srv, "skew", "%s from the consensus (> --max-skew %s)", fmtSigned(secs(*srv.OffsetConsensus)), fmtDur(cfg.MaxSkew))
					}
				}
			}
			off := math.Abs(sel.Offset)
			msg := "local clock is %s from the consensus of %d source(s)"
			sign := fmtSigned(secs(-sel.Offset)) // local minus consensus
			switch {
			case cfg.CritOffset > 0 && off > cfg.CritOffset.Seconds():
				add(Critical, nil, "local-offset", msg+" (> %s)", sign, len(sel.Truechimers), fmtDur(cfg.CritOffset))
			case cfg.WarnOffset > 0 && off > cfg.WarnOffset.Seconds():
				add(Warning, nil, "local-offset", msg+" (> %s)", sign, len(sel.Truechimers), fmtDur(cfg.WarnOffset))
			}
		}
	}

	topology(r, cfg, add)
	leap(r, add)

	r.Status = OK
	for _, f := range r.Findings {
		r.Status = Worse(r.Status, f.Severity)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return rankSev(r.Findings[i].Severity) > rankSev(r.Findings[j].Severity) })
	return r
}

func rankSev(s Severity) int {
	switch s {
	case Critical:
		return 3
	case Unknown:
		return 2
	case Warning:
		return 1
	}
	return 0
}

// topology looks at who synchronises from whom through the refids.
func topology(r *Report, cfg Config, add func(Severity, *Server, string, string, ...any)) {
	byRef := map[[4]byte]*Server{}
	for _, s := range r.Servers {
		if s.addr.IsValid() {
			byRef[ntp.RefIDFor(s.addr)] = s
		}
	}
	local := map[[4]byte]bool{}
	for _, a := range cfg.LocalAddrs {
		if a.IsLoopback() {
			continue
		}
		local[ntp.RefIDFor(a)] = true
	}
	var synced []*Server
	for _, s := range r.Servers {
		if !s.cand || s.Stratum < 2 {
			continue
		}
		synced = append(synced, s)
		if up, ok := byRef[s.refid]; ok && up != s {
			s.RefIDServer = up.Name
		} else if local[s.refid] {
			s.RefIDServer = "this host"
			add(Warning, s, "sync-from-this-host", "server is synchronised to this host (refid %s): if this host also uses it, they form a loop", s.RefID)
		}
	}
	// Mutual synchronisation (A -> B -> A).
	reported := map[*Server]bool{}
	for _, a := range synced {
		b, ok := byRef[a.refid]
		if !ok || b == a || reported[a] || !b.cand || b.Stratum < 2 {
			continue
		}
		if b.refid == ntp.RefIDFor(a.addr) {
			reported[a], reported[b] = true, true
			add(Warning, nil, "sync-loop", "%s and %s are synchronised to each other (stratum %d and %d): a timing loop without an external reference", a.label(), b.label(), a.Stratum, b.Stratum)
		}
	}
	// Upstream diversity: every candidate behind the same upstream means
	// one bad upstream moves all of them together, undetectably.
	cands := 0
	for _, s := range r.Servers {
		if s.cand {
			cands++
		}
	}
	if cands >= 2 && len(synced) == cands && synced[0].refid != localRefID {
		first := synced[0].refid
		same := true
		for _, s := range synced[1:] {
			if s.refid != first {
				same = false
				break
			}
		}
		if same {
			name := synced[0].RefID
			if synced[0].RefIDServer != "" {
				name += " (" + synced[0].RefIDServer + ")"
			}
			msg := fmt.Sprintf("all %d sources are synchronised to the same upstream %s: a fault there shifts them together and cannot be detected as a falseticker", cands, name)
			if cfg.AllowCommonUpstream {
				r.Notes = append(r.Notes, msg)
			} else {
				add(Warning, nil, "common-upstream", "%s", msg)
			}
		}
	}
}

// leap compares the leap indicators of the synchronised sources.
func leap(r *Report, add func(Severity, *Server, string, string, ...any)) {
	counts := map[int][]string{}
	for _, s := range r.Servers {
		if s.cand {
			counts[s.Leap] = append(counts[s.Leap], s.label())
		}
	}
	if len(counts) > 1 {
		var parts []string
		for _, li := range []int{ntp.LeapNone, ntp.LeapAddSec, ntp.LeapDelSec} {
			if n := counts[li]; len(n) > 0 {
				parts = append(parts, fmt.Sprintf("%s: %s", leapName(li), strings.Join(n, ", ")))
			}
		}
		add(Warning, nil, "leap-disagreement", "sources disagree on the leap second warning (%s): a wrong leap file or a smearing server mixed with non-smearing ones", strings.Join(parts, "; "))
	} else if len(counts) == 1 {
		for li := range counts {
			if li != ntp.LeapNone {
				r.Notes = append(r.Notes, fmt.Sprintf("all sources announce a leap second (%s) at the end of the current month (UTC)", leapName(li)))
			}
		}
	}
}

func leapName(li int) string {
	switch li {
	case ntp.LeapAddSec:
		return "insert"
	case ntp.LeapDelSec:
		return "delete"
	default:
		return "none"
	}
}

func (s *Server) label() string {
	switch {
	case s.Address == "" || s.Address == s.Name:
		return s.Name
	default:
		return s.Name + " (" + s.Address + ")"
	}
}

// Label is the display name of a server.
func (s *Server) Label() string { return s.label() }

func secs(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

// fmtDur prints a duration with a unit suited to its magnitude.
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.1fm", d.Minutes())
	case d >= time.Second:
		return fmt.Sprintf("%.3fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.3fms", float64(d)/1e6)
	default:
		return fmt.Sprintf("%.1fus", float64(d)/1e3)
	}
}

// fmtSigned is fmtDur with an explicit sign.
func fmtSigned(d time.Duration) string {
	if d < 0 {
		return "-" + fmtDur(-d)
	}
	return "+" + fmtDur(d)
}

// FormatDuration and FormatSigned are exported for the renderers.
func FormatDuration(d time.Duration) string { return fmtDur(d) }

// FormatSigned prints a signed duration ("+1.234ms").
func FormatSigned(d time.Duration) string { return fmtSigned(d) }

// Seconds converts float seconds to a duration.
func Seconds(f float64) time.Duration { return secs(f) }
