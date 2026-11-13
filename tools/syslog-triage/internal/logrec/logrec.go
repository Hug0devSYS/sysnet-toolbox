// Package logrec parses syslog and journald records: RFC 3164 (BSD) lines
// with or without a PRI part, RFC 3339 "high precision" lines written by
// rsyslog/syslog-ng and journalctl -o short-iso, RFC 5424 lines, Cisco
// IOS/NX-OS messages (%FAC-SEV-MNEMONIC) and journalctl -o json exports.
package logrec

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Format identifies how a record was parsed.
type Format string

// Record formats.
const (
	FormatRFC3164 Format = "rfc3164"
	FormatRFC3339 Format = "rfc3339"
	FormatRFC5424 Format = "rfc5424"
	FormatCisco   Format = "cisco"
	FormatJournal Format = "journal"
	FormatRaw     Format = "raw"
)

// SeverityUnknown marks a record without severity information.
const SeverityUnknown = -1

// SeverityNames are the RFC 5424 severity keywords, indexed by value.
var SeverityNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// SeverityName returns the keyword of a severity value ("-" when unknown).
func SeverityName(s int) string {
	if s < 0 || s > 7 {
		return "-"
	}
	return SeverityNames[s]
}

// ParseSeverity accepts a keyword (with common aliases) or a digit 0-7.
func ParseSeverity(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) == 1 && s[0] >= '0' && s[0] <= '7' {
		return int(s[0] - '0'), true
	}
	switch s {
	case "emerg", "emergency", "panic":
		return 0, true
	case "alert":
		return 1, true
	case "crit", "critical":
		return 2, true
	case "err", "error":
		return 3, true
	case "warning", "warn":
		return 4, true
	case "notice":
		return 5, true
	case "info", "informational":
		return 6, true
	case "debug":
		return 7, true
	}
	return 0, false
}

// Record is one parsed log message.
type Record struct {
	Time     time.Time // zero when the line has no usable timestamp
	Host     string
	App      string // program / syslog tag / Cisco facility-mnemonic; "-" when unknown
	PID      string
	Severity int // 0-7 or SeverityUnknown
	Facility int // 0-23 or -1
	Message  string
	Format   Format
}

// Parser converts lines into records.
type Parser struct {
	// Location is used for timestamps without a time zone (RFC 3164).
	Location *time.Location
	// Ref is the reference time used to infer the year of RFC 3164
	// timestamps: the year of Ref, or the previous year when the result
	// would be more than a week after Ref (logs spanning New Year).
	Ref time.Time
	// Year forces the year of RFC 3164 timestamps when non-zero.
	Year int
	// Raw disables header parsing: every line is a message.
	Raw bool
}

// Parse parses one line. ok is false when no syslog/journal header was
// recognised; the record then holds the line as a raw message.
func (p *Parser) Parse(line string) (rec Record, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	if !utf8.ValidString(line) {
		line = strings.ToValidUTF8(line, "\uFFFD")
	}
	if !p.Raw {
		if strings.HasPrefix(line, "{") {
			if r, ok := parseJournal(line); ok {
				return r, true
			}
		} else if r, ok := p.parseSyslog(line); ok {
			return r, true
		}
	}
	return Record{App: "-", Severity: SeverityUnknown, Facility: -1, Message: line, Format: FormatRaw}, false
}

func (p *Parser) loc() *time.Location {
	if p.Location != nil {
		return p.Location
	}
	return time.Local
}

// parsePRI parses "<N>" (0-191) at the start of s.
func parsePRI(s string) (pri int, rest string, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, s, false
	}
	end := strings.IndexByte(s[:min(len(s), 5)], '>')
	if end < 2 {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[1:end])
	if err != nil || n < 0 || n > 191 {
		return 0, s, false
	}
	return n, s[end+1:], true
}

var ciscoRe = regexp.MustCompile(`^(?:\d+: )?(?:[\w.\-]+: )?[*.]?(?:(\w{3} +\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2})(?:\.\d+)?(?: [A-Za-z]{2,5}[+\-]?\d{0,2})?: )?%([A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)?)-([0-7])-([A-Z0-9_]+): ?(.*)$`)

func (p *Parser) parseSyslog(line string) (Record, bool) {
	rec := Record{Severity: SeverityUnknown, Facility: -1, App: "-"}
	pri, rest, hasPRI := parsePRI(line)
	if hasPRI {
		rec.Facility, rec.Severity = pri/8, pri%8
		if strings.HasPrefix(rest, "1 ") {
			if r, ok := p.parse5424(rest[2:], rec); ok {
				return r, true
			}
		}
	}
	// Timestamp: RFC 3339 or BSD "Mmm dd hh:mm:ss".
	var ts time.Time
	var after string
	if t, r, ok := cutRFC3339(rest); ok {
		ts, after, rec.Format = t, r, FormatRFC3339
	} else if t, r, ok := p.cutBSD(rest); ok {
		ts, after, rec.Format = t, r, FormatRFC3164
	} else {
		// Cisco messages sent without a standard header
		// ("<189>123: *Mar  1 00:01:02.345: %LINK-3-UPDOWN: ...").
		if r, ok := p.parseCisco(rest, rec, time.Time{}); ok {
			return r, true
		}
		return rec, false
	}
	rec.Time = ts
	parseHostTag(after, &rec)
	if rec.App == "-" || isDigits(rec.App) || strings.HasPrefix(rec.App, "%") {
		body := rec.Message
		if strings.HasPrefix(rec.App, "%") {
			body = rec.App + ": " + rec.Message
		}
		if r, ok := p.parseCisco(body, rec, ts); ok {
			return r, true
		}
	}
	return rec, true
}

// parseHostTag splits "host tag[pid]: message" (host optional).
func parseHostTag(s string, rec *Record) {
	host, rest, found := strings.Cut(s, " ")
	if !found {
		rec.Message = s
		return
	}
	if looksLikeTag(host) {
		// No hostname ("<34>Oct 11 22:14:15 su: 'su root' failed").
		rest = s
	} else {
		rec.Host = host
	}
	tagTok, msg, found := strings.Cut(rest, " ")
	if !found {
		tagTok, msg = rest, ""
	}
	if looksLikeTag(tagTok) {
		tag := strings.TrimSuffix(tagTok, ":")
		if i := strings.IndexByte(tag, '['); i > 0 && strings.HasSuffix(tag, "]") {
			rec.PID = tag[i+1 : len(tag)-1]
			tag = tag[:i]
		}
		rec.App = tag
		rec.Message = msg
		return
	}
	rec.Message = rest
}

// looksLikeTag reports whether tok is "name:" or "name[pid]:".
func looksLikeTag(tok string) bool {
	if len(tok) < 2 || len(tok) > 64 || !strings.HasSuffix(tok, ":") {
		return false
	}
	t := tok[:len(tok)-1]
	if i := strings.IndexByte(t, '['); i >= 0 {
		if i == 0 || !strings.HasSuffix(t, "]") {
			return false
		}
		t = t[:i]
	}
	if t == "" || strings.ContainsAny(t, "[]{}\"'") {
		return false
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *Parser) parseCisco(s string, base Record, ts time.Time) (Record, bool) {
	if !strings.Contains(s, "%") {
		return base, false
	}
	m := ciscoRe.FindStringSubmatch(s)
	if m == nil {
		return base, false
	}
	rec := base
	rec.Format = FormatCisco
	rec.App = "%" + m[2] + "-" + m[4]
	rec.PID = ""
	rec.Severity = int(m[3][0] - '0')
	rec.Message = m[5]
	if ts.IsZero() && m[1] != "" {
		if t, ok := p.bsdTime(strings.Join(strings.Fields(m[1]), " ")); ok {
			ts = t
		}
	}
	rec.Time = ts
	return rec, true
}

func cutRFC3339(s string) (time.Time, string, bool) {
	tok, rest, _ := strings.Cut(s, " ")
	if len(tok) < 20 || tok[4] != '-' || tok[10] != 'T' {
		return time.Time{}, s, false
	}
	t, err := time.Parse(time.RFC3339Nano, tok)
	if err != nil {
		// journalctl -o short-iso writes "+0100" without a colon.
		t, err = time.Parse("2006-01-02T15:04:05.999999999-0700", tok)
		if err != nil {
			return time.Time{}, s, false
		}
	}
	return t, rest, true
}

var months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

// cutBSD parses "Mmm dd hh:mm:ss" (day space- or zero-padded) at the start
// of s, optionally followed by fractional seconds.
func (p *Parser) cutBSD(s string) (time.Time, string, bool) {
	if len(s) < 15 {
		return time.Time{}, s, false
	}
	if _, ok := months[s[:3]]; !ok || s[3] != ' ' {
		return time.Time{}, s, false
	}
	stamp := s[:15]
	if stamp[4] == ' ' {
		stamp = stamp[:4] + "0" + stamp[5:]
	}
	t, ok := p.bsdTime(stamp)
	if !ok {
		return time.Time{}, s, false
	}
	rest := s[15:]
	if strings.HasPrefix(rest, ".") {
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if frac, err := strconv.ParseFloat("0"+rest[:i], 64); err == nil && i > 1 {
			t = t.Add(time.Duration(frac * float64(time.Second)))
		}
		rest = rest[i:]
	}
	return t, strings.TrimLeft(rest, " "), true
}

// bsdTime parses "Mmm dd hh:mm:ss" or "Mmm dd yyyy hh:mm:ss" and infers the
// year when it is missing.
func (p *Parser) bsdTime(stamp string) (time.Time, bool) {
	if t, err := time.ParseInLocation("Jan 2 2006 15:04:05", stamp, p.loc()); err == nil {
		return t, true
	}
	f := strings.Fields(stamp)
	if len(f) != 3 {
		return time.Time{}, false
	}
	stamp = strings.Join(f, " ")
	year := p.Year
	ref := p.Ref
	if ref.IsZero() {
		ref = time.Now()
	}
	if year == 0 {
		year = ref.In(p.loc()).Year()
	}
	t, err := time.ParseInLocation("Jan 2 2006 15:04:05", f[0]+" "+f[1]+" "+strconv.Itoa(year)+" "+f[2], p.loc())
	if err != nil {
		return time.Time{}, false
	}
	if p.Year == 0 && t.After(ref.Add(7*24*time.Hour)) {
		t = t.AddDate(-1, 0, 0)
		// Feb 29 of a leap year seen from the following year.
		if t.Month() != months[f[0]] {
			return time.Time{}, false
		}
	}
	return t, true
}

// parse5424 parses "TIMESTAMP HOST APP PROCID MSGID SD [MSG]".
func (p *Parser) parse5424(s string, rec Record) (Record, bool) {
	fields := make([]string, 0, 5)
	rest := s
	for len(fields) < 5 {
		tok, r, found := strings.Cut(rest, " ")
		if !found {
			return rec, false
		}
		fields = append(fields, tok)
		rest = r
	}
	if fields[0] != "-" {
		t, err := time.Parse(time.RFC3339Nano, fields[0])
		if err != nil {
			return rec, false
		}
		rec.Time = t
	}
	nilv := func(v string) string {
		if v == "-" {
			return ""
		}
		return v
	}
	rec.Host = nilv(fields[1])
	rec.App = fields[2]
	if rec.App == "" {
		rec.App = "-"
	}
	rec.PID = nilv(fields[3])
	// Structured data: "-" or one or more [id param="value" ...] elements.
	if strings.HasPrefix(rest, "-") {
		rest = rest[1:]
	} else if strings.HasPrefix(rest, "[") {
		n, ok := skipSD(rest)
		if !ok {
			return rec, false
		}
		rest = rest[n:]
	} else {
		return rec, false
	}
	rest = strings.TrimPrefix(rest, " ")
	rest = strings.TrimPrefix(rest, "\uFEFF")
	rec.Message = rest
	rec.Format = FormatRFC5424
	if r, ok := p.parseCisco(rest, rec, rec.Time); ok && rec.App == "-" {
		return r, true
	}
	return rec, true
}

// skipSD returns the length of the structured-data elements at the start of s.
func skipSD(s string) (int, bool) {
	i := 0
	for i < len(s) && s[i] == '[' {
		inQuote := false
		i++
		for ; i < len(s); i++ {
			c := s[i]
			if c == '\\' && inQuote {
				i++
				continue
			}
			if c == '"' {
				inQuote = !inQuote
				continue
			}
			if c == ']' && !inQuote {
				break
			}
		}
		if i >= len(s) {
			return 0, false
		}
		i++ // past ']'
	}
	return i, true
}

// journalField decodes a journal export field: a string, a number, null,
// or an array of bytes (binary-safe export of non-UTF-8 values).
func journalField(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	case '[':
		var b []int
		if json.Unmarshal(raw, &b) == nil {
			buf := make([]byte, 0, len(b))
			for _, v := range b {
				buf = append(buf, byte(v))
			}
			return strings.ToValidUTF8(string(buf), "\uFFFD")
		}
		// A field present several times: array of strings, keep the first.
		var ss []json.RawMessage
		if json.Unmarshal(raw, &ss) == nil && len(ss) > 0 {
			return journalField(ss[0])
		}
	default:
		return string(raw)
	}
	return ""
}

func parseJournal(line string) (Record, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return Record{}, false
	}
	msgRaw, ok := m["MESSAGE"]
	if !ok {
		return Record{}, false
	}
	rec := Record{Severity: SeverityUnknown, Facility: -1, Format: FormatJournal}
	rec.Message = journalField(msgRaw)
	if us, err := strconv.ParseInt(journalField(m["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		rec.Time = time.UnixMicro(us)
	} else if us, err := strconv.ParseInt(journalField(m["_SOURCE_REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		rec.Time = time.UnixMicro(us)
	}
	rec.Host = journalField(m["_HOSTNAME"])
	for _, k := range []string{"SYSLOG_IDENTIFIER", "_COMM", "_SYSTEMD_UNIT"} {
		if v := journalField(m[k]); v != "" {
			rec.App = v
			break
		}
	}
	if rec.App == "" {
		rec.App = "-"
	}
	for _, k := range []string{"_PID", "SYSLOG_PID"} {
		if v := journalField(m[k]); v != "" {
			rec.PID = v
			break
		}
	}
	if v, err := strconv.Atoi(journalField(m["PRIORITY"])); err == nil && v >= 0 && v <= 7 {
		rec.Severity = v
	}
	if v, err := strconv.Atoi(journalField(m["SYSLOG_FACILITY"])); err == nil && v >= 0 && v <= 23 {
		rec.Facility = v
	}
	return rec, true
}
