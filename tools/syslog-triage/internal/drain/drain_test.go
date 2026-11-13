package drain

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/mask"
)

func add(m *Miner, key, msg string) (*Cluster, bool) {
	return m.Add(key, mask.Tokens(msg, 0), time.Time{})
}

func TestClustering(t *testing.T) {
	m := New(DefaultParams())
	users := []string{"alice", "bob", "carol", "dave"}
	for i := 0; i < 40; i++ {
		add(m, "sshd", fmt.Sprintf("Accepted publickey for %s from 192.0.2.%d port %d ssh2", users[i%4], i, 40000+i))
		add(m, "sshd", fmt.Sprintf("Failed password for invalid user %s from 198.51.100.%d port %d ssh2", users[i%4], i, 50000+i))
		add(m, "kernel", fmt.Sprintf("eth%d: link up, 1000Mbps, full-duplex", i%3))
		// Same text under another program stays separate.
		add(m, "other", fmt.Sprintf("Accepted publickey for %s from 192.0.2.%d port %d ssh2", users[i%4], i, 40000+i))
	}
	got := map[string]int64{}
	for _, c := range m.Clusters() {
		got[c.Key+"|"+c.Template()] = c.Count
	}
	want := map[string]int64{
		"sshd|Accepted publickey for <*> from <IP> port <NUM> ssh2":           40,
		"sshd|Failed password for invalid user <*> from <IP> port <NUM> ssh2": 40,
		"kernel|<*> link up, <NUM>, full-duplex":                              40,
		"other|Accepted publickey for <*> from <IP> port <NUM> ssh2":          40,
	}
	if len(got) != len(want) {
		t.Fatalf("clusters: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d (all: %v)", k, got[k], got)
		}
	}
}

func TestDissimilarMessagesStayApart(t *testing.T) {
	m := New(DefaultParams())
	a, _ := add(m, "", "connection reset by peer")
	b, created := add(m, "", "disk quota exceeded today")
	if !created || a == b {
		t.Fatal("different messages merged")
	}
	c, created := add(m, "", "connection reset by server")
	if created || c != a || c.Template() != "connection reset by <*>" {
		t.Fatalf("similar message not merged: %q created=%v", c.Template(), created)
	}
	// Different lengths never merge.
	if d, created := add(m, "", "connection reset"); !created || d == a {
		t.Fatal("different length merged")
	}
	// Empty messages form their own cluster.
	e1, _ := add(m, "", "")
	e2, created := add(m, "", "   ")
	if created || e1 != e2 {
		t.Fatal("empty messages")
	}
	if m.Match("", mask.Tokens("connection reset by firewall", 0)) != a {
		t.Fatal("Match")
	}
	if m.Match("", mask.Tokens("totally unrelated words here now", 0)) != nil {
		t.Fatal("Match of unknown message")
	}
}

func TestSimilarityThreshold(t *testing.T) {
	strict := New(Params{Depth: 4, Sim: 0.9, MaxChildren: 100})
	add(strict, "", "session opened for alice from console")
	if _, created := add(strict, "", "session opened for bob from network"); !created {
		t.Fatal("sim 0.9 merged messages with 2 of 6 tokens different")
	}
	loose := New(Params{Depth: 4, Sim: 0.5, MaxChildren: 100})
	add(loose, "", "session opened for alice from console")
	if _, created := add(loose, "", "session opened for bob from network"); created {
		t.Fatal("sim 0.5 did not merge")
	}
}

func TestMaxChildren(t *testing.T) {
	m := New(Params{Depth: 4, Sim: 0.4, MaxChildren: 3})
	// First tokens vary (non-numeric): only 2 named branches, then the
	// wildcard branch takes the rest.
	for _, w := range []string{"alpha", "beta", "gamma", "delta", "epsilon"} {
		add(m, "", w+" service restarted successfully")
	}
	root := m.roots[""].children["4"]
	if len(root.children) != 3 || root.children[mask.Wildcard] == nil {
		t.Fatalf("children: %d", len(root.children))
	}
	var tmpl []string
	for _, c := range m.Clusters() {
		tmpl = append(tmpl, c.Template())
	}
	if len(tmpl) != 3 || tmpl[2] != "<*> service restarted successfully" {
		t.Fatalf("templates %q", tmpl)
	}
}

func TestDigitsRouteToWildcard(t *testing.T) {
	m := New(DefaultParams())
	add(m, "", "eth0 link down")
	c, created := add(m, "", "eth1 link down")
	if created || c.Template() != "<*> link down" {
		t.Fatalf("%q created=%v", c.Template(), created)
	}
}

func TestModelRoundTrip(t *testing.T) {
	m := New(Params{Depth: 5, Sim: 0.5, MaxChildren: 10})
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		m.Add("sshd", mask.Tokens(fmt.Sprintf("Accepted publickey for u%d from 192.0.2.1 port 22", i), 0), t0.Add(time.Duration(i)*time.Hour))
	}
	old, _ := m.Add("cron", mask.Tokens("job finished", 0), t0.AddDate(0, -6, 0))
	m.Add("kernel", mask.Tokens("<*> starts with a wildcard token", 0), t0)
	var buf bytes.Buffer
	if err := m.SaveModel(&buf, true, t0.AddDate(0, 0, 1), 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	m2, split, err := LoadModel(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !split || m2.P != m.P || len(m2.Clusters()) != 2 {
		t.Fatalf("params %+v split %v clusters %d", m2.P, split, len(m2.Clusters()))
	}
	for _, c := range m2.Clusters() {
		if c.ID == old.ID {
			t.Fatal("cluster older than max age kept")
		}
		if !c.Known || c.Count != 0 {
			t.Fatalf("restored cluster: %+v", c)
		}
	}
	// Known messages match their restored cluster, new ones get fresh ids.
	c, created := m2.Add("sshd", mask.Tokens("Accepted publickey for zed from 203.0.113.9 port 2222", 0), t0)
	if created || !c.Known || c.TotalCount != 6 || c.ID != 1 {
		t.Fatalf("known: %+v created=%v", c, created)
	}
	c, _ = m2.Add("kernel", mask.Tokens("foo starts with a wildcard token", 0), t0)
	if !c.Known {
		t.Fatal("wildcard-first template not matched after restore")
	}
	n, created := m2.Add("sshd", mask.Tokens("something else entirely", 0), t0)
	if !created || n.Known || n.ID <= old.ID {
		t.Fatalf("new cluster %+v", n)
	}
}

func TestModelErrors(t *testing.T) {
	for _, in := range []string{"", "{}", `{"format":"x","version":1}`, `{"format":"syslog-triage-model","version":9}`,
		`{"format":"syslog-triage-model","version":1,"params":{"depth":4,"sim":2,"max_children":10}}`,
		`{"format":"syslog-triage-model","version":1,"params":{"depth":4,"sim":0.4,"max_children":10},"clusters":[{"id":1},{"id":1}]}`} {
		if _, _, err := LoadModel(strings.NewReader(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestSaveModelFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "model.json")
	m := New(DefaultParams())
	add(m, "a", "hello world")
	if err := m.SaveModelFile(p, false, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
	m2, split, err := LoadModelFile(p)
	if err != nil || split || len(m2.Clusters()) != 1 {
		t.Fatalf("reload: %v %v", err, split)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporary file left behind: %d entries", len(ents))
	}
	if err := m.SaveModelFile(filepath.Join(dir, "missing", "m.json"), false, time.Now(), 0); err == nil {
		t.Fatal("save into a missing directory succeeded")
	}
}

func BenchmarkAdd(b *testing.B) {
	m := New(DefaultParams())
	msgs := make([][]string, 1000)
	for i := range msgs {
		msgs[i] = mask.Tokens(fmt.Sprintf("Accepted publickey for user%d from 192.0.2.%d port %d ssh2 kind%d", i%50, i%250, 1024+i, i%7), 0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add("sshd", msgs[i%len(msgs)], time.Time{})
	}
}
