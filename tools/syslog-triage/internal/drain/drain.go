// Package drain implements the Drain online log-template miner
// (He, Zhu, Zheng, Lyu: "Drain: An Online Log Parsing Approach with Fixed
// Depth Tree", ICWS 2017), with the usual Drain3 refinements: masked
// tokens, parameter-aware tie breaking, a bounded number of children per
// tree node and a persistent model.
//
// Messages are partitioned by a key (the program name by default), then by
// token count, then by their first Depth-2 tokens; the leaf holds clusters
// whose template is compared token by token with the message.
package drain

import (
	"strconv"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/mask"
)

// Params are the Drain tuning parameters.
type Params struct {
	Depth       int     `json:"depth"`        // tree depth including the length layer (>= 3)
	Sim         float64 `json:"sim"`          // similarity threshold in [0,1]
	MaxChildren int     `json:"max_children"` // max children per internal node (>= 2)
}

// DefaultParams are the Drain3 defaults.
func DefaultParams() Params { return Params{Depth: 4, Sim: 0.4, MaxChildren: 100} }

// Cluster is a log template and its statistics.
type Cluster struct {
	ID     int
	Key    string   // partition key (program name or "")
	Tokens []string // template; mask.Wildcard marks parameters
	Path   []string // routing keys in the prefix tree

	// Persistent statistics (stored in the model).
	TotalCount int64
	FirstSeen  time.Time
	LastSeen   time.Time

	// Known is true for clusters loaded from a model.
	Known bool
	// Count is the number of messages matched during this run.
	Count int64
}

// Template returns the template as a single string.
func (c *Cluster) Template() string { return strings.Join(c.Tokens, " ") }

type node struct {
	children map[string]*node
	clusters []*Cluster
}

func newNode() *node { return &node{children: map[string]*node{}} }

// Miner is a Drain tree. It is not safe for concurrent use.
type Miner struct {
	P        Params
	roots    map[string]*node // key -> length layer
	clusters []*Cluster
	nextID   int
}

// New returns an empty miner.
func New(p Params) *Miner {
	if p.Depth < 3 {
		p.Depth = 3
	}
	if p.MaxChildren < 2 {
		p.MaxChildren = 2
	}
	return &Miner{P: p, roots: map[string]*node{}, nextID: 1}
}

// Clusters returns every cluster in creation order.
func (m *Miner) Clusters() []*Cluster { return m.clusters }

// routeKey is the tree key of a token: parameters and tokens containing
// digits share the wildcard branch (Drain heuristic).
func routeKey(tok string) string {
	if tok == mask.Wildcard || mask.IsPlaceholder(tok) {
		return mask.Wildcard
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] >= '0' && tok[i] <= '9' {
			return mask.Wildcard
		}
	}
	return tok
}

func (m *Miner) prefixLen(n int) int { return min(n, m.P.Depth-2) }

// search descends the tree without modifying it, falling back to the
// wildcard branch when a token has no child of its own.
func (m *Miner) search(key string, tokens []string) *node {
	root := m.roots[key]
	if root == nil {
		return nil
	}
	n := root.children[strconv.Itoa(len(tokens))]
	for i := 0; n != nil && i < m.prefixLen(len(tokens)); i++ {
		k := routeKey(tokens[i])
		c := n.children[k]
		if c == nil {
			c = n.children[mask.Wildcard]
		}
		n = c
	}
	return n
}

// insertPath creates (or follows) the path for tokens and returns the leaf
// and the routing keys used.
func (m *Miner) insertPath(key string, tokens []string, path []string) (*node, []string) {
	root := m.roots[key]
	if root == nil {
		root = newNode()
		m.roots[key] = root
	}
	lk := strconv.Itoa(len(tokens))
	n := root.children[lk]
	if n == nil {
		n = newNode()
		root.children[lk] = n
	}
	depth := m.prefixLen(len(tokens))
	used := make([]string, 0, depth)
	for i := 0; i < depth; i++ {
		var k string
		if path != nil && i < len(path) {
			k = path[i]
		} else {
			k = routeKey(tokens[i])
		}
		c := n.children[k]
		if c == nil {
			if k != mask.Wildcard && path == nil && len(n.children) >= m.P.MaxChildren-1 {
				// Keep the last slot for the wildcard branch.
				k = mask.Wildcard
				c = n.children[k]
			}
			if c == nil {
				c = newNode()
				n.children[k] = c
			}
		}
		used = append(used, k)
		n = c
	}
	return n, used
}

// similarity returns the share of template tokens equal to the message
// tokens and the number of parameters in the template.
func similarity(tmpl, tokens []string) (float64, int) {
	if len(tmpl) == 0 {
		return 1, 0
	}
	same, params := 0, 0
	for i, t := range tmpl {
		if t == mask.Wildcard {
			params++
			continue
		}
		if t == tokens[i] {
			same++
		}
	}
	return float64(same) / float64(len(tmpl)), params
}

func (m *Miner) bestMatch(leaf *node, tokens []string, threshold float64) *Cluster {
	var best *Cluster
	bestSim, bestParams := -1.0, -1
	for _, c := range leaf.clusters {
		sim, params := similarity(c.Tokens, tokens)
		if sim > bestSim || sim == bestSim && params > bestParams {
			best, bestSim, bestParams = c, sim, params
		}
	}
	if best != nil && bestSim >= threshold {
		return best
	}
	return nil
}

// Add classifies a masked message and returns its cluster and whether the
// cluster was created by this call.
func (m *Miner) Add(key string, tokens []string, ts time.Time) (*Cluster, bool) {
	var c *Cluster
	if leaf := m.search(key, tokens); leaf != nil {
		c = m.bestMatch(leaf, tokens, m.P.Sim)
	}
	created := false
	if c == nil {
		leaf, path := m.insertPath(key, tokens, nil)
		// The insertion path may differ from the search path (new branch):
		// the leaf could already hold a matching cluster.
		c = m.bestMatch(leaf, tokens, m.P.Sim)
		if c == nil {
			c = &Cluster{ID: m.nextID, Key: key, Tokens: append([]string(nil), tokens...), Path: path}
			m.nextID++
			leaf.clusters = append(leaf.clusters, c)
			m.clusters = append(m.clusters, c)
			created = true
		}
	}
	if !created {
		for i, t := range c.Tokens {
			if t != tokens[i] {
				c.Tokens[i] = mask.Wildcard
			}
		}
	}
	c.Count++
	c.TotalCount++
	if !ts.IsZero() {
		if c.FirstSeen.IsZero() || ts.Before(c.FirstSeen) {
			c.FirstSeen = ts
		}
		if ts.After(c.LastSeen) {
			c.LastSeen = ts
		}
	}
	return c, created
}

// Match returns the cluster a message would join, without changing the
// miner (nil when the message would create a new cluster).
func (m *Miner) Match(key string, tokens []string) *Cluster {
	if leaf := m.search(key, tokens); leaf != nil {
		return m.bestMatch(leaf, tokens, m.P.Sim)
	}
	return nil
}

// restore inserts a cluster loaded from a model.
func (m *Miner) restore(c *Cluster) {
	leaf, path := m.insertPath(c.Key, c.Tokens, c.Path)
	c.Path = path
	c.Known = true
	leaf.clusters = append(leaf.clusters, c)
	m.clusters = append(m.clusters, c)
	if c.ID >= m.nextID {
		m.nextID = c.ID + 1
	}
}
