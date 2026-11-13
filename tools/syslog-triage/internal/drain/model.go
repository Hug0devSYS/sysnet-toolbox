package drain

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ModelVersion is the version of the model file format.
const ModelVersion = 1

type modelFile struct {
	Format   string         `json:"format"`
	Version  int            `json:"version"`
	Updated  time.Time      `json:"updated"`
	Params   Params         `json:"params"`
	AppSplit bool           `json:"app_split"`
	NextID   int            `json:"next_id"`
	Clusters []modelCluster `json:"clusters"`
}

type modelCluster struct {
	ID        int       `json:"id"`
	Key       string    `json:"key"`
	Tokens    []string  `json:"tokens"`
	Path      []string  `json:"path"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

const modelFormat = "syslog-triage-model"

// LoadModel reads a model written by SaveModel. The returned miner uses
// the parameters stored in the model; appSplit is the partitioning mode
// the model was built with.
func LoadModel(r io.Reader) (m *Miner, appSplit bool, err error) {
	var f modelFile
	dec := json.NewDecoder(r)
	if err := dec.Decode(&f); err != nil {
		return nil, false, fmt.Errorf("invalid model: %w", err)
	}
	if f.Format != modelFormat {
		return nil, false, errors.New("invalid model: not a syslog-triage model file")
	}
	if f.Version != ModelVersion {
		return nil, false, fmt.Errorf("unsupported model version %d (expected %d)", f.Version, ModelVersion)
	}
	if f.Params.Sim < 0 || f.Params.Sim > 1 || f.Params.Depth < 3 {
		return nil, false, errors.New("invalid model: bad parameters")
	}
	m = New(f.Params)
	seen := map[int]bool{}
	for _, mc := range f.Clusters {
		if seen[mc.ID] || mc.ID <= 0 {
			return nil, false, fmt.Errorf("invalid model: duplicate or invalid cluster id %d", mc.ID)
		}
		seen[mc.ID] = true
		c := &Cluster{ID: mc.ID, Key: mc.Key, Tokens: append([]string(nil), mc.Tokens...),
			TotalCount: mc.Count, FirstSeen: mc.FirstSeen, LastSeen: mc.LastSeen}
		if c.Tokens == nil {
			c.Tokens = []string{}
		}
		depth := m.prefixLen(len(c.Tokens))
		if len(mc.Path) == depth {
			c.Path = mc.Path
		}
		m.restore(c)
	}
	if f.NextID > m.nextID {
		m.nextID = f.NextID
	}
	return m, f.AppSplit, nil
}

// LoadModelFile loads a model from path.
func LoadModelFile(path string) (*Miner, bool, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer fh.Close()
	m, split, err := LoadModel(fh)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return m, split, nil
}

// SaveModel writes the miner state. Clusters whose last occurrence is
// older than maxAge before now are dropped (maxAge <= 0 keeps everything).
func (m *Miner) SaveModel(w io.Writer, appSplit bool, now time.Time, maxAge time.Duration) error {
	f := modelFile{Format: modelFormat, Version: ModelVersion, Updated: now.UTC(), Params: m.P,
		AppSplit: appSplit, NextID: m.nextID, Clusters: []modelCluster{}}
	for _, c := range m.clusters {
		if maxAge > 0 && !c.LastSeen.IsZero() && now.Sub(c.LastSeen) > maxAge {
			continue
		}
		f.Clusters = append(f.Clusters, modelCluster{ID: c.ID, Key: c.Key, Tokens: c.Tokens, Path: c.Path,
			Count: c.TotalCount, FirstSeen: c.FirstSeen.UTC(), LastSeen: c.LastSeen.UTC()})
	}
	sort.Slice(f.Clusters, func(i, j int) bool { return f.Clusters[i].ID < f.Clusters[j].ID })
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(f)
}

// SaveModelFile writes the model atomically (temporary file + rename) with
// mode 0600: templates can contain user names or host names.
func (m *Miner) SaveModelFile(path string, appSplit bool, now time.Time, maxAge time.Duration) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".syslog-triage-model-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := m.SaveModel(tmp, appSplit, now, maxAge); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
