// Package monitorhistory stores opt-in, bounded server monitoring observations.
package monitorhistory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Point struct {
	Time   int64    `json:"time"`
	OK     bool     `json:"ok"`
	CPU    *float64 `json:"cpu"`
	Memory *float64 `json:"memory"`
	RXRate *float64 `json:"rxRate"`
	TXRate *float64 `json:"txRate"`
}
type Day struct {
	Date    string `json:"date"`
	RX      uint64 `json:"rx"`
	TX      uint64 `json:"tx"`
	Seconds int64  `json:"seconds"`
	Gaps    int    `json:"gaps"`
}
type Counter struct {
	Time       int64  `json:"time"`
	Epoch      string `json:"epoch"`
	Interfaces string `json:"interfaces"`
	RX         uint64 `json:"rx"`
	TX         uint64 `json:"tx"`
}
type State struct {
	Enabled bool     `json:"enabled"`
	Points  []Point  `json:"points"`
	Days    []Day    `json:"days"`
	Last    *Counter `json:"last,omitempty"`
}
type Store struct {
	mu  sync.Mutex
	dir string
}

func New(root string) *Store { return &Store{dir: filepath.Join(root, "monitor-history")} }
func (s *Store) path(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}
func empty() State { return State{Points: []Point{}, Days: []Day{}} }
func (s *Store) read(id string) (State, error) {
	state := empty()
	data, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if len(data) > 2<<20 {
		return state, errors.New("监控记录超出限制")
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, errors.New("监控记录损坏")
	}
	if len(state.Points) > 3000 || len(state.Days) > 31 {
		return state, errors.New("监控记录超出限制")
	}
	return state, nil
}
func trim(state *State, now time.Time) {
	points := []Point{}
	for _, p := range state.Points {
		if p.Time >= now.Add(-24*time.Hour).Unix() && p.Time <= now.Unix() {
			points = append(points, p)
		}
	}
	state.Points = points
	cutoff := now.UTC().AddDate(0, 0, -29).Format("2006-01-02")
	days := []Day{}
	for _, d := range state.Days {
		if d.Date >= cutoff && d.Date <= now.UTC().Format("2006-01-02") {
			days = append(days, d)
		}
	}
	state.Days = days
}
func (s *Store) write(id string, state State) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".history-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.path(id))
}
func (s *Store) Read(id string, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.read(id)
	if err != nil {
		return state, err
	}
	beforePoints, beforeDays := len(state.Points), len(state.Days)
	trim(&state, now)
	if beforePoints != len(state.Points) || beforeDays != len(state.Days) {
		if state.Last != nil && state.Last.Time < now.Add(-24*time.Hour).Unix() {
			state.Last = nil
		}
		err = s.write(id, state)
	}
	return state, err
}
func (s *Store) Enable(id string, enabled bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.read(id)
	if err != nil {
		return err
	}
	if state.Enabled != enabled {
		state.Last = nil
	}
	state.Enabled = enabled
	trim(&state, now)
	return s.write(id, state)
}
func (s *Store) Clear(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func valid(v *float64) bool { return v == nil || !math.IsNaN(*v) && !math.IsInf(*v, 0) && *v >= 0 }

// Record never joins across failed observations, counter epochs or day boundaries.
// Such intervals are unknown, not zero traffic, and increment the gap count.
func (s *Store) Record(id string, p Point, c *Counter, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.read(id)
	if err != nil {
		return err
	}
	if !state.Enabled {
		return nil
	}
	trim(&state, now)
	if p.Time > now.Unix() || p.Time < now.Add(-90*time.Second).Unix() || !valid(p.CPU) || !valid(p.Memory) || !valid(p.RXRate) || !valid(p.TXRate) {
		return errors.New("监控采样无效")
	}
	if len(state.Points) > 0 && p.Time-state.Points[len(state.Points)-1].Time < 30 {
		return nil
	}
	if !p.OK {
		p.CPU = nil
		p.Memory = nil
		p.RXRate = nil
		p.TXRate = nil
		c = nil
	}
	date := time.Unix(p.Time, 0).UTC().Format("2006-01-02")
	idx := -1
	for i := range state.Days {
		if state.Days[i].Date == date {
			idx = i
		}
	}
	if idx < 0 {
		state.Days = append(state.Days, Day{Date: date})
		idx = len(state.Days) - 1
	}
	d := &state.Days[idx]
	previous := state.Last
	if c != nil && c.Time == p.Time && c.Epoch != "" && c.Interfaces != "" && previous != nil && previous.Epoch == c.Epoch && previous.Interfaces == c.Interfaces && c.Time > previous.Time && c.Time-previous.Time <= 90 && time.Unix(previous.Time, 0).UTC().Format("2006-01-02") == date && c.RX >= previous.RX && c.TX >= previous.TX && math.MaxUint64-d.RX >= c.RX-previous.RX && math.MaxUint64-d.TX >= c.TX-previous.TX {
		d.RX += c.RX - previous.RX
		d.TX += c.TX - previous.TX
		d.Seconds += c.Time - previous.Time
	} else {
		d.Gaps++
	}
	if c != nil && (c.Time != p.Time || c.Epoch == "" || c.Interfaces == "") {
		c = nil
	}
	state.Last = c
	state.Points = append(state.Points, p)
	sort.Slice(state.Days, func(i, j int) bool { return state.Days[i].Date < state.Days[j].Date })
	return s.write(id, state)
}

// Prune removes old records for deleted servers without racing new registrations.
func (s *Store) Prune(ids []string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, id := range ids {
		keep[filepath.Base(s.path(id))] = true
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || keep[entry.Name()] {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if now.Sub(info.ModTime()) < 30*24*time.Hour {
			continue
		}
		if err = os.Remove(filepath.Join(s.dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
