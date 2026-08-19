// Package service is the layer both façades go through: it holds the client,
// applies defaults and validation once, and shapes results so the MCP tools
// and the TUI cannot drift apart.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sebdraven/mcp-abusech/internal/abusech"
)

// ErrEmptyQuery is returned when a lookup is given nothing to look for.
var ErrEmptyQuery = errors.New("a query is required")

// Service answers questions about abuse.ch data.
type Service struct {
	client *abusech.Client
}

// New returns a service over an abuse.ch client.
func New(c *abusech.Client) *Service { return &Service{client: c} }

// SampleResult is a set of malware samples with the context needed to read it.
type SampleResult struct {
	Query     string            `json:"query"`
	Count     int               `json:"count"`
	Samples   []abusech.Sample  `json:"samples"`
	Families  []FamilyCount     `json:"families,omitempty" jsonschema:"how many samples each family accounts for; more than one family in a lookup means abuse.ch disagrees with itself or the query was broad"`
	Note      string            `json:"note,omitempty"`
	RetrievedAt string          `json:"retrieved_at" jsonschema:"when this answer was fetched. abuse.ch is a live service, so unlike a pinned corpus the same query tomorrow may differ"`
}

// FamilyCount is one family and how many samples carry it.
type FamilyCount struct {
	Signature string `json:"signature"`
	Count     int    `json:"count"`
}

// IOCResult is a set of indicators.
type IOCResult struct {
	Query       string        `json:"query"`
	Count       int           `json:"count"`
	IOCs        []abusech.IOC `json:"iocs"`
	Types       []TypeCount   `json:"types,omitempty" jsonschema:"how many indicators of each kind; a family seen only through one indicator type is thinly observed"`
	Note        string        `json:"note,omitempty"`
	RetrievedAt string        `json:"retrieved_at"`
}

// TypeCount is one indicator type and how many carry it.
type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// SamplesByFamily returns the samples abuse.ch attributes to a family.
func (s *Service) SamplesByFamily(ctx context.Context, family string, limit int) (SampleResult, error) {
	family = strings.TrimSpace(family)
	if family == "" {
		return SampleResult{}, ErrEmptyQuery
	}
	samples, err := s.client.SamplesBySignature(ctx, family, limit)
	if err != nil {
		if abusech.IsNoResult(err) {
			return SampleResult{
				Query: family, RetrievedAt: now(),
				Note: "abuse.ch has no samples under this signature. That is a statement about MalwareBazaar's corpus, not about whether the family exists: signatures there come from submitters and automated rules, and a family documented in vendor reporting may be absent or filed under another name",
			}, nil
		}
		return SampleResult{}, err
	}
	return SampleResult{
		Query: family, Count: len(samples), Samples: samples,
		Families:    countFamilies(samples),
		RetrievedAt: now(),
		Note:        familyNote(samples),
	}, nil
}

// SampleByHash looks up one sample.
func (s *Service) SampleByHash(ctx context.Context, hash string) (SampleResult, error) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return SampleResult{}, ErrEmptyQuery
	}
	samples, err := s.client.SampleByHash(ctx, hash)
	if err != nil {
		if abusech.IsNoResult(err) {
			return SampleResult{
				Query: hash, RetrievedAt: now(),
				Note: "no sample with this hash on MalwareBazaar. Absence here says nothing about the file itself — most malware is never submitted",
			}, nil
		}
		return SampleResult{}, err
	}
	return SampleResult{
		Query: hash, Count: len(samples), Samples: samples,
		Families: countFamilies(samples), RetrievedAt: now(),
	}, nil
}

// RecentSamples returns the latest submissions.
func (s *Service) RecentSamples(ctx context.Context, selector string) (SampleResult, error) {
	samples, err := s.client.RecentSamples(ctx, selector)
	if err != nil {
		if abusech.IsNoResult(err) {
			return SampleResult{Query: selector, RetrievedAt: now(), Note: "nothing submitted in this window"}, nil
		}
		return SampleResult{}, err
	}
	return SampleResult{
		Query: selector, Count: len(samples), Samples: samples,
		Families: countFamilies(samples), RetrievedAt: now(),
	}, nil
}

// IOCsByFamily returns the indicators attributed to a family.
func (s *Service) IOCsByFamily(ctx context.Context, family string, limit int) (IOCResult, error) {
	family = strings.TrimSpace(family)
	if family == "" {
		return IOCResult{}, ErrEmptyQuery
	}
	iocs, err := s.client.IOCsByMalware(ctx, family, limit)
	if err != nil {
		if abusech.IsNoResult(err) {
			return IOCResult{
				Query: family, RetrievedAt: now(),
				Note: "no indicators under this family name on ThreatFox. Try the tag lookup instead: ThreatFox families use Malpedia identifiers such as win.example, while tags carry the names analysts actually type",
			}, nil
		}
		return IOCResult{}, err
	}
	return IOCResult{
		Query: family, Count: len(iocs), IOCs: iocs,
		Types: countTypes(iocs), RetrievedAt: now(), Note: iocNote(iocs),
	}, nil
}

// IOCsByTag returns the indicators carrying a tag.
func (s *Service) IOCsByTag(ctx context.Context, tag string, limit int) (IOCResult, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return IOCResult{}, ErrEmptyQuery
	}
	iocs, err := s.client.IOCsByTag(ctx, tag, limit)
	if err != nil {
		if abusech.IsNoResult(err) {
			return IOCResult{Query: tag, RetrievedAt: now(), Note: "no indicators carry this tag"}, nil
		}
		return IOCResult{}, err
	}
	return IOCResult{
		Query: tag, Count: len(iocs), IOCs: iocs,
		Types: countTypes(iocs), RetrievedAt: now(), Note: iocNote(iocs),
	}, nil
}

// SearchIOC looks up one indicator.
func (s *Service) SearchIOC(ctx context.Context, ioc string) (IOCResult, error) {
	ioc = strings.TrimSpace(ioc)
	if ioc == "" {
		return IOCResult{}, ErrEmptyQuery
	}
	iocs, err := s.client.SearchIOC(ctx, ioc)
	if err != nil {
		if abusech.IsNoResult(err) {
			return IOCResult{
				Query: ioc, RetrievedAt: now(),
				Note: "this indicator is not on ThreatFox. Not evidence that it is benign — ThreatFox holds what people have reported, nothing more",
			}, nil
		}
		return IOCResult{}, err
	}
	return IOCResult{
		Query: ioc, Count: len(iocs), IOCs: iocs,
		Types: countTypes(iocs), RetrievedAt: now(),
	}, nil
}

// RecentIOCs returns what has been reported over the last days.
func (s *Service) RecentIOCs(ctx context.Context, days int) (IOCResult, error) {
	iocs, err := s.client.RecentIOCs(ctx, days)
	if err != nil {
		if abusech.IsNoResult(err) {
			return IOCResult{RetrievedAt: now(), Note: "nothing reported in this window"}, nil
		}
		return IOCResult{}, err
	}
	return IOCResult{
		Query: fmt.Sprintf("last %d day(s)", days), Count: len(iocs), IOCs: iocs,
		Types: countTypes(iocs), RetrievedAt: now(),
	}, nil
}

func countFamilies(samples []abusech.Sample) []FamilyCount {
	counts := map[string]int{}
	for _, s := range samples {
		sig := s.Signature
		if sig == "" {
			sig = "(unclassified)"
		}
		counts[sig]++
	}
	out := make([]FamilyCount, 0, len(counts))
	for sig, n := range counts {
		out = append(out, FamilyCount{Signature: sig, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

func countTypes(iocs []abusech.IOC) []TypeCount {
	counts := map[string]int{}
	for _, i := range iocs {
		counts[i.IOCType]++
	}
	out := make([]TypeCount, 0, len(counts))
	for t, n := range counts {
		out = append(out, TypeCount{Type: t, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func familyNote(samples []abusech.Sample) string {
	if len(samples) == 0 {
		return ""
	}
	unclassified := 0
	for _, s := range samples {
		if s.Signature == "" {
			unclassified++
		}
	}
	if unclassified == len(samples) {
		return "none of these samples carries a family signature; MalwareBazaar has them but has not classified them"
	}
	return ""
}

func iocNote(iocs []abusech.IOC) string {
	if len(iocs) == 0 {
		return ""
	}
	low := 0
	for _, i := range iocs {
		if i.Confidence < 50 {
			low++
		}
	}
	if low > len(iocs)/2 {
		return "most of these indicators carry a confidence below 50, as set by whoever reported them. Treat them as leads rather than as findings"
	}
	return ""
}
