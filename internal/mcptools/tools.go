// Package mcptools exposes the service over MCP.
//
// Tool descriptions carry more weight here than in a REST API: they are the
// only thing a model reads before choosing. Two things are stated in every one
// of them, because getting either wrong produces confident nonsense — that
// abuse.ch is a live service rather than a pinned corpus, and that absence of
// data is a fact about what people have submitted, never about whether
// something exists.
package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-abusech/internal/service"
)

type registry struct{ svc *service.Service }

// Register wires every tool onto an MCP server.
func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_samples",
		Description: "List the MalwareBazaar samples attributed to a malware family, by signature. " +
			"Use it to get hashes for a family you have a name for — then look those up elsewhere to see what other vendors call it. " +
			"The signature is what abuse.ch assigned, usually from submitter tags or automated rules rather than from published analysis, so it is one opinion among several: a family may be absent here, or filed under a name no vendor uses. " +
			"An empty answer means MalwareBazaar holds nothing under that signature, never that the family does not exist.",
	}, r.samples)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_sample",
		Description: "Look up one MalwareBazaar sample by MD5, SHA-1 or SHA-256. " +
			"Returns the family signature abuse.ch assigned, submission dates, file metadata, and the fuzzy hashes (imphash, tlsh, ssdeep) that let you pivot to related samples. " +
			"A hash that is not here says nothing about the file: most malware is never submitted to a public repository.",
	}, r.sample)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_recent_samples",
		Description: "The most recent MalwareBazaar submissions: pass 'time' for the last hour, or '100' for the last hundred. " +
			"Useful for watching what is arriving rather than for answering a question about a known family.",
	}, r.recentSamples)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_iocs",
		Description: "List the ThreatFox indicators attributed to a malware family. " +
			"ThreatFox identifies families by Malpedia identifier (win.example, apk.example), so a plain vendor name often returns nothing — try ab_iocs_by_tag with the name analysts actually type. " +
			"Every indicator carries a confidence level set by whoever reported it; read it, because ThreatFox aggregates community submissions rather than vetted analysis.",
	}, r.iocs)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_iocs_by_tag",
		Description: "List the ThreatFox indicators carrying a tag. " +
			"Tags are free-form and reflect what reporters typed, so this is the lookup that works with vendor names, campaign names and family names alike — where the family lookup expects a Malpedia identifier. " +
			"Confidence is per-indicator and set by the reporter, not by abuse.ch.",
	}, r.iocsByTag)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_search_ioc",
		Description: "Look up one indicator on ThreatFox: a domain, URL, IP:port or hash. " +
			"Answers 'has anyone reported this, and as what'. " +
			"A miss is not evidence of anything: ThreatFox holds what people have chosen to report, and most infrastructure never gets reported at all.",
	}, r.searchIOC)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ab_recent_iocs",
		Description: "The indicators reported to ThreatFox over the last 1 to 7 days. " +
			"For watching what is being seen now; large, so narrow the window before widening it.",
	}, r.recentIOCs)
}

type familyInput struct {
	Family string `json:"family" jsonschema:"the malware family signature, as abuse.ch spells it"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type hashInput struct {
	Hash string `json:"hash" jsonschema:"MD5, SHA-1 or SHA-256 of the sample"`
}

type recentSamplesInput struct {
	Selector string `json:"selector,omitempty" jsonschema:"'time' for the last hour, or '100' for the last hundred submissions (default)"`
}

type tagInput struct {
	Tag   string `json:"tag" jsonschema:"the tag, as reporters typed it"`
	Limit int    `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type iocInput struct {
	IOC string `json:"ioc" jsonschema:"a domain, URL, IP:port or hash"`
}

type recentIOCsInput struct {
	Days int `json:"days,omitempty" jsonschema:"how many days back, 1 to 7 (default 1)"`
}

func (r *registry) samples(ctx context.Context, _ *mcp.CallToolRequest, in familyInput) (*mcp.CallToolResult, service.SampleResult, error) {
	if strings.TrimSpace(in.Family) == "" {
		return nil, service.SampleResult{}, fmt.Errorf("family is required")
	}
	res, err := r.svc.SamplesByFamily(ctx, in.Family, in.Limit)
	return nil, res, err
}

func (r *registry) sample(ctx context.Context, _ *mcp.CallToolRequest, in hashInput) (*mcp.CallToolResult, service.SampleResult, error) {
	if strings.TrimSpace(in.Hash) == "" {
		return nil, service.SampleResult{}, fmt.Errorf("hash is required")
	}
	res, err := r.svc.SampleByHash(ctx, in.Hash)
	return nil, res, err
}

func (r *registry) recentSamples(ctx context.Context, _ *mcp.CallToolRequest, in recentSamplesInput) (*mcp.CallToolResult, service.SampleResult, error) {
	res, err := r.svc.RecentSamples(ctx, in.Selector)
	return nil, res, err
}

func (r *registry) iocs(ctx context.Context, _ *mcp.CallToolRequest, in familyInput) (*mcp.CallToolResult, service.IOCResult, error) {
	if strings.TrimSpace(in.Family) == "" {
		return nil, service.IOCResult{}, fmt.Errorf("family is required")
	}
	res, err := r.svc.IOCsByFamily(ctx, in.Family, in.Limit)
	return nil, res, err
}

func (r *registry) iocsByTag(ctx context.Context, _ *mcp.CallToolRequest, in tagInput) (*mcp.CallToolResult, service.IOCResult, error) {
	if strings.TrimSpace(in.Tag) == "" {
		return nil, service.IOCResult{}, fmt.Errorf("tag is required")
	}
	res, err := r.svc.IOCsByTag(ctx, in.Tag, in.Limit)
	return nil, res, err
}

func (r *registry) searchIOC(ctx context.Context, _ *mcp.CallToolRequest, in iocInput) (*mcp.CallToolResult, service.IOCResult, error) {
	if strings.TrimSpace(in.IOC) == "" {
		return nil, service.IOCResult{}, fmt.Errorf("ioc is required")
	}
	res, err := r.svc.SearchIOC(ctx, in.IOC)
	return nil, res, err
}

func (r *registry) recentIOCs(ctx context.Context, _ *mcp.CallToolRequest, in recentIOCsInput) (*mcp.CallToolResult, service.IOCResult, error) {
	res, err := r.svc.RecentIOCs(ctx, in.Days)
	return nil, res, err
}
