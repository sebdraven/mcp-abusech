// Package abusech is a read-only client for the abuse.ch APIs: MalwareBazaar
// for malware samples and ThreatFox for indicators of compromise.
//
// Both are POST endpoints taking a `query` field, both authenticate with the
// same Auth-Key, and both answer with a query_status that has to be read
// before the payload — a failed lookup returns HTTP 200 with an error status
// in the body, so trusting the status code alone silently turns "no such
// family" into "no samples".
package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// BazaarEndpoint serves malware samples.
	BazaarEndpoint = "https://mb-api.abuse.ch/api/v1/"
	// ThreatFoxEndpoint serves indicators of compromise.
	ThreatFoxEndpoint = "https://threatfox-api.abuse.ch/api/v1/"
)

// Client talks to the abuse.ch APIs.
type Client struct {
	http    *http.Client
	authKey string
}

// New returns a client. The auth key is required: abuse.ch has enforced
// authentication on both APIs since 2024, and an unauthenticated request is
// rejected outright rather than rate-limited.
func New(authKey string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		authKey: authKey,
	}
}

// Sample is one malware sample as MalwareBazaar records it.
type Sample struct {
	SHA256    string   `json:"sha256_hash"`
	SHA1      string   `json:"sha1_hash"`
	MD5       string   `json:"md5_hash"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	FileName  string   `json:"file_name"`
	FileSize  int      `json:"file_size"`
	FileType  string   `json:"file_type"`
	MIMEType  string   `json:"file_type_mime"`
	Signature string   `json:"signature" jsonschema:"the malware family abuse.ch assigned; a sample carries at most one"`
	Reporter  string   `json:"reporter"`
	Origin    string   `json:"origin_country"`
	Tags      []string `json:"tags"`
	Imphash   string   `json:"imphash"`
	Tlsh      string   `json:"tlsh"`
	Ssdeep    string   `json:"ssdeep"`

	// VendorIntel is a large nested object of per-vendor verdicts, kept raw so
	// callers that want it can decode it without this package modelling every
	// vendor's schema.
	VendorIntel json.RawMessage `json:"vendor_intel,omitempty"`
}

// IOC is one indicator as ThreatFox records it.
type IOC struct {
	ID               string   `json:"id"`
	IOC              string   `json:"ioc"`
	ThreatType       string   `json:"threat_type"`
	ThreatTypeDesc   string   `json:"threat_type_desc"`
	IOCType          string   `json:"ioc_type"`
	IOCTypeDesc      string   `json:"ioc_type_desc"`
	Malware          string   `json:"malware"`
	MalwarePrintable string   `json:"malware_printable"`
	MalwareAlias     string   `json:"malware_alias"`
	MalpediaURL      string   `json:"malware_malpedia" jsonschema:"link to the Malpedia entry, when abuse.ch has mapped the family"`
	Confidence       int      `json:"confidence_level" jsonschema:"0 to 100, as assigned by the reporter"`
	FirstSeen        string   `json:"first_seen_utc"`
	LastSeen         string   `json:"last_seen_utc"`
	Reference        string   `json:"reference"`
	Reporter         string   `json:"reporter"`
	Tags             []string `json:"tags"`
}

// APIError is a query that reached abuse.ch and came back refused.
type APIError struct {
	Status string
	Query  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("abuse.ch %s: %s", e.Query, e.Status)
}

// IsNoResult reports whether an error means the query succeeded but matched
// nothing.
//
// The distinction matters and abuse.ch does not make it in the HTTP status: an
// empty answer is a fact about the corpus, a failure is a fact about the
// request, and reporting one as the other is how "we have no samples" gets
// read as "this family does not exist".
func IsNoResult(err error) bool {
	var e *APIError
	if !errors.As(err, &e) {
		return false
	}
	switch e.Status {
	case "no_results", "no_result", "signature_not_found", "hash_not_found",
		"taginfo_not_found", "malwareinfo_not_found", "illegal_search_term":
		return true
	}
	return false
}

// SamplesBySignature returns the samples abuse.ch attributes to a family.
func (c *Client) SamplesBySignature(ctx context.Context, signature string, limit int) ([]Sample, error) {
	if limit <= 0 {
		limit = 50
	}
	return c.samples(ctx, url.Values{
		"query":     {"get_siginfo"},
		"signature": {strings.TrimSpace(signature)},
		"limit":     {strconv.Itoa(limit)},
	}, "get_siginfo")
}

// SampleByHash looks up one sample by MD5, SHA-1 or SHA-256.
func (c *Client) SampleByHash(ctx context.Context, hash string) ([]Sample, error) {
	return c.samples(ctx, url.Values{
		"query": {"get_info"},
		"hash":  {strings.TrimSpace(hash)},
	}, "get_info")
}

// RecentSamples returns the latest submissions. selector is "time" for the
// last hour or "100" for the last hundred.
func (c *Client) RecentSamples(ctx context.Context, selector string) ([]Sample, error) {
	if selector == "" {
		selector = "100"
	}
	return c.samples(ctx, url.Values{
		"query":    {"get_recent"},
		"selector": {selector},
	}, "get_recent")
}

// IOCsByTag returns the indicators carrying a tag.
func (c *Client) IOCsByTag(ctx context.Context, tag string, limit int) ([]IOC, error) {
	if limit <= 0 {
		limit = 50
	}
	return c.iocs(ctx, url.Values{
		"query": {"taginfo"},
		"tag":   {strings.TrimSpace(tag)},
		"limit": {strconv.Itoa(limit)},
	}, "taginfo")
}

// IOCsByMalware returns the indicators attributed to a malware family.
func (c *Client) IOCsByMalware(ctx context.Context, malware string, limit int) ([]IOC, error) {
	if limit <= 0 {
		limit = 50
	}
	return c.iocs(ctx, url.Values{
		"query":   {"malwareinfo"},
		"malware": {strings.TrimSpace(malware)},
		"limit":   {strconv.Itoa(limit)},
	}, "malwareinfo")
}

// SearchIOC looks up one indicator: a domain, URL, IP:port or hash.
func (c *Client) SearchIOC(ctx context.Context, ioc string) ([]IOC, error) {
	return c.iocs(ctx, url.Values{
		"query":       {"search_ioc"},
		"search_term": {strings.TrimSpace(ioc)},
	}, "search_ioc")
}

// RecentIOCs returns the indicators seen in the last days (1 to 7).
func (c *Client) RecentIOCs(ctx context.Context, days int) ([]IOC, error) {
	if days <= 0 || days > 7 {
		days = 1
	}
	return c.iocs(ctx, url.Values{
		"query": {"get_iocs"},
		"days":  {strconv.Itoa(days)},
	}, "get_iocs")
}

func (c *Client) samples(ctx context.Context, form url.Values, query string) ([]Sample, error) {
	var out struct {
		QueryStatus string   `json:"query_status"`
		Data        []Sample `json:"data"`
	}
	if err := c.post(ctx, BazaarEndpoint, form, &out); err != nil {
		return nil, err
	}
	if out.QueryStatus != "ok" {
		return nil, &APIError{Status: out.QueryStatus, Query: query}
	}
	return out.Data, nil
}

func (c *Client) iocs(ctx context.Context, form url.Values, query string) ([]IOC, error) {
	var out struct {
		QueryStatus string `json:"query_status"`
		Data        []IOC  `json:"data"`
	}
	if err := c.postJSON(ctx, ThreatFoxEndpoint, form, &out); err != nil {
		return nil, err
	}
	if out.QueryStatus != "ok" {
		return nil, &APIError{Status: out.QueryStatus, Query: query}
	}
	return out.Data, nil
}

// postJSON sends a ThreatFox request.
//
// The two APIs do NOT share a request format, despite sharing a host, an auth
// key and a query vocabulary: MalwareBazaar takes form-encoded bodies and
// ThreatFox takes JSON. Sending the wrong one produces query_status "no_json"
// with HTTP 200, which reads as a data problem rather than as a request that
// was never understood.
func (c *Client) postJSON(ctx context.Context, endpoint string, form url.Values, out any) error {
	// The callers build url.Values because that is what MalwareBazaar wants;
	// flattening to a map keeps one call-site shape for both APIs.
	payload := make(map[string]any, len(form))
	for k, v := range form {
		if len(v) == 0 {
			continue
		}
		// Numeric fields have to go over as numbers: ThreatFox rejects a
		// quoted limit or days value.
		if k == "limit" || k == "days" {
			if n, err := strconv.Atoi(v[0]); err == nil {
				payload[k] = n
				continue
			}
		}
		payload[k] = v[0]
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}
	return c.do(ctx, endpoint, "application/json", bytes.NewReader(body), out)
}

func (c *Client) post(ctx context.Context, endpoint string, form url.Values, out any) error {
	return c.do(ctx, endpoint, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()), out)
}

func (c *Client) do(ctx context.Context, endpoint, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if c.authKey != "" {
		req.Header.Set("Auth-Key", c.authKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("abuse.ch request: %w", err)
	}
	defer resp.Body.Close()

	// Capped: a get_recent can return a lot, and an unbounded read on a remote
	// service is an easy way to lose a process to a bad day upstream.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return fmt.Errorf("abuse.ch rejected the auth key (HTTP 401); both APIs have required one since 2024")
	case http.StatusTooManyRequests:
		return fmt.Errorf("abuse.ch rate limit reached (HTTP 429)")
	default:
		return fmt.Errorf("abuse.ch returned HTTP %d: %s", resp.StatusCode, snippet(raw))
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding response: %w (body: %s)", err, snippet(raw))
	}
	return nil
}

func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// DecodeVendorIntel unpacks the per-vendor verdicts attached to a sample.
func DecodeVendorIntel(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}
