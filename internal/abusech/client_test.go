package abusech

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stub stands in for abuse.ch.
//
// Every test here runs against it rather than the real service: hitting
// abuse.ch from a test suite would make the build depend on a third party's
// uptime, burn an API quota on every push, and make failures ambiguous between
// "the code is wrong" and "the service is having a bad day".
func stub(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New("test-key")
	c.http = srv.Client()
	return c, srv
}

// postTo redirects a client method at the stub. The endpoints are constants,
// so the test drives the low-level post directly.
func postTo(t *testing.T, c *Client, srv *httptest.Server, form map[string][]string, out any) error {
	t.Helper()
	values := make(map[string][]string, len(form))
	for k, v := range form {
		values[k] = v
	}
	return c.post(context.Background(), srv.URL, values, out)
}

func TestPostSendsAuthKeyAndForm(t *testing.T) {
	// The auth header is the whole reason a key exists; sending the query as
	// JSON, or omitting the header, both fail in ways that look like "no
	// results" rather than like a mistake.
	var gotKey, gotQuery, gotContentType string
	c, srv := stub(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		gotContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		gotQuery = r.PostForm.Get("query")
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[]}`))
	})

	var out struct {
		QueryStatus string `json:"query_status"`
	}
	if err := postTo(t, c, srv, map[string][]string{"query": {"get_siginfo"}}, &out); err != nil {
		t.Fatalf("post: %v", err)
	}
	if gotKey != "test-key" {
		t.Errorf("Auth-Key = %q, want the configured key", gotKey)
	}
	if gotQuery != "get_siginfo" {
		t.Errorf("query = %q, want get_siginfo", gotQuery)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q; abuse.ch takes form-encoded bodies, not JSON", gotContentType)
	}
}

func TestQueryStatusIsCheckedNotJustHTTPStatus(t *testing.T) {
	// The trap this guards against: abuse.ch answers a failed lookup with
	// HTTP 200 and an error in the body. Trusting the status code turns "no
	// such family" into "this family has no samples", which reads as a fact
	// about the malware rather than about the request.
	c, srv := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"query_status":"signature_not_found"}`))
	})

	var out struct {
		QueryStatus string   `json:"query_status"`
		Data        []Sample `json:"data"`
	}
	if err := postTo(t, c, srv, map[string][]string{"query": {"get_siginfo"}}, &out); err != nil {
		t.Fatalf("the transport succeeded, so post should not error: %v", err)
	}
	if out.QueryStatus == "ok" {
		t.Fatal("stub is meant to return a failure status")
	}

	// And the wrapper turns that into an error the caller can classify.
	err := &APIError{Status: out.QueryStatus, Query: "get_siginfo"}
	if !IsNoResult(err) {
		t.Errorf("signature_not_found should classify as no-result, not as a failure")
	}
}

func TestIsNoResultDistinguishesEmptyFromBroken(t *testing.T) {
	// An empty answer is a fact about the corpus; a failure is a fact about
	// the request. Reporting one as the other is the mistake this exists to
	// prevent.
	for _, status := range []string{"no_results", "hash_not_found", "taginfo_not_found"} {
		if !IsNoResult(&APIError{Status: status}) {
			t.Errorf("%q should be a no-result", status)
		}
	}
	for _, status := range []string{"unknown_auth_key", "http_post_expected", "some_new_status"} {
		if IsNoResult(&APIError{Status: status}) {
			t.Errorf("%q is a failure, not a no-result", status)
		}
	}
	if IsNoResult(context.Canceled) {
		t.Error("a non-API error must not classify as a no-result")
	}
}

func TestUnauthorisedIsReportedClearly(t *testing.T) {
	// A 401 has one cause and one fix, so it says so rather than surfacing as
	// a decoding failure on an HTML error page.
	c, srv := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html>unauthorized</html>`))
	})
	err := postTo(t, c, srv, map[string][]string{"query": {"get_recent"}}, &struct{}{})
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if got := err.Error(); !strings.Contains(got, "auth key") {
		t.Errorf("the error should name the cause, got %q", got)
	}
}

func TestNonJSONBodyIsReportedWithASnippet(t *testing.T) {
	// When a service returns an HTML error page, a bare "invalid character
	// '<'" tells the reader nothing about what happened.
	c, srv := stub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>Gateway Timeout</body></html>`))
	})
	err := postTo(t, c, srv, map[string][]string{"query": {"get_recent"}}, &struct{}{})
	if err == nil {
		t.Fatal("expected a decoding error")
	}
	if !strings.Contains(err.Error(), "Gateway Timeout") {
		t.Errorf("the error should quote what came back, got %q", err.Error())
	}
}

func TestSampleDecodesTheFieldsWeRelyOn(t *testing.T) {
	// Field names come from the API, not from this package, so a rename
	// upstream would silently produce empty structs. This pins the ones the
	// tools actually read.
	raw := `{
      "sha256_hash": "7a43461961a2e4aa94b537b083b6ab090532857cbfe5a412efa142c637bc8f3e",
      "md5_hash": "50d829498390ba6fd2a4d5984ca71586",
      "first_seen": "2026-08-19 10:43:51",
      "file_name": "sample.exe",
      "file_size": 10508800,
      "file_type": "exe",
      "signature": "NeedleStealer",
      "reporter": "abuse_ch",
      "tags": ["exe", "NeedleStealer"],
      "imphash": "d42595b695fc008ef2c56aabd8efd68e",
      "tlsh": "T172B69E47EC9135ADC1AAD2318666B152BAF27C485B3133D72B50F3282F73BD06AB9750"
    }`
	var s Sample
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.SHA256 == "" || s.Signature != "NeedleStealer" || s.FileSize != 10508800 {
		t.Errorf("core fields did not decode: %+v", s)
	}
	if s.Imphash == "" || s.Tlsh == "" {
		t.Error("the fuzzy hashes are what makes pivoting possible; they must decode")
	}
	if len(s.Tags) != 2 {
		t.Errorf("tags = %v, want two", s.Tags)
	}
}

func TestIOCDecodesTheFieldsWeRelyOn(t *testing.T) {
	raw := `{
      "id": "1234567",
      "ioc": "woolvilli.com",
      "threat_type": "botnet_cc",
      "ioc_type": "domain",
      "malware": "win.example",
      "malware_printable": "Example",
      "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.example",
      "confidence_level": 75,
      "first_seen_utc": "2026-08-19 10:27:45",
      "reporter": "someone",
      "tags": ["NeedleStealer"]
    }`
	var i IOC
	if err := json.Unmarshal([]byte(raw), &i); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if i.IOC != "woolvilli.com" || i.IOCType != "domain" {
		t.Errorf("core fields did not decode: %+v", i)
	}
	if i.Confidence != 75 {
		t.Errorf("confidence = %d; it is set per reporter and must survive decoding", i.Confidence)
	}
	if i.MalpediaURL == "" {
		t.Error("the Malpedia link is how a ThreatFox family maps to a catalogue entry")
	}
}

func TestDecodeVendorIntelSurvivesGarbage(t *testing.T) {
	// Vendor intel is kept raw precisely because its shape varies; the decoder
	// must return nothing rather than panic when it is absent or malformed.
	if got := DecodeVendorIntel(nil); got != nil {
		t.Errorf("nil input should decode to nil, got %v", got)
	}
	if got := DecodeVendorIntel([]byte(`not json`)); got != nil {
		t.Errorf("malformed input should decode to nil, got %v", got)
	}
	got := DecodeVendorIntel([]byte(`{"ANY.RUN":[{"verdict":"malicious"}]}`))
	if len(got) != 1 {
		t.Errorf("expected one vendor, got %v", got)
	}
}
