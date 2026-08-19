# mcp-abusech

An MCP server and a TUI over the [abuse.ch](https://abuse.ch/) APIs:
[MalwareBazaar](https://bazaar.abuse.ch/) for malware samples and
[ThreatFox](https://threatfox.abuse.ch/) for indicators of compromise.

It answers two questions that come up constantly when reading a threat report:
*which samples exist for this family name*, and *has anyone reported this
domain, IP or hash*.

---

## What it is not

**Not a corpus.** Every answer comes from a live service. Nothing is cached and
nothing is pinned, so the same query tomorrow may return more samples, fewer, or
the same ones classified differently. Each result carries the time it was
fetched, because that timestamp is the only provenance available — unlike a
sibling server that answers from a corpus pinned to a commit and can reproduce a
result exactly.

**Not ground truth.** MalwareBazaar signatures come from submitter tags and
automated rules rather than from published analysis, and ThreatFox aggregates
community submissions with a per-reporter confidence level. Both are useful and
neither is authoritative. An absent family may simply never have been submitted;
an absent indicator says nothing about whether it is malicious.

---

## Setup

Both APIs have required authentication since 2024. Get a key at
[auth.abuse.ch](https://auth.abuse.ch/), then either export it:

```
export ABUSECH_AUTH_KEY=...
```

or store it in the macOS keychain under the API host, which is the convention
the sibling servers use so one entry serves every tool talking to a vendor:

```
security add-generic-password -s mb-api.abuse.ch -a "$USER" -w
```

Build:

```
go build -o bin/mcp-abusech ./cmd/mcp-abusech
go build -o bin/abusech-tui ./cmd/abusech-tui
```

---

## One-shot lookups

The quickest way to check the key works and to see what a family looks like:

```
bin/mcp-abusech -family NeedleStealer -limit 5
bin/mcp-abusech -hash 7a43461961a2e4aa94b537b083b6ab090532857cbfe5a412efa142c637bc8f3e
bin/mcp-abusech -tag NeedleStealer
bin/mcp-abusech -ioc woolvilli.com
```

Each prints JSON and exits.

---

## MCP

Add to your client's configuration:

```json
"abusech": {
  "command": "/path/to/mcp-abusech",
  "env": { "ABUSECH_AUTH_KEY": "..." }
}
```

On macOS the env block can be omitted if the key is in the keychain.

### Tools

| Tool | Answers |
|---|---|
| `ab_samples` | which samples MalwareBazaar attributes to a family |
| `ab_sample` | what is known about one hash |
| `ab_recent_samples` | what has been submitted lately |
| `ab_iocs` | which indicators ThreatFox attributes to a family |
| `ab_iocs_by_tag` | which indicators carry a tag |
| `ab_search_ioc` | has this domain, IP or hash been reported |
| `ab_recent_iocs` | what has been reported over the last days |

**A note on family lookups.** ThreatFox identifies families by Malpedia
identifier — `win.example`, `apk.example` — while MalwareBazaar uses free-form
signatures and tags carry whatever reporters typed. So a plain vendor name works
with `ab_samples` and `ab_iocs_by_tag` but often returns nothing from `ab_iocs`.
The tool descriptions say so, but it is the first thing that trips people up.

---

## TUI

```
bin/abusech-tui
```

Type a query, press enter. `tab` cycles the lookup — samples by family, sample
by hash, indicators by tag, indicator search — because abuse.ch has no single
search endpoint and guessing which one you meant would turn a wrong choice into
an unexplained "no results".

`space` marks a row, `esc` quits, and marked rows print to stdout on exit, led
by the query and the retrieval time. A list of hashes with no record of what was
asked, or when, is not much use a week later.

```
bin/abusech-tui -marks json > leads.json
```

---

## Known gaps

**No URLhaus.** It is the third abuse.ch service and would fit here, but it has
its own query shapes and nothing has needed it yet.

**No pagination.** The APIs cap results and this passes the cap through; a
family with thousands of samples returns the most recent slice, and there is
currently no way to walk past it.

**Rate limits are not handled.** A 429 is reported as an error rather than
retried, on the grounds that a tool which silently waits is worse than one that
says it was throttled.
