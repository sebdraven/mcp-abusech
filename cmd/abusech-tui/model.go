package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sebdraven/mcp-abusech/internal/service"
)

// mode is which lookup the search box performs.
//
// abuse.ch has no single search: samples and indicators live in different
// services with different query shapes, and a family name that works in one
// often returns nothing in the other. Making the mode explicit and visible is
// less magical than guessing, and guessing wrong here reads as "nothing found"
// rather than "wrong endpoint".
type mode int

const (
	modeFamily mode = iota // MalwareBazaar samples by signature
	modeHash               // MalwareBazaar single sample
	modeTag                // ThreatFox indicators by tag
	modeIOC                // ThreatFox single indicator
)

func (m mode) String() string {
	switch m {
	case modeFamily:
		return "samples by family"
	case modeHash:
		return "sample by hash"
	case modeTag:
		return "indicators by tag"
	default:
		return "indicator lookup"
	}
}

func (m mode) hint() string {
	switch m {
	case modeFamily:
		return "a MalwareBazaar signature, e.g. NeedleStealer"
	case modeHash:
		return "MD5, SHA-1 or SHA-256"
	case modeTag:
		return "a ThreatFox tag, as reporters typed it"
	default:
		return "a domain, URL, IP:port or hash"
	}
}

// row is one result line, flattened so samples and indicators share a view.
type row struct {
	primary   string // hash or indicator
	kind      string // file type or indicator type
	family    string
	firstSeen string
	detail    string
}

func (r row) key() string { return r.kind + "\x00" + r.primary }

type model struct {
	svc     *service.Service
	version string

	input   textinput.Model
	mode    mode
	rows    []row
	cursor  int
	marked  map[string]bool
	loading bool

	lastQuery   string
	retrievedAt string
	note        string
	status      string
	err         string
	width       int
	height      int
}

type resultMsg struct {
	rows        []row
	note        string
	retrievedAt string
	query       string
	err         string
}

var (
	styTitle  = lipgloss.NewStyle().Bold(true)
	styDim    = lipgloss.NewStyle().Faint(true)
	styMark   = lipgloss.NewStyle().Bold(true)
	styCursor = lipgloss.NewStyle().Reverse(true)
	styWarn   = lipgloss.NewStyle().Italic(true)
)

func newModel(svc *service.Service, version string) model {
	ti := textinput.New()
	ti.Placeholder = modeFamily.hint()
	ti.Focus()
	ti.CharLimit = 200
	return model{
		svc: svc, version: version,
		input:  ti,
		marked: map[string]bool{},
		status: "type a name and press enter · tab switches lookup",
	}
}

func (m model) Init() tea.Cmd { return textinput.Blink }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case resultMsg:
		m.loading = false
		m.err = msg.err
		m.rows = msg.rows
		m.note = msg.note
		m.retrievedAt = msg.retrievedAt
		m.lastQuery = msg.query
		m.cursor = 0
		if msg.err == "" {
			m.status = fmt.Sprintf("%d result(s)", len(msg.rows))
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "tab":
			m.mode = (m.mode + 1) % 4
			m.input.Placeholder = m.mode.hint()
			m.status = "lookup: " + m.mode.String()
			return m, nil
		case "enter":
			q := strings.TrimSpace(m.input.Value())
			if q == "" {
				return m, nil
			}
			m.loading = true
			m.err = ""
			m.status = "querying abuse.ch…"
			return m, m.search(q, m.mode)
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < len(m.rows)-1 {
				m.cursor++
			}
			return m, nil
		case " ":
			if m.cursor < len(m.rows) {
				k := m.rows[m.cursor].key()
				if m.marked[k] {
					delete(m.marked, k)
				} else {
					m.marked[k] = true
				}
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// search runs the lookup off the update loop, so the UI keeps redrawing while
// the network call is in flight. The sibling server answers from memory and
// never needed this; here every query is a round trip.
func (m model) search(q string, md mode) tea.Cmd {
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		switch md {
		case modeFamily:
			res, err := svc.SamplesByFamily(ctx, q, 200)
			if err != nil {
				return resultMsg{query: q, err: err.Error()}
			}
			return resultMsg{rows: sampleRows(res), note: res.Note, retrievedAt: res.RetrievedAt, query: q}
		case modeHash:
			res, err := svc.SampleByHash(ctx, q)
			if err != nil {
				return resultMsg{query: q, err: err.Error()}
			}
			return resultMsg{rows: sampleRows(res), note: res.Note, retrievedAt: res.RetrievedAt, query: q}
		case modeTag:
			res, err := svc.IOCsByTag(ctx, q, 200)
			if err != nil {
				return resultMsg{query: q, err: err.Error()}
			}
			return resultMsg{rows: iocRows(res), note: res.Note, retrievedAt: res.RetrievedAt, query: q}
		default:
			res, err := svc.SearchIOC(ctx, q)
			if err != nil {
				return resultMsg{query: q, err: err.Error()}
			}
			return resultMsg{rows: iocRows(res), note: res.Note, retrievedAt: res.RetrievedAt, query: q}
		}
	}
}

func sampleRows(res service.SampleResult) []row {
	out := make([]row, 0, len(res.Samples))
	for _, s := range res.Samples {
		out = append(out, row{
			primary: s.SHA256, kind: s.FileType, family: s.Signature,
			firstSeen: s.FirstSeen,
			detail:    fmt.Sprintf("%s · %d bytes", s.FileName, s.FileSize),
		})
	}
	return out
}

func iocRows(res service.IOCResult) []row {
	out := make([]row, 0, len(res.IOCs))
	for _, i := range res.IOCs {
		family := i.MalwarePrintable
		if family == "" {
			family = i.Malware
		}
		out = append(out, row{
			primary: i.IOC, kind: i.IOCType, family: family,
			firstSeen: i.FirstSeen,
			// Confidence is per-reporter and carried into the row, because a
			// list of indicators read without it invites treating a 25 the
			// same as a 100.
			detail: fmt.Sprintf("%s · confidence %d", i.ThreatType, i.Confidence),
		})
	}
	return out
}

func (m model) View() string {
	var b strings.Builder

	header := styTitle.Render("abuse.ch")
	if m.version != "" {
		header += " " + styDim.Render(m.version)
	}
	header += "  " + styDim.Render(m.mode.String())
	if m.retrievedAt != "" {
		header += "  " + styDim.Render("retrieved "+m.retrievedAt)
	}
	b.WriteString(header + "\n\n")
	b.WriteString(m.input.View() + "\n\n")

	switch {
	case m.loading:
		b.WriteString(styDim.Render("querying abuse.ch…") + "\n")
	case m.err != "":
		b.WriteString(styWarn.Render("error: "+m.err) + "\n")
	case len(m.rows) == 0 && m.lastQuery != "":
		b.WriteString(styDim.Render("no results") + "\n")
	}

	visible := m.height - 10
	if visible < 3 {
		visible = 3
	}
	start := 0
	if m.cursor >= visible {
		start = m.cursor - visible + 1
	}
	for i := start; i < len(m.rows) && i < start+visible; i++ {
		r := m.rows[i]
		prefix := "  "
		if m.marked[r.key()] {
			prefix = styMark.Render("* ")
		}
		line := fmt.Sprintf("%s%-64s %-10s %s", prefix, truncate(r.primary, 64), r.kind, r.family)
		if i == m.cursor {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.note != "" {
		b.WriteString("\n" + styWarn.Render(wrap(m.note, m.width-2)) + "\n")
	}
	b.WriteString("\n" + styDim.Render(m.status+" · space marks · tab switches · esc quits"))
	if n := len(m.marked); n > 0 {
		b.WriteString(styDim.Render(fmt.Sprintf(" · %d marked", n)))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func wrap(s string, width int) string {
	if width < 20 {
		width = 20
	}
	var out strings.Builder
	line := 0
	for _, w := range strings.Fields(s) {
		if line+len(w)+1 > width {
			out.WriteString("\n")
			line = 0
		} else if line > 0 {
			out.WriteString(" ")
			line++
		}
		out.WriteString(w)
		line += len(w)
	}
	return out.String()
}
