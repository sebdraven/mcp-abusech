// Command abusech-tui browses MalwareBazaar samples and ThreatFox indicators
// interactively.
//
// Deliberately not a graph explorer like its sibling: abuse.ch returns lists,
// not a graph, so this is a search box over a scrollable result set with
// marking and export. What it does share is the marking workflow — space to
// mark, output on exit — because that is how a lookup turns into something you
// can paste into a report.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/sebdraven/mcp-abusech/internal/abusech"
	"github.com/sebdraven/mcp-abusech/internal/service"
)

var version = "dev"

func main() {
	var (
		markFmt = flag.String("marks", "text", "how to print marked entries on exit: text or json")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	key, err := authKey()
	if err != nil {
		log.Fatalf("%v", err)
	}
	svc := service.New(abusech.New(key))

	p := tea.NewProgram(newModel(svc, version), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		log.Fatalf("tui: %v", err)
	}

	// Marks go to stdout after the alt screen is torn down, so they survive
	// the session and can be piped.
	m, ok := final.(model)
	if !ok || len(m.marked) == 0 {
		return
	}
	printMarks(m, *markFmt)
}

func authKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ABUSECH_AUTH_KEY")); k != "" {
		return k, nil
	}
	out, err := exec.Command("security", "find-generic-password",
		"-s", "mb-api.abuse.ch", "-w").Output()
	if err == nil {
		if k := strings.TrimSpace(string(out)); k != "" {
			return k, nil
		}
	}
	return "", fmt.Errorf("no abuse.ch auth key: set ABUSECH_AUTH_KEY, or store one in the keychain under the service name mb-api.abuse.ch")
}

func printMarks(m model, format string) {
	type mark struct {
		Value     string `json:"value"`
		Kind      string `json:"kind"`
		Family    string `json:"family,omitempty"`
		FirstSeen string `json:"first_seen,omitempty"`
	}
	var marks []mark
	for _, row := range m.rows {
		if !m.marked[row.key()] {
			continue
		}
		marks = append(marks, mark{
			Value: row.primary, Kind: row.kind,
			Family: row.family, FirstSeen: row.firstSeen,
		})
	}
	if format == "json" {
		out := struct {
			Query       string `json:"query"`
			RetrievedAt string `json:"retrieved_at"`
			Marks       []mark `json:"marks"`
		}{m.lastQuery, m.retrievedAt, marks}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	// The query and timestamp lead the text output too: a list of hashes with
	// no record of what was asked, or when, is not much use a week later.
	fmt.Printf("# %s — retrieved %s\n", m.lastQuery, m.retrievedAt)
	for _, mk := range marks {
		if mk.Family != "" {
			fmt.Printf("%s\t%s\t%s\n", mk.Value, mk.Kind, mk.Family)
			continue
		}
		fmt.Printf("%s\t%s\n", mk.Value, mk.Kind)
	}
}
