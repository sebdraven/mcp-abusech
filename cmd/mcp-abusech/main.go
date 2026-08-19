// Command mcp-abusech serves the abuse.ch APIs — MalwareBazaar for samples,
// ThreatFox for indicators — over MCP.
//
// Unlike a corpus-backed server, every answer here comes from a live service.
// Nothing is cached and nothing is pinned: the same query tomorrow may return
// a different answer, which is why each result carries the time it was
// fetched.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-abusech/internal/abusech"
	"github.com/sebdraven/mcp-abusech/internal/mcptools"
	"github.com/sebdraven/mcp-abusech/internal/service"
)

// version is injected at build time with -ldflags "-X main.version=...".
// The default is deliberately "dev": a locally built binary that announces a
// release version lies to whoever reads it.
var version = "dev"

func main() {
	var (
		family  = flag.String("family", "", "list samples for a malware family and exit")
		hash    = flag.String("hash", "", "look up one sample by hash and exit")
		ioc     = flag.String("ioc", "", "look up one indicator and exit")
		tag     = flag.String("tag", "", "list indicators carrying a tag and exit")
		limit   = flag.Int("limit", 50, "max results for the one-shot lookups")
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
	ctx := context.Background()

	// One-shot lookups: the cheapest way to check the key works and to see
	// what a family looks like before wiring the server into anything.
	switch {
	case *family != "":
		res, err := svc.SamplesByFamily(ctx, *family, *limit)
		exitWith(res, err)
	case *hash != "":
		res, err := svc.SampleByHash(ctx, *hash)
		exitWith(res, err)
	case *ioc != "":
		res, err := svc.SearchIOC(ctx, *ioc)
		exitWith(res, err)
	case *tag != "":
		res, err := svc.IOCsByTag(ctx, *tag, *limit)
		exitWith(res, err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "abusech",
		Version: version,
	}, nil)
	mcptools.Register(server, svc)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// authKey finds the abuse.ch auth key.
//
// The environment variable is the only portable answer: it works in a
// container, on Linux and in any MCP client. The macOS keychain is consulted
// as a convenience where it exists, so a key does not have to sit in cleartext
// in a client's configuration file — but nothing depends on it.
func authKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ABUSECH_AUTH_KEY")); k != "" {
		return k, nil
	}
	if runtime.GOOS == "darwin" {
		// Short deadline: this is a convenience, and a keychain prompt that
		// never gets answered would hang a server nobody can see.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", "find-generic-password",
			"-s", "mb-api.abuse.ch", "-w").Output()
		if err == nil {
			if k := strings.TrimSpace(string(out)); k != "" {
				return k, nil
			}
		}
	}
	return "", fmt.Errorf("no abuse.ch auth key: set ABUSECH_AUTH_KEY.\n" +
		"Both MalwareBazaar and ThreatFox have required authentication since 2024; get a key at https://auth.abuse.ch/\n" +
		"On macOS the key can instead be stored in the keychain under the service name mb-api.abuse.ch")
}

func exitWith(v any, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encoding result: %v", err)
	}
	os.Exit(0)
}
