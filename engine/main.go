// engine/main.go — Blue Whale Go Engine Wrapper
//
// A thin CLI wrapper around projectdiscovery tools (Katana, Nuclei, ffuf).
// This binary is called by sh/pipe.sh as a higher-level orchestration layer.
// It exposes sub-commands so the Bash bridge can invoke each phase independently.
//
// Build: go build -o ../bin/whale-engine .
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// EngineInfo describes this binary.
type EngineInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "info":
		info := EngineInfo{
			Name:    "whale-engine",
			Version: "1.0.0",
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)

	case "katana":
		runEngine("katana", args)

	case "nuclei":
		runEngine("nuclei", args)

	case "ffuf":
		runEngine("ffuf", args)

	case "check":
		checkDeps([]string{"katana", "nuclei", "ffuf", "jq"})

	default:
		fmt.Fprintf(os.Stderr, "Unknown sub-command: %s\n", sub)
		printUsage()
		os.Exit(1)
	}
}

// runEngine resolves the binary (local bin/ first, then PATH) and exec's it.
func runEngine(tool string, args []string) {
	bin := resolveBin(tool)
	if bin == "" {
		fmt.Fprintf(os.Stderr, "[engine] ERROR: '%s' not found in bin/ or $PATH.\n", tool)
		fmt.Fprintf(os.Stderr, "  Run 'python main.py bootstrap' to install dependencies.\n")
		os.Exit(2)
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[engine] Failed to run %s: %v\n", tool, err)
		os.Exit(1)
	}
}

// resolveBin looks for the binary in the local bin/ directory first,
// then falls back to $PATH.
func resolveBin(name string) string {
	// Determine project root (two levels up from this source file's directory
	// when running from source, or next to the binary at runtime)
	exe, err := os.Executable()
	if err == nil {
		localBin := filepath.Join(filepath.Dir(exe), name)
		if isExecutable(localBin) {
			return localBin
		}
	}
	// Fallback: system PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}

// checkDeps prints the availability of required tools as JSON.
func checkDeps(tools []string) {
	result := make(map[string]string, len(tools))
	for _, t := range tools {
		bin := resolveBin(t)
		if bin != "" {
			result[t] = bin
		} else {
			result[t] = "MISSING"
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)

	// Exit non-zero if any are missing
	for _, v := range result {
		if v == "MISSING" {
			os.Exit(3)
		}
	}
}

func printUsage() {
	fmt.Println(strings.TrimSpace(`
Blue Whale Engine — Go wrapper for security scanning tools.

Usage:
  whale-engine <sub-command> [args...]

Sub-commands:
  info           Print engine metadata as JSON.
  check          Check all required tool dependencies.
  katana [args]  Run Katana with the given arguments.
  nuclei [args]  Run Nuclei with the given arguments.
  ffuf   [args]  Run ffuf with the given arguments.

Build:
  cd engine && go build -o ../bin/whale-engine .
`))
}
