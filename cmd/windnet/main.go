package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/linkvectorized/windnet/pkg/capture"
	"github.com/linkvectorized/windnet/pkg/output"
)

var version = "0.1.0"

func main() {
	ver := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("windnet v%s\n", version)
		os.Exit(0)
	}

	hostname, _ := os.Hostname()
	platform := detectPlatform()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conns, err := capture.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	output.PrintTable(conns, hostname, platform, version)
}

func detectPlatform() string {
	switch {
	case fileExists("/System/Library/CoreServices/SystemVersion.plist"):
		return "macOS"
	case fileExists("/etc/os-release"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
