package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linkvectorized/windnet/pkg/capture"
	"github.com/linkvectorized/windnet/pkg/output"
)

const version = "0.1.0"

func main() {
	live     := flag.Bool("live", false, "Continuously refresh connections (live mode)")
	interval := flag.Int("interval", 5, "Refresh interval in seconds (live mode only)")
	ver      := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("windnet v%s\n", version)
		os.Exit(0)
	}

	hostname, _ := os.Hostname()
	platform := detectPlatform()

	if *live {
		runLive(hostname, platform, *interval)
	} else {
		runOnce(hostname, platform)
	}
}

func runOnce(hostname, platform string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conns, err := capture.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	output.PrintTable(conns, hostname, platform, version, false, 0)
}

func runLive(hostname, platform string, interval int) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	tick := time.NewTicker(time.Duration(interval) * time.Second)
	defer tick.Stop()

	// Run immediately on start
	scan(hostname, platform, interval)

	for {
		select {
		case <-tick.C:
			scan(hostname, platform, interval)
		case <-sig:
			fmt.Println("\nSignal received. Scanning complete.")
			return
		}
	}
}

func scan(hostname, platform string, interval int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conns, err := capture.Scan(ctx)
	if err != nil {
		// Don't fatal in live mode — show empty state
		conns = nil
	}

	output.PrintTable(conns, hostname, platform, version, true, interval)
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
