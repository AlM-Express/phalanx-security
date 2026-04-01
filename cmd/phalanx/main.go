package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const banner = `
  ██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
  ██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
  Zero-Trust Node.js Supply Chain Security  v1.1.0
  ══════════════════════════════════════════════════════════
`

// runPhalanx spawns a fresh phalanx subprocess with the given arguments.
// This avoids cobra internal state corruption when running multiple commands
// in the same process lifetime.
func runPhalanx(args ...string) {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("  [ERROR] Could not locate phalanx executable:", err)
		return
	}

	cwd, _ := os.Getwd()
	cmd := exec.Command(exePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Dir = cwd

	if err := cmd.Run(); err != nil {
		// Non-zero exit (e.g. BLOCK action) is expected — don't treat as crash
		if exitErr, ok := err.(*exec.ExitError); ok {
			_ = exitErr // exit code already printed by the subprocess
		} else {
			fmt.Println("  [ERROR]", err)
		}
	}
}

func runInteractiveMenu() {
	fmt.Print(banner)
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("  What would you like to do?")
		fmt.Println()
		fmt.Println("  [1]  audit        — Scan existing node_modules for threats")
		fmt.Println("  [2]  install      — Securely install packages (replaces npm install)")
		fmt.Println("  [3]  install safe — Install with ALL scripts permanently disabled")
		fmt.Println("  [4]  trust-lock   — Save a cryptographic snapshot of node_modules")
		fmt.Println("  [5]  verify       — Check node_modules for tampering since last snapshot")
		fmt.Println("  [q]  quit")
		fmt.Println()
		fmt.Print("  Enter choice: ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()

		switch choice {
		case "1", "audit":
			runPhalanx("audit")
		case "2", "install":
			runPhalanx("install")
		case "3", "install safe":
			runPhalanx("install", "--safe")
		case "4", "trust-lock":
			runPhalanx("trust-lock")
		case "5", "verify":
			runPhalanx("verify")
		case "q", "quit", "exit":
			fmt.Println("  Goodbye. Stay secure.")
			fmt.Println()
			os.Exit(0)
		default:
			fmt.Println("  Invalid choice. Please enter 1-5 or q.")
			continue
		}

		fmt.Println()
		fmt.Println("  ══════════════════════════════════════════════════════════")
		fmt.Print("  Press Enter to return to the menu...")
		scanner.Scan()
	}
}

func main() {
	// If launched with no arguments (e.g. double-clicked), show interactive menu
	if len(os.Args) == 1 {
		runInteractiveMenu()
		return
	}

	// Otherwise behave as a normal CLI tool
	if err := Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
