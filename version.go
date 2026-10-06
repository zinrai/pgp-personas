package main

import "fmt"

// Placeholders, not empty: a locally built binary reports these, and
// goreleaser overwrites them via -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func runVersion(args []string) error {
	if err := parse(newFlags("version", "Print the version."), args); err != nil {
		return err
	}
	fmt.Printf("pgp-personas version %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
	return nil
}
