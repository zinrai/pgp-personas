// Command pgp-personas keeps everyone's secret keys on one machine,
// unprotected, not each on its owner's own token: in a test environment one
// shell plays every person.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
)

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

var commands = []command{
	{"person", "make a person's key in the keyring, their public key into --pubkey", runPerson},
	{"decrypt", "decrypt stdin to stdout --as a person", runDecrypt},
	{"secret-key", "make one secret key, outside the keyring, into --out", runSecretKey},
	{"version", "print the version and exit", runVersion},
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: pgp-personas <command> [--flag value]...\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-11s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(os.Stderr, `
For test environments only: every secret key here is unprotected, on one
machine. In production each person makes and keeps their own key. The
keyring is PGP_PERSONAS_KEYRING.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	i := slices.IndexFunc(commands, func(c command) bool { return c.name == name })
	if i < 0 {
		if name != "-h" && name != "--help" && name != "help" {
			fmt.Fprintf(os.Stderr, "pgp-personas: unknown command %q\n\n", name)
		}
		usage()
		os.Exit(2)
	}
	err := commands[i].run(os.Args[2:])
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgp-personas %s: %v\n", name, err)
		os.Exit(1)
	}
}

func newFlags(name, help string) *flag.FlagSet {
	fs := flag.NewFlagSet("pgp-personas "+name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: pgp-personas %s\n\n%s\n", name, help)
		fs.PrintDefaults()
	}
	return fs
}

// Flags only, never a positional argument: every command reads the same
// way.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q: every value is given with a flag", fs.Arg(0))
	}
	return nil
}

func required(flags map[string]string) error {
	var missing []string
	for name, value := range flags {
		if value == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("%s required", strings.Join(missing, ", "))
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Made once, not on every run: a new key could not decrypt what was
// encrypted to the old one.
func kept(path string) bool {
	if !exists(path) {
		return false
	}
	fmt.Printf("%s: kept\n", path)
	return true
}
