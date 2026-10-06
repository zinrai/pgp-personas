package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Ed25519 with a Curve25519 encryption subkey, not RSA: what gpg makes by
// default, so any OpenPGP tool reads these keys and encrypts to them.
var keyConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519}

// From the environment only, not a flag: decrypt runs between two commands
// in a pipe, and the same people keep the same keys wherever they are used.
func personKeyPath(name string) (string, error) {
	dir := os.Getenv("PGP_PERSONAS_KEYRING")
	if dir == "" {
		return "", errors.New("PGP_PERSONAS_KEYRING, the directory of everyone's secret keys, is required")
	}
	return filepath.Join(dir, name+".gpg"), nil
}

func runPerson(args []string) error {
	fs := newFlags("person", "Make a person's key in the keyring, once, and write their public key, binary,\nto --pubkey.")
	name := fs.String("name", "", "the person (required)")
	pubkey := fs.String("pubkey", "", "file to write the public key to (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required(map[string]string{"name": *name, "pubkey": *pubkey}); err != nil {
		return err
	}
	e, err := personKey(*name)
	if err != nil {
		return err
	}
	if err := writePublicKey(e, *pubkey); err != nil {
		return err
	}
	fmt.Println(*pubkey)
	return nil
}

func runDecrypt(args []string) error {
	fs := newFlags("decrypt", "Decrypt an OpenPGP message, armored or binary, from stdin to stdout with a\nperson's key: what that person does with their own tool in production.")
	as := fs.String("as", "", "the person whose key decrypts (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required(map[string]string{"as": *as}); err != nil {
		return err
	}
	path, err := personKeyPath(*as)
	if err != nil {
		return err
	}
	e, err := readSecretKey(path)
	if err != nil {
		return err
	}
	plain, err := decrypt(e, os.Stdin)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plain)
	return err
}

func runSecretKey(args []string) error {
	fs := newFlags("secret-key", "Make one secret key, binary, with no passphrase, once, into --out: for a\nservice that reads its key from a file. Anyone who can read the file has the key.")
	out := fs.String("out", "", "file to write (required)")
	name := fs.String("name", "", "the key's user ID (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required(map[string]string{"out": *out, "name": *name}); err != nil {
		return err
	}
	if kept(*out) {
		return nil
	}
	// 0755, not 0700: the key itself is 0600, and a service that runs in
	// the owner's group can then be let read it.
	if err := writeNewKey(*out, *name, 0o755); err != nil {
		return err
	}
	fmt.Println(*out)
	return nil
}

// Made once, not each time: the same person is made again for each place
// their public key is needed, and must keep the key that decrypts what was
// encrypted to them before.
func personKey(name string) (*openpgp.Entity, error) {
	path, err := personKeyPath(name)
	if err != nil {
		return nil, err
	}
	if !exists(path) {
		if err := writeNewKey(path, name, 0o700); err != nil {
			return nil, err
		}
	}
	return readSecretKey(path)
}

// Written every time, not once: the same person's public key may be
// needed in more than one place.
func writePublicKey(e *openpgp.Entity, path string) error {
	var pub bytes.Buffer
	if err := e.Serialize(&pub); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, pub.Bytes(), 0o644)
}

func decrypt(e *openpgp.Entity, r io.Reader) ([]byte, error) {
	in, err := dearmor(r)
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(in, openpgp.EntityList{e}, nil, nil)
	if err != nil {
		return nil, err
	}
	// Read to the end before returning, not as it arrives: OpenPGP reports
	// a tampered message only once its body has been read.
	return io.ReadAll(md.UnverifiedBody)
}

// No passphrase: one shell plays every person, unattended, and a service
// cannot type one.
func writeNewKey(path, name string, dirMode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	e, err := openpgp.NewEntity(name, "", "", keyConfig)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func readSecretKey(path string) (*openpgp.Entity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ring, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(ring) != 1 || ring[0].PrivateKey == nil {
		return nil, fmt.Errorf("%s: want exactly one secret key", path)
	}
	return ring[0], nil
}

func dearmor(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(5)
	if len(head) == 0 {
		return nil, errors.New("no message on stdin")
	}
	if string(head) != "-----" {
		return br, nil
	}
	block, err := armor.Decode(br)
	if err != nil {
		return nil, err
	}
	return block.Body, nil
}
