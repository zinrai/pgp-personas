package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestAPersonDecryptsWhatIsEncryptedToTheirPublicKey(t *testing.T) {
	inTestEnvironment(t)
	person(t, "alice", "pubkeys/alice.gpg")
	msg := encryptTo(t, "pubkeys/alice.gpg", "unseal key 1")
	if got := decryptAs(t, "alice", msg); got != "unseal key 1" {
		t.Fatalf("decrypted %q", got)
	}
}

func TestAPersonMadeAgainKeepsTheKeyThatDecryptsWhatWasEncryptedBefore(t *testing.T) {
	inTestEnvironment(t)
	person(t, "alice", "foundation/pubkeys/alice.gpg")
	msg := encryptTo(t, "foundation/pubkeys/alice.gpg", "unseal key 1")
	person(t, "alice", "workload/pubkeys/alice.gpg")
	if got := decryptAs(t, "alice", msg); got != "unseal key 1" {
		t.Fatalf("decrypted %q", got)
	}
}

func TestASecretKeyIsOneUnprotectedKeyThatDecrypts(t *testing.T) {
	inTestEnvironment(t)
	if err := runSecretKey([]string{"--name", "seal", "--out", "seal-key/key.gpg"}); err != nil {
		t.Fatal(err)
	}
	keys := readKeys(t, "seal-key/key.gpg")
	if len(keys) != 1 || keys[0].PrivateKey == nil || keys[0].PrivateKey.Encrypted {
		t.Fatalf("%d keys, want one unprotected secret key", len(keys))
	}
	msg := encryptTo(t, "seal-key/key.gpg", "root key")
	if got := decryptWith(t, keys, msg); got != "root key" {
		t.Fatalf("decrypted %q", got)
	}
}

func inTestEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PGP_PERSONAS_KEYRING", filepath.Join(t.TempDir(), "keyring"))
}

func person(t *testing.T, name, pubkey string) {
	t.Helper()
	if err := runPerson([]string{"--name", name, "--pubkey", pubkey}); err != nil {
		t.Fatal(err)
	}
}

func readKeys(t *testing.T, path string) openpgp.EntityList {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keys, err := openpgp.ReadKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func encryptTo(t *testing.T, keyFile, plaintext string) []byte {
	t.Helper()
	var out bytes.Buffer
	aw, _ := armor.Encode(&out, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(aw, readKeys(t, keyFile), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(plaintext))
	w.Close()
	aw.Close()
	return out.Bytes()
}

func decryptWith(t *testing.T, keys openpgp.EntityList, message []byte) string {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	md, err := openpgp.ReadMessage(block.Body, keys, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(md.UnverifiedBody)
	return string(b)
}

func decryptAs(t *testing.T, name string, message []byte) string {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	inW.Write(message)
	inW.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	err := runDecrypt([]string{"--as", name})
	os.Stdin, os.Stdout = oldIn, oldOut
	outW.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(outR)
	return string(b)
}
