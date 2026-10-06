# pgp-personas

A command-line tool that does, in a test environment, what people do with their own OpenPGP keys in production: make a key, hand over the public key, and decrypt what is encrypted to them. One shell can then play every person.

**For test environments only.** Every secret key is unprotected, on one machine. In production each person makes and keeps their own key, often on a hardware token.

## Usage

Everyone's secret keys are in one keyring:

```bash
$ export PGP_PERSONAS_KEYRING=$PWD/keyring
```

Make a person, with their public key where the tool that encrypts to them reads it, and decrypt as that person, from stdin to stdout:

```bash
$ pgp-personas person --name alice --pubkey pubkeys/alice.gpg
$ pgp-personas decrypt --as alice < message.asc
```

Between two commands, such as those of [vault-ceremony](https://github.com/zinrai/vault-ceremony), the plaintext exists only in the pipe:

```bash
$ vault-ceremony key --as alice | pgp-personas decrypt --as alice | vault-ceremony unseal --as alice
```

A secret key outside the keyring, for a service that reads its key from a file, such as [vault-seal-dev](https://github.com/zinrai/vault-seal-dev):

```bash
$ pgp-personas secret-key --name 'development seal' --out seal-key/key.gpg
```

Keys are Ed25519 with a Curve25519 encryption subkey, as gpg makes by default. Each is made once: a key that exists is kept, since a new one could not decrypt what was encrypted to the old one. `person` writes the public key every time.

## License

This project is licensed under the [MIT License](./LICENSE).
