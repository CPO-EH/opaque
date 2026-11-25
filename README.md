# OPAQUE

This is a fork of [bytemare/opaque](https://github.com/bytemare/opaque) that adds
a hybrid post-quantum key exchange (3DH combined with ML-KEM). The classical
RFC 9807 behavior is unchanged and remains the default. See
[Post-quantum hybrid mode](#post-quantum-hybrid-mode) for what was added and why.
The badges below refer to the upstream project.

[![CI](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)
[![codecov](https://codecov.io/gh/bytemare/opaque/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/opaque)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bytemare/opaque/badge)](https://scorecard.dev/viewer/?uri=github.com/bytemare/opaque)

```go
  import "github.com/bytemare/opaque"
```

This package implements [OPAQUE (RFC 9807)](https://datatracker.ietf.org/doc/rfc9807),
the augmented password-authenticated key exchange (aPAKE) protocol that is
secure against pre-computation attacks. It enables a client to authenticate to
a server without ever revealing its password to the server.

This implementation is developed and maintained by one of the authors of the
[RFC](https://datatracker.ietf.org/doc/rfc9807). It has not been independently audited,
and even though great care about security and performance has been taken, it
comes with no warranty.

## What is OPAQUE?

> OPAQUE is an aPAKE that is secure against pre-computation attacks. OPAQUE
> provides forward secrecy with respect to password leakage while also hiding
> the password from the server, even during password registration. OPAQUE allows
> applications to increase the difficulty of offline dictionary attacks via
> iterated hashing or other key stretching schemes. OPAQUE is also extensible,
> allowing clients to safely store and retrieve arbitrary application data on
> servers using only their password.

## References

- [The original paper](https://eprint.iacr.org/2018/163.pdf) from Jarecki, Krawczyk, and Xu.
- [RFC 9807](https://datatracker.ietf.org/doc/rfc9807).
- [OPAQUE in WhatsApp](https://www.whatsapp.com/security/WhatsApp_Security_Encrypted_Backups_Whitepaper.pdf)
  to enable end-to-end encrypted backups.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/opaque).

## Post-quantum hybrid mode

### Why

In RFC 9807, the login key exchange (3DH) relies only on elliptic curve
Diffie-Hellman. Shor's algorithm breaks the discrete logarithm problem, so an
attacker who records login traffic today could derive the session keys once a
large enough quantum computer exists. This is the "harvest now, decrypt later"
threat, and it matters for any data that has to stay confidential for years.

### What this fork adds

An optional ML-KEM exchange ([FIPS 203](https://doi.org/10.6028/NIST.FIPS.203))
runs alongside 3DH during login. The client generates a fresh ML-KEM key pair
for each login, the server encapsulates a secret to it, and that secret is mixed
into the key derivation together with the three Diffie-Hellman results. An
attacker has to break both elliptic curve Diffie-Hellman and ML-KEM to recover
the session key. If ML-KEM turns out to have a flaw, security falls back to
plain RFC 9807, and if the curve is broken by a quantum computer, ML-KEM still
protects the session.

ML-KEM comes from the Go standard library (`crypto/mlkem`), so no new
dependency is needed.

### Usage

```go
// Ristretto255, SHA-512, Argon2id and ML-KEM-768.
conf := opaque.DefaultHybridConfiguration()

// Or enable it on any existing configuration.
conf.KEM = opaque.MLKEM768 // or opaque.MLKEM1024
```

The rest of the API is the same. Client and server must use the same `KEM`
value. Records created during registration do not change, so users registered
with a classical configuration can log in with the hybrid one without
registering again.

Because this fork keeps the module path `github.com/bytemare/opaque`, point Go
to it with a replace directive:

```shell
go mod edit -replace github.com/bytemare/opaque=github.com/CPO-EH/opaque@main
go mod tidy
```

### Protocol changes

The full specification, precise enough to write a compatible implementation in
another language, is in [docs/hybrid-mlkem.md](docs/hybrid-mlkem.md). This is
a summary.

These changes only apply when a KEM is set. With `KEM` left at `NoKEM`, the
messages and transcripts are byte for byte the same as RFC 9807, and the RFC
test vectors still pass.

- KE1 ends with the client's ephemeral ML-KEM encapsulation key, after the
  client key share.
- KE2 contains the ML-KEM ciphertext between the server key share and the
  server MAC.
- The input keying material becomes `DH1 || DH2 || DH3 || ss_KEM`.
- The ciphertext is appended to the transcript hash. The encapsulation key is
  already covered because KE1 is hashed in full. Both MACs therefore
  authenticate the KEM exchange, and a substituted key or ciphertext makes the
  login fail.
- The transcript prefix changes from `OPAQUEv1-` to
  `OPAQUEv1-Hybrid-ML-KEM-768-` (or `-ML-KEM-1024-`), so a hybrid transcript can
  never be mistaken for a classical one.
- When a KEM is set, the serialized `Configuration` gets one extra byte at the
  end. Configurations serialized before this change still decode.
- The server validates the encapsulation key as required by FIPS 203 before
  using it.

Message sizes grow as follows:

| Parameter set | KE1     | KE2     |
|---------------|---------|---------|
| ML-KEM-768    | +1184 B | +1088 B |
| ML-KEM-1024   | +1568 B | +1568 B |

Registration messages are unchanged.

### Session resumption

If a login is started on one client instance and finished on another, the
second instance needs the 64-byte seed of the ML-KEM key in addition to the
values already required. Pass it in `AKEOptions.KEMSeed` for both
`GenerateKE1` and `GenerateKE3`. Treat it with the same care as the ephemeral
secret key share. `Client.ClearState()` wipes it.

### Tests

`tests/hybrid_test.go` runs every case on all supported groups with both
ML-KEM-768 and ML-KEM-1024. It covers:

- full registration and login, with matching session keys on both sides
- message sizes
- a tampered ciphertext and a substituted encapsulation key, both rejected
- mixing hybrid and classical peers, which is refused
- malformed encapsulation keys
- session resumption, including a missing, duplicated or wrong-length seed
- configuration encoding and decoding

### Test vectors

[tests/hybrid_vectors.json](tests/hybrid_vectors.json) contains 8 test vectors
(ristretto255 and P-256, with and without explicit identities, each with
ML-KEM-768 and ML-KEM-1024). They reuse the inputs of the RFC 9807 vectors and
add a fixed ML-KEM seed for the client and fixed encapsulation randomness for
the server, so every message and key is reproducible. Another implementation
is compatible if it produces the same bytes. Section 8 of the specification
describes the format.

`tests/hybrid_vectors_test.go` checks the vectors in two ways: the library
must reproduce them, and a separate computation of the key schedule written
from the specification, using only the Go standard library, must agree with
them. To regenerate the file:

```shell
go test ./tests -run TestHybridVectors -update-hybrid-vectors
```

The server option `AKEOptions.KEMRandomness` exists only to produce these
vectors. Never set it in production: anyone who knows that value can compute
the KEM shared secret.

### Limitations

This mode protects the confidentiality of past sessions. It does not make the
whole protocol post-quantum.

- It is not part of RFC 9807. Hybrid peers cannot talk to RFC 9807
  implementations or to classical peers.
- Authentication still relies on the static elliptic curve keys. An attacker
  with a quantum computer who is active during a login could impersonate the
  server.
- The OPRF is still based on elliptic curves. An attacker with a quantum
  computer who obtains a login transcript and the server's OPRF key could run
  an offline dictionary attack on the password.
- The construction has not been formally analyzed or audited.

Planned next steps are post-quantum authentication, using a static KEM key for
the server in the style of KEMTLS, and a post-quantum OPRF.

## Security and Operational Notes

- Use a confidential transport (e.g., TLS 1.3+) to protect client identities on
  the wire.
- Keep the OPRF global seed single and stable across clients, and derive unique
  per-client OPRF keys using a stable, unique credential identifier.
- Ensure consistent configuration (groups, hashes, KSF) across registration and
  subsequent logins.
- The server must always verify KE3 with `LoginFinish` before using the session
  secret.
- For unknown users, return a fake record (`GetFakeRecord`) to reduce
  user-enumeration signals.
- Rate limiting and replay tracking are application layer responsibilities. OPAQUE
  authenticates the transcripts, and session management is up to you.
- The server is concurrency-safe for typical use. Avoid a hidden global state in
  your app layer.
- Store `ServerKeyMaterial` securely. Treat secrets (e.g., private key and OPRF
  seed) appropriately.
- `Client.ClearState()` is a best-effort to clear ephemeral material, but zeroization
  has language/runtime limits.

## Versioning

[SemVer](https://semver.org) is used for versioning. For the versions
available, see the [tags on the repository](https://github.com/bytemare/opaque/tags).

## Release Integrity (SLSA Level 3)
This section describes the upstream bytemare/opaque releases, not this fork. Upstream releases are built with the reusable [bytemare/slsa](https://github.com/bytemare/slsa) workflow and ship the evidence required for SLSA Level 3 compliance:

- Artifacts are uploaded to the release page, and include the deterministic source archive plus subjects.sha256, signed SBOM (sbom.cdx.json), GitHub provenance (*.intoto.jsonl), a reproducibility report (verification.json), and a signed Verification Summary Attestation (verification-summary.attestation.json[.bundle]).
- All artifacts are signed using [Sigstore](https://sigstore.dev) with transparency via [Rekor](https://rekor.sigstore.dev).
- Verification (or see the latest docs at [bytemare/slsa](https://github.com/bytemare/slsa)):
```shell
curl -sSL https://raw.githubusercontent.com/bytemare/slsa/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full --signer-repo bytemare/slsa
```
Run again with `--mode reproduce` to build in a container, or `--mode vsa` to validate just the verification summary.

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code
of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.
