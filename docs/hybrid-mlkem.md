# OPAQUE with a hybrid 3DH and ML-KEM key exchange

Status: experimental, version 1 of this specification. Not an IETF document.

## 1. Introduction

OPAQUE ([RFC 9807]) authenticates a client to a server with a password and
establishes a shared session key. Its key exchange, 3DH, combines three
elliptic curve Diffie-Hellman values. An adversary that records a login today
and later runs Shor's algorithm on a quantum computer can recover these values
and therefore the session key.

This document specifies a variant of the 3DH key exchange of RFC 9807 that
adds an ephemeral ML-KEM ([FIPS 203]) exchange. The ML-KEM shared secret is
mixed into the key schedule together with the three Diffie-Hellman values. The
session key stays secret as long as at least one of the two components holds:
the elliptic curve group or ML-KEM.

Only the key exchange changes. Registration, the OPRF, the envelope, the
credential response and the masking of RFC 9807 are used as they are.

This variant is not interoperable with RFC 9807. A peer that implements it
cannot complete a login with a peer that implements only RFC 9807, and the
transcripts of both protocols are separated by a different prefix.

The reference implementation is the Go package in this repository. Test vectors
are in [`tests/hybrid_vectors.json`](../tests/hybrid_vectors.json).

## 2. Conventions

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described
in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

This document uses the notation, functions and constants of RFC 9807. In
particular:

- `||` is the concatenation of byte strings.
- `I2OSP(x, n)` is the n-byte big-endian encoding of the integer x.
- `Nn` is the nonce length (32), `Npk` the length of an encoded public key of
  the AKE group, `Nm` the MAC output length, `Nx` the KDF output length.
- `Hash`, `MAC`, `Extract`, `Expand`, `Expand-Label` and `Derive-Secret` are
  defined in RFC 9807, sections 2 and 6.4.

The following ML-KEM functions are used, as defined in FIPS 203:

- `ML-KEM.KeyGen_internal(d, z)` returns an encapsulation key `ek` and a
  decapsulation key `dk` from two 32-byte seeds.
- `ML-KEM.Encaps(ek)` returns a 32-byte shared secret `ss` and a ciphertext
  `ct`. It draws 32 random bytes `m` and calls `ML-KEM.Encaps_internal(ek, m)`.
- `ML-KEM.Decaps(dk, ct)` returns the shared secret.

## 3. Parameters

A configuration of this variant is an RFC 9807 configuration plus one KEM:

| KEM         | Identifier | Name          | Nek  | Nct  | Nss | Nseed |
|-------------|------------|---------------|------|------|-----|-------|
| ML-KEM-768  | 1          | `ML-KEM-768`  | 1184 | 1088 | 32  | 64    |
| ML-KEM-1024 | 2          | `ML-KEM-1024` | 1568 | 1568 | 32  | 64    |

- `Nek` is the length of an encapsulation key.
- `Nct` is the length of a ciphertext.
- `Nss` is the length of the shared secret.
- `Nseed` is the length of the seed from which a key pair is derived.

The identifier value 0 means that no KEM is used, which is plain RFC 9807.
ML-KEM-1024 is RECOMMENDED. ML-KEM-768 MAY be used where message size
matters more than the security margin.

`KEMName` below is the Name column of the table, as an ASCII string.

## 4. Messages

Registration messages are those of RFC 9807, section 5.1. KE3 is unchanged.

KE1 and KE2 each gain one field. In KE1 it is the last field. In KE2 it is
inserted before `server_mac`. Using the presentation language of RFC 9807:

```
struct {
  uint8 client_nonce[Nn];
  uint8 client_public_keyshare[Npk];
  uint8 client_kem_public_key[Nek];
} AuthRequest;

struct {
  CredentialRequest credential_request;
  AuthRequest auth_request;
} KE1;

struct {
  uint8 server_nonce[Nn];
  uint8 server_public_keyshare[Npk];
  uint8 kem_ciphertext[Nct];
  uint8 server_mac[Nm];
} AuthResponse;

struct {
  CredentialResponse credential_response;
  AuthResponse auth_response;
} KE2;
```

All fields have a fixed length for a given configuration, so the messages are
plain concatenations without length prefixes:

```
KE1 = blinded_message || client_nonce || client_public_keyshare
      || client_kem_public_key

KE2 = evaluated_message || masking_nonce || masked_response
      || server_nonce || server_public_keyshare || kem_ciphertext
      || server_mac
```

The sizes are therefore:

```
len(KE1) = Noe + Nn + Npk + Nek
len(KE2) = Noe + Nn + Npk + Nn + Nm + Nn + Npk + Nct + Nm
```

where `Noe` is the length of an encoded OPRF element and
`Npk + Nn + Nm` is the length of the masked response, as in RFC 9807.

## 5. Protocol

### 5.1 Client: generating KE1

In addition to the steps of RFC 9807 section 6.4.3 (`AuthClientStart`), the
client:

1. Draws `kem_seed` as `Nseed` random bytes, and sets `d` to its first 32 bytes
   and `z` to its last 32 bytes.
2. Computes `(ek, dk) = ML-KEM.KeyGen_internal(d, z)`.
3. Sets `client_kem_public_key = ek`.
4. Keeps `kem_seed` (or `dk`) in its state until KE3 is computed, and erases it
   afterwards.

A fresh `kem_seed` MUST be drawn for every login. It MUST NOT be reused.

### 5.2 Server: generating KE2

In addition to the steps of RFC 9807 section 6.4.4 (`AuthServerRespond`), the
server:

1. Verifies that `client_kem_public_key` passes the encapsulation key check of
   FIPS 203, section 7.2: the length is `Nek`, and decoding then re-encoding
   the polynomial part gives back the same bytes. If the check fails, the
   server aborts.
2. Computes `(ss, ct) = ML-KEM.Encaps(client_kem_public_key)` and sets
   `kem_ciphertext = ct`.
3. Computes the key schedule of section 5.4 with:

   ```
   dh1 = SerializeElement(eskS * epkU)
   dh2 = SerializeElement(skS  * epkU)
   dh3 = SerializeElement(eskS * pkU)
   ikm = dh1 || dh2 || dh3 || ss
   ```

   where `eskS` is the server's ephemeral private key, `skS` its long-term
   private key, `epkU` the client's ephemeral public key from KE1, and `pkU`
   the client's public key from the registration record. These are the same
   values as in RFC 9807.

4. Sets `server_mac` and outputs KE2, keeping `expected_client_mac` and
   `session_key` as in RFC 9807. It erases `ss`.

### 5.3 Client: processing KE2

In addition to the steps of RFC 9807 section 6.4.3 (`AuthClientFinalize`), the
client:

1. Verifies that `kem_ciphertext` has length `Nct`. Since KE2 has a fixed
   length, this follows from the length check of KE2.
2. Computes `ss = ML-KEM.Decaps(dk, kem_ciphertext)`.
3. Computes the key schedule of section 5.4 with:

   ```
   dh1 = SerializeElement(eskU * epkS)
   dh2 = SerializeElement(eskU * pkS)
   dh3 = SerializeElement(skU  * epkS)
   ikm = dh1 || dh2 || dh3 || ss
   ```

4. Verifies `server_mac`, computes KE3 and outputs the session key, as in
   RFC 9807. It erases `ss` and `kem_seed`.

ML-KEM decapsulation uses implicit rejection: an invalid ciphertext of the
right length does not produce an error but a pseudorandom secret. The
subsequent `server_mac` verification then fails. Implementations MUST NOT
report a KEM-specific error in that case. A ciphertext of the wrong length is
a malformed message and MAY be reported as such.

### 5.4 Key schedule

The key schedule is that of RFC 9807 section 6.4.2, with two changes: the
input keying material includes `ss` (see above), and the preamble has a
different prefix and one more field.

```
preamble = "OPAQUEv1-Hybrid-" || KEMName || "-"
           || I2OSP(len(context), 2) || context
           || I2OSP(len(client_identity), 2) || client_identity
           || KE1
           || I2OSP(len(server_identity), 2) || server_identity
           || credential_response
           || server_nonce
           || server_public_keyshare
           || kem_ciphertext
```

For ML-KEM-768, the prefix is the 27-byte ASCII string
`OPAQUEv1-Hybrid-ML-KEM-768-`.

`KE1` is the full serialized KE1 message, including `client_kem_public_key`.
As in RFC 9807, `client_identity` defaults to the client's public key and
`server_identity` to the server's public key when the application does not
provide them.

The rest is unchanged:

```
prk                 = Extract("", ikm)
handshake_secret    = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
session_key         = Derive-Secret(prk, "SessionKey", Hash(preamble))
Km2                 = Derive-Secret(handshake_secret, "ServerMAC", "")
Km3                 = Derive-Secret(handshake_secret, "ClientMAC", "")
server_mac          = MAC(Km2, Hash(preamble))
expected_client_mac = MAC(Km3, Hash(preamble || server_mac))
```

with, as in RFC 9807:

```
Derive-Secret(Secret, Label, Context) =
    Expand-Label(Secret, Label, Context, Nx)

Expand-Label(Secret, Label, Context, Length) =
    Expand(Secret, CustomLabel, Length)

CustomLabel = I2OSP(Length, 2)
              || I2OSP(len("OPAQUE-" || Label), 1) || "OPAQUE-" || Label
              || I2OSP(len(Context), 1) || Context
```

`Hash` is the hash function of the configuration, `Extract`, `Expand` and `Nx`
come from its KDF, and `MAC` is its MAC. These three functions may differ, as
in RFC 9807.

Both the encapsulation key (through KE1) and the ciphertext are covered by the
preamble, so both MACs authenticate the KEM exchange.

## 6. Configuration encoding

This section describes how the reference implementation serializes a
configuration. It is not needed to run the protocol, but it lets
implementations exchange configurations.

```
config = I2OSP(oprf, 1) || I2OSP(ake, 1) || I2OSP(ksf, 1)
         || I2OSP(kdf, 1) || I2OSP(mac, 1) || I2OSP(hash, 1)
         || I2OSP(len(context), 2) || context
         [ || I2OSP(kem, 1) ]
```

The KEM byte is present only when a KEM is used, so encodings of RFC 9807
configurations are unchanged. A decoder MUST reject an encoding whose trailing
KEM byte is 0 or is not a known identifier, or that has more than one byte
after the context.

## 7. Security considerations

What this variant provides:

- Confidentiality of session keys against an adversary that records the
  traffic and later breaks the elliptic curve group, including with a quantum
  computer, provided ML-KEM is secure. This is the main goal.
- No loss with respect to RFC 9807 if ML-KEM is broken: the
  Diffie-Hellman values are still part of the input keying material.
- Domain separation from RFC 9807 through the preamble prefix, which also
  names the KEM.

What it does not provide:

- Post-quantum authentication. Mutual authentication still rests on the static
  Diffie-Hellman keys and on the MACs. An adversary able to compute discrete
  logarithms during a login can impersonate any party whose long-term public
  key it knows.
- A post-quantum OPRF. The OPRF of RFC 9807 is based on the same elliptic
  curve group. An adversary that can compute discrete logarithms and that
  obtains a login transcript together with the server's OPRF key can run an
  offline dictionary attack on the password. Key stretching (KSF) only slows
  this attack down.

Other considerations:

- The KEM key pair is ephemeral. Reusing `kem_seed` across logins removes the
  forward secrecy of the KEM component.
- `kem_seed` and `dk` are as sensitive as the client's ephemeral
  Diffie-Hellman private key and MUST be erased after use. An implementation
  that lets a login be resumed by another client instance needs to carry
  `kem_seed` along, and MUST protect it accordingly.
- Derandomized encapsulation (`ML-KEM.Encaps_internal` with a chosen `m`) is
  only for producing and checking test vectors. With a known or repeated `m`,
  anyone who sees the ciphertext can compute `ss`.
- The server MUST perform the encapsulation key check of section 5.2 before
  encapsulating.
- This construction has not been formally analyzed. The approach of
  concatenating a KEM secret to Diffie-Hellman values before a single
  extraction is common in hybrid key exchanges, but the security of this
  specific combination with OPAQUE has not been proven.

## 8. Test vectors

[`tests/hybrid_vectors.json`](../tests/hybrid_vectors.json) holds 8 vectors:
the four RFC 9807 vectors for ristretto255-SHA512 and P256-SHA256 (with and
without explicit identities), each with ML-KEM-768 and ML-KEM-1024. The
curve25519 vectors and the fake-credential vectors of RFC 9807 are not
included.

Each vector takes all its RFC 9807 inputs from the matching entry of
`tests/vectors.json`, with the `Identity` KSF, and adds two inputs:

- `client_kem_seed`: the `Nseed`-byte seed of section 5.1.
- `server_kem_randomness`: the 32-byte value `m` used for a derandomized
  encapsulation, `(ss, ct) = ML-KEM.Encaps_internal(ek, m)`.

Both are the first bytes of `SHA-512("OPAQUE hybrid test vector " || label)`,
where `label` is the field name, for example `client_kem_seed`. The same two
values are used in all 8 vectors. They are only fixed for reproducibility.

Reproducing KE2 requires a way to fix `m` on the server. That mechanism must
not be reachable in production code, since anyone who knows `m` can compute
the KEM shared secret. This implementation only offers it in builds with the
`opaque_kat` tag. Without it, the client side can still be checked: KE1, then
KE3 and the session key computed from the KE2 of the vector.

Each vector is a JSON object with four members.

`config` has the fields `Name` (`3DH-ML-KEM-768` or `3DH-ML-KEM-1024`),
`OPRF`, `Group`, `KEM` (the KEM name), `KSF`, `KDF`, `MAC`, `Hash`, `Context`
(hex encoded), `Nek` and `Nct`. The values of `OPRF`, `Group`, `KSF`, `KDF`,
`MAC` and `Hash` use the same strings as `tests/vectors.json`.

`inputs` has the fields `oprf_seed`, `credential_identifier`, `password`,
`client_identity`, `server_identity`, `server_private_key`,
`server_public_key`, `blind_registration`, `envelope_nonce`, `blind_login`,
`client_nonce`, `client_keyshare_seed`, `client_kem_seed`, `masking_nonce`,
`server_nonce`, `server_keyshare_seed` and `server_kem_randomness`.
`client_identity` and `server_identity` are omitted when the application does
not set them, in which case the defaults of section 5.4 apply.
`client_keyshare_seed` and `server_keyshare_seed` give the ephemeral
Diffie-Hellman key pairs through `DeriveDiffieHellmanKeyPair`, as in RFC 9807.

`intermediates` has the fields `client_public_key`, `masking_key`,
`envelope`, `client_kem_public_key`, `kem_ciphertext`, `kem_shared_secret`,
`ikm`, `preamble_hash` (that is, `Hash(preamble)`), `handshake_secret`,
`server_mac_key` (Km2) and `client_mac_key` (Km3).

`outputs` has the fields `registration_request`, `registration_response`,
`registration_upload`, `KE1`, `KE2`, `KE3`, `export_key` and `session_key`.

All byte strings are hex encoded. Registration outputs and `export_key` are
identical to those of the RFC 9807 vectors, since registration does not change.

An implementation conforms if, from the inputs, it reproduces every output and
intermediate byte for byte. The test in
[`tests/hybrid_vectors_test.go`](../tests/hybrid_vectors_test.go) checks this
for the reference implementation, and also recomputes the key schedule of
section 5.4 independently, using only the Go standard library, to make sure
this document and the code agree.

## 9. References

- [RFC 9807]: The OPAQUE Augmented Password-Authenticated Key Exchange
  (aPAKE) Protocol.
- [FIPS 203]: Module-Lattice-Based Key-Encapsulation Mechanism Standard.
- RFC 2119 and RFC 8174: key words for use in RFCs to indicate requirement
  levels.

[RFC 9807]: https://datatracker.ietf.org/doc/rfc9807
[FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
