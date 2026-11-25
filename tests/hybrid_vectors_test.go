// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/kem"
	"github.com/bytemare/opaque/internal/oprf"
)

// Hybrid mode test vectors.
//
// The vectors reuse the inputs of the RFC 9807 vectors (tests/vectors.json) for the supported groups, and add the two
// inputs of the KEM: the client's ML-KEM seed and the server's encapsulation randomness. They are checked in two
// independent ways:
//   - the library reproduces every output from the inputs, byte for byte;
//   - hybridKeySchedule recomputes the AKE from the specification (docs/hybrid-mlkem.md) using only the Go standard
//     library for HKDF, HMAC and hashing, so the specification, the vectors and the code must all agree.
//
// Regenerate with: go test ./tests -run TestHybridVectors -update-hybrid-vectors

const hybridVectorsFile = "hybrid_vectors.json"

var updateHybridVectors = flag.Bool("update-hybrid-vectors", false, "regenerate "+hybridVectorsFile)

type hybridConfig struct {
	Name    string    `json:"Name"`
	OPRF    string    `json:"OPRF"`
	Group   string    `json:"Group"`
	KEM     string    `json:"KEM"`
	KSF     string    `json:"KSF"`
	KDF     string    `json:"KDF"`
	MAC     string    `json:"MAC"`
	Hash    string    `json:"Hash"`
	Context ByteToHex `json:"Context"`
	Nek     int       `json:"Nek"`
	Nct     int       `json:"Nct"`
}

type hybridInputs struct {
	OprfSeed             ByteToHex `json:"oprf_seed"`
	CredentialIdentifier ByteToHex `json:"credential_identifier"`
	Password             ByteToHex `json:"password"`
	ClientIdentity       ByteToHex `json:"client_identity,omitempty"`
	ServerIdentity       ByteToHex `json:"server_identity,omitempty"`
	ServerPrivateKey     ByteToHex `json:"server_private_key"`
	ServerPublicKey      ByteToHex `json:"server_public_key"`
	BlindRegistration    ByteToHex `json:"blind_registration"`
	EnvelopeNonce        ByteToHex `json:"envelope_nonce"`
	BlindLogin           ByteToHex `json:"blind_login"`
	ClientNonce          ByteToHex `json:"client_nonce"`
	ClientKeyshareSeed   ByteToHex `json:"client_keyshare_seed"`
	ClientKEMSeed        ByteToHex `json:"client_kem_seed"`
	MaskingNonce         ByteToHex `json:"masking_nonce"`
	ServerNonce          ByteToHex `json:"server_nonce"`
	ServerKeyshareSeed   ByteToHex `json:"server_keyshare_seed"`
	ServerKEMRandomness  ByteToHex `json:"server_kem_randomness"`
}

type hybridIntermediates struct {
	ClientPublicKey    ByteToHex `json:"client_public_key"`
	MaskingKey         ByteToHex `json:"masking_key"`
	Envelope           ByteToHex `json:"envelope"`
	ClientKEMPublicKey ByteToHex `json:"client_kem_public_key"`
	KEMCiphertext      ByteToHex `json:"kem_ciphertext"`
	KEMSharedSecret    ByteToHex `json:"kem_shared_secret"`
	IKM                ByteToHex `json:"ikm"`
	PreambleHash       ByteToHex `json:"preamble_hash"`
	HandshakeSecret    ByteToHex `json:"handshake_secret"`
	ServerMacKey       ByteToHex `json:"server_mac_key"`
	ClientMacKey       ByteToHex `json:"client_mac_key"`
}

type hybridOutputs struct {
	RegistrationRequest  ByteToHex `json:"registration_request"`
	RegistrationResponse ByteToHex `json:"registration_response"`
	RegistrationRecord   ByteToHex `json:"registration_upload"`
	KE1                  ByteToHex `json:"KE1"`
	KE2                  ByteToHex `json:"KE2"`
	KE3                  ByteToHex `json:"KE3"`
	ExportKey            ByteToHex `json:"export_key"`
	SessionKey           ByteToHex `json:"session_key"`
}

type hybridVector struct {
	Config        hybridConfig        `json:"config"`
	Inputs        hybridInputs        `json:"inputs"`
	Intermediates hybridIntermediates `json:"intermediates"`
	Outputs       hybridOutputs       `json:"outputs"`
}

// fixedBytes returns n reproducible bytes for a named vector input.
func fixedBytes(label string, n int) []byte {
	h := sha512.Sum512([]byte("OPAQUE hybrid test vector " + label))
	return h[:n]
}

func (v *hybridVector) configuration() *opaque.Configuration {
	k := opaque.MLKEM768
	if v.Config.KEM == opaque.MLKEM1024.String() {
		k = opaque.MLKEM1024
	}

	return &opaque.Configuration{
		OPRF:    oprfToGroup(oprf.Identifier(v.Config.OPRF)),
		AKE:     groupToGroup(v.Config.Group),
		KSF:     ksfToKSF(v.Config.KSF),
		KDF:     kdfToHash(v.Config.KDF),
		MAC:     macToHash(v.Config.MAC),
		Hash:    hashToHash(v.Config.Hash),
		KEM:     k,
		Context: v.Config.Context,
	}
}

// run executes registration and login with the library from the vector inputs and fills in the outputs and the
// observable intermediates.
func (v *hybridVector) run(t *testing.T) {
	t.Helper()

	conf := v.configuration()
	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}

	server, err := conf.Server()
	if err != nil {
		t.Fatal(err)
	}

	sk, err := server.Deserialize.DecodePrivateKey(v.Inputs.ServerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	if err = server.SetKeyMaterial(&opaque.ServerKeyMaterial{
		Identity:       v.Inputs.ServerIdentity,
		PrivateKey:     sk,
		PublicKeyBytes: v.Inputs.ServerPublicKey,
		OPRFGlobalSeed: v.Inputs.OprfSeed,
	}); err != nil {
		t.Fatal(err)
	}

	decodeBlind := func(b []byte) *ecc.Scalar {
		s := conf.OPRF.Group().NewScalar()
		if err := s.Decode(b); err != nil {
			t.Fatal(err)
		}

		return s
	}

	// Registration.
	req, err := client.RegistrationInit(v.Inputs.Password,
		&opaque.ClientOptions{OPRFBlind: decodeBlind(v.Inputs.BlindRegistration)})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := server.RegistrationResponse(req, v.Inputs.CredentialIdentifier, nil)
	if err != nil {
		t.Fatal(err)
	}

	record, exportKey, err := client.RegistrationFinalize(resp, v.Inputs.ClientIdentity, v.Inputs.ServerIdentity,
		&opaque.ClientOptions{RegistrationEnvelopeNonce: v.Inputs.EnvelopeNonce})
	if err != nil {
		t.Fatal(err)
	}

	client.ClearState()

	// Login.
	ke1, err := client.GenerateKE1(v.Inputs.Password, &opaque.ClientOptions{
		OPRFBlind: decodeBlind(v.Inputs.BlindLogin),
		AKE: &opaque.AKEOptions{
			SecretKeyShareSeed: v.Inputs.ClientKeyshareSeed,
			Nonce:              v.Inputs.ClientNonce,
			KEMSeed:            v.Inputs.ClientKEMSeed,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ke2, serverOutput, err := server.GenerateKE2(ke1, &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: v.Inputs.CredentialIdentifier,
		ClientIdentity:       v.Inputs.ClientIdentity,
	}, &opaque.ServerOptions{
		MaskingNonce: v.Inputs.MaskingNonce,
		AKE: &opaque.AKEOptions{
			SecretKeyShareSeed: v.Inputs.ServerKeyshareSeed,
			Nonce:              v.Inputs.ServerNonce,
			KEMRandomness:      v.Inputs.ServerKEMRandomness,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ke3, sessionKey, loginExportKey, err := client.GenerateKE3(ke2, v.Inputs.ClientIdentity, v.Inputs.ServerIdentity)
	if err != nil {
		t.Fatal(err)
	}

	if err = server.LoginFinish(ke3, serverOutput.ClientMAC); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sessionKey, serverOutput.SessionSecret) {
		t.Fatal("client and server session keys differ")
	}

	if !bytes.Equal(exportKey, loginExportKey) {
		t.Fatal("registration and login export keys differ")
	}

	v.Outputs = hybridOutputs{
		RegistrationRequest:  req.Serialize(),
		RegistrationResponse: resp.Serialize(),
		RegistrationRecord:   record.Serialize(),
		KE1:                  ke1.Serialize(),
		KE2:                  ke2.Serialize(),
		KE3:                  ke3.Serialize(),
		ExportKey:            exportKey,
		SessionKey:           sessionKey,
	}
	v.Intermediates.ClientPublicKey = record.ClientPublicKey.Encode()
	v.Intermediates.MaskingKey = record.MaskingKey
	v.Intermediates.Envelope = record.Envelope
	v.Intermediates.ClientKEMPublicKey = ke1.ClientKEMKey
	v.Intermediates.KEMCiphertext = ke2.ServerKEMCiphertext
}

// hybridKeySchedule recomputes the hybrid AKE of the specification, from the server's point of view, using the vector
// inputs and messages. It fills in the AKE intermediates and returns the expected server MAC, client MAC and session
// key.
func (v *hybridVector) hybridKeySchedule(t *testing.T) (serverMac, clientMac, sessionKey []byte) {
	t.Helper()

	conf := v.configuration()
	ic, err := toInternal(conf)
	if err != nil {
		t.Fatal(err)
	}

	g := ic.Group
	ne, nn, nm := ic.Sizes.AKEElement, ic.Sizes.Nonce, ic.Sizes.MAC
	kemID := kem.ID(conf.KEM)

	// Parse the messages following the wire format of the specification.
	ke1, ke2 := v.Outputs.KE1, v.Outputs.KE2
	off := ic.Sizes.OPRFElement + nn
	epkC := ke1[off : off+ne]
	ek := ke1[off+ne:]

	credResp := ke2[:ic.Sizes.CredentialResponse]
	off = ic.Sizes.CredentialResponse
	serverNonce := ke2[off : off+nn]
	epkS := ke2[off+nn : off+nn+ne]
	ct := ke2[off+nn+ne : len(ke2)-nm]

	if len(ek) != kemID.EncapsulationKeySize() || len(ct) != kemID.CiphertextSize() {
		t.Fatal("unexpected KEM field sizes")
	}

	// KEM: the server encapsulates with the fixed randomness, the client decapsulates with its seed.
	ss, ctCheck, err := kemID.EncapsulateDerand(ek, v.Inputs.ServerKEMRandomness)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ct, ctCheck) {
		t.Fatal("KEM ciphertext does not match the derandomized encapsulation")
	}

	ssClient, err := kemID.Decapsulate(v.Inputs.ClientKEMSeed, ct)
	if err != nil || !bytes.Equal(ss, ssClient) {
		t.Fatal("KEM decapsulation does not match encapsulation")
	}

	// Diffie-Hellman, from the server's keys.
	decodeElement := func(b []byte) *ecc.Element {
		e, err := opaque.DeserializeElement(g, b)
		if err != nil {
			t.Fatal(err)
		}

		return e
	}

	skS, err := opaque.DeserializeScalar(g, v.Inputs.ServerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	eskS := ic.MakeSecretKeyShare(v.Inputs.ServerKeyshareSeed)
	if !bytes.Equal(g.Base().Multiply(eskS).Encode(), epkS) {
		t.Fatal("server key share does not match its seed")
	}

	pkC := v.Outputs.RegistrationRecord[:ne]
	dh1 := decodeElement(epkC).Multiply(eskS).Encode()
	dh2 := decodeElement(epkC).Multiply(skS).Encode()
	dh3 := decodeElement(pkC).Multiply(eskS).Encode()
	ikm := bytes.Join([][]byte{dh1, dh2, dh3, ss}, nil)

	// Transcript.
	clientID := v.Inputs.ClientIdentity
	if len(clientID) == 0 {
		clientID = pkC
	}

	serverID := v.Inputs.ServerIdentity
	if len(serverID) == 0 {
		serverID = v.Inputs.ServerPublicKey
	}

	transcript := bytes.Join([][]byte{
		[]byte("OPAQUEv1-Hybrid-" + v.Config.KEM + "-"),
		encoding.EncodeVector(v.Config.Context),
		encoding.EncodeVector(clientID),
		ke1,
		encoding.EncodeVector(serverID),
		credResp,
		serverNonce,
		epkS,
		ct,
	}, nil)

	hashOf := func(b []byte) []byte {
		h := conf.Hash.New()
		h.Write(b)

		return h.Sum(nil)
	}

	preamble := hashOf(transcript)

	// Key schedule, with Expand-Label as in RFC 9807 section 6.4.2.
	kdf := conf.KDF
	nh := kdf.Size()
	expandLabel := func(secret []byte, label string, context []byte) []byte {
		info := bytes.Join([][]byte{
			{byte(nh >> 8), byte(nh)},
			{byte(len("OPAQUE-" + label))},
			[]byte("OPAQUE-" + label),
			{byte(len(context))},
			context,
		}, nil)

		out, err := hkdf.Expand(kdf.New, secret, string(info), nh)
		if err != nil {
			t.Fatal(err)
		}

		return out
	}

	prk, err := hkdf.Extract(kdf.New, ikm, nil)
	if err != nil {
		t.Fatal(err)
	}

	handshakeSecret := expandLabel(prk, "HandshakeSecret", preamble)
	sessionKey = expandLabel(prk, "SessionKey", preamble)
	km2 := expandLabel(handshakeSecret, "ServerMAC", nil)
	km3 := expandLabel(handshakeSecret, "ClientMAC", nil)

	macOf := func(key, msg []byte) []byte {
		m := hmac.New(conf.MAC.New, key)
		m.Write(msg)

		return m.Sum(nil)
	}

	serverMac = macOf(km2, preamble)
	clientMac = macOf(km3, hashOf(append(transcript, serverMac...)))

	v.Intermediates.KEMSharedSecret = ss
	v.Intermediates.IKM = ikm
	v.Intermediates.PreambleHash = preamble
	v.Intermediates.HandshakeSecret = handshakeSecret
	v.Intermediates.ServerMacKey = km2
	v.Intermediates.ClientMacKey = km3

	return serverMac, clientMac, sessionKey
}

func (v *hybridVector) checkKeySchedule(t *testing.T) {
	t.Helper()

	serverMac, clientMac, sessionKey := v.hybridKeySchedule(t)
	nm := len(serverMac)

	if !bytes.Equal(serverMac, v.Outputs.KE2[len(v.Outputs.KE2)-nm:]) {
		t.Fatal("server MAC differs from the specification")
	}

	if !bytes.Equal(clientMac, v.Outputs.KE3) {
		t.Fatal("client MAC differs from the specification")
	}

	if !bytes.Equal(sessionKey, v.Outputs.SessionKey) {
		t.Fatal("session key differs from the specification")
	}
}

func loadRFCVectors(t *testing.T) []*vector {
	t.Helper()

	contents, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}

	var v []*vector
	if err = json.Unmarshal(contents, &v); err != nil {
		t.Fatal(err)
	}

	return v
}

func generateHybridVectors(t *testing.T) []*hybridVector {
	t.Helper()

	var out []*hybridVector

	for _, rfc := range loadRFCVectors(t) {
		// curve25519 is not supported by this implementation.
		if isFake(rfc.Config.Fake) || rfc.Config.Group == "curve25519" {
			continue
		}

		for _, k := range []opaque.KEM{opaque.MLKEM768, opaque.MLKEM1024} {
			kemID := kem.ID(k)
			v := &hybridVector{
				Config: hybridConfig{
					Name:    "3DH-" + k.String(),
					OPRF:    string(rfc.Config.OPRF),
					Group:   rfc.Config.Group,
					KEM:     k.String(),
					KSF:     rfc.Config.KSF,
					KDF:     rfc.Config.KDF,
					MAC:     rfc.Config.MAC,
					Hash:    rfc.Config.Hash,
					Context: rfc.Config.Context,
					Nek:     kemID.EncapsulationKeySize(),
					Nct:     kemID.CiphertextSize(),
				},
				Inputs: hybridInputs{
					OprfSeed:             rfc.Inputs.OprfSeed,
					CredentialIdentifier: rfc.Inputs.CredentialIdentifier,
					Password:             rfc.Inputs.Password,
					ClientIdentity:       rfc.Inputs.ClientIdentity,
					ServerIdentity:       rfc.Inputs.ServerIdentity,
					ServerPrivateKey:     rfc.Inputs.ServerPrivateKey,
					ServerPublicKey:      rfc.Inputs.ServerPublicKey,
					BlindRegistration:    rfc.Inputs.BlindRegistration,
					EnvelopeNonce:        rfc.Inputs.EnvelopeNonce,
					BlindLogin:           rfc.Inputs.BlindLogin,
					ClientNonce:          rfc.Inputs.ClientNonce,
					ClientKeyshareSeed:   rfc.Inputs.ClientKeyshareSeed,
					ClientKEMSeed:        fixedBytes("client_kem_seed", kem.SeedSize),
					MaskingNonce:         rfc.Inputs.MaskingNonce,
					ServerNonce:          rfc.Inputs.ServerNonce,
					ServerKeyshareSeed:   rfc.Inputs.ServerKeyshareSeed,
					ServerKEMRandomness:  fixedBytes("server_kem_randomness", kem.EncapsulationRandomnessSize),
				},
			}

			v.run(t)
			v.checkKeySchedule(t)

			// Registration is unchanged by the KEM: it must match the RFC vector.
			if !bytes.Equal(v.Outputs.RegistrationRecord, rfc.Outputs.RegistrationRecord) ||
				!bytes.Equal(v.Outputs.ExportKey, rfc.Outputs.ExportKey) {
				t.Fatal("hybrid registration differs from RFC 9807")
			}

			out = append(out, v)
		}
	}

	return out
}

// TestHybridVectors checks the hybrid mode test vectors, or regenerates them with -update-hybrid-vectors.
func TestHybridVectors(t *testing.T) {
	if *updateHybridVectors {
		vectors := generateHybridVectors(t)

		contents, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		if err = os.WriteFile(hybridVectorsFile, append(contents, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}

		t.Logf("wrote %d vectors to %s", len(vectors), hybridVectorsFile)

		return
	}

	contents, err := os.ReadFile(hybridVectorsFile)
	if err != nil {
		t.Fatal(err)
	}

	var vectors []*hybridVector
	if err = json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}

	if len(vectors) == 0 {
		t.Fatal("no hybrid vectors")
	}

	for i, want := range vectors {
		t.Run(fmt.Sprintf("%d-%s-%s", i, want.Config.OPRF, want.Config.KEM), func(t *testing.T) {
			// The library must reproduce every output and intermediate from the inputs.
			got := &hybridVector{Config: want.Config, Inputs: want.Inputs}
			got.run(t)
			got.checkKeySchedule(t)

			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)

			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("vector mismatch\nwant %s\ngot  %s", wantJSON, gotJSON)
			}

			// The specification recomputation must also hold on the stored values alone.
			want.checkKeySchedule(t)
		})
	}
}
