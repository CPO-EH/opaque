// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 CPO-EH. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

//go:build opaque_kat

package opaque_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal/kem"
)

// This file is only compiled with the opaque_kat build tag, which lets the tests fix the randomness of the server's
// ML-KEM encapsulation. It reproduces the hybrid vectors in full, KE2 included, and can regenerate them:
//
//	go test -tags opaque_kat ./tests -run TestHybridVectors -update-hybrid-vectors

var updateHybridVectors = flag.Bool("update-hybrid-vectors", false, "regenerate "+hybridVectorsFile)

// fixedBytes returns n reproducible bytes for a named vector input.
func fixedBytes(label string, n int) []byte {
	h := sha512.Sum512([]byte("OPAQUE hybrid test vector " + label))
	return h[:n]
}

// run executes registration and login with the library from the vector inputs, with the server's encapsulation
// randomness fixed, and fills in the outputs and the observable intermediates.
func (v *hybridVector) run(t *testing.T) {
	t.Helper()

	conf, client, server := v.parties(t)
	record := v.register(t, conf, client, server)
	ke1 := v.startLogin(t, conf, client)

	restore, err := kem.SetEncapsulationRandomness(v.Inputs.ServerKEMRandomness)
	if err != nil {
		t.Fatal(err)
	}

	ke2, output := v.serverKE2(t, server, ke1, record)
	restore()

	ke3 := v.finishLogin(t, client, ke2)
	if err = server.LoginFinish(ke3, output.ClientMAC); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Outputs.SessionKey, output.SessionSecret) {
		t.Fatal("client and server session keys differ")
	}

	// The ciphertext is the derandomized encapsulation of the vector randomness to the client's key.
	_, ct, err := kem.ID(conf.KEM).EncapsulateDerand(ke1.ClientKEMKey, v.Inputs.ServerKEMRandomness)
	if err != nil || !bytes.Equal(ct, ke2.ServerKEMCiphertext) {
		t.Fatal("KEM ciphertext does not match the derandomized encapsulation")
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

// TestHybridVectorsKAT reproduces the hybrid mode test vectors in full, or regenerates them with
// -update-hybrid-vectors.
func TestHybridVectorsKAT(t *testing.T) {
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

	for i, want := range loadHybridVectors(t) {
		t.Run(fmt.Sprintf("%d-%s-%s", i, want.Config.OPRF, want.Config.KEM), func(t *testing.T) {
			got := &hybridVector{Config: want.Config, Inputs: want.Inputs}
			got.run(t)
			got.checkKeySchedule(t)

			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)

			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("vector mismatch\nwant %s\ngot  %s", wantJSON, gotJSON)
			}
		})
	}
}

// TestHybrid_FixedEncapsulationRandomness verifies that a wrong length is refused, that fixed randomness makes the
// KEM ciphertext reproducible, and that fresh randomness is used again once it is restored.
func TestHybrid_FixedEncapsulationRandomness(t *testing.T) {
	if _, err := kem.SetEncapsulationRandomness(make([]byte, kem.EncapsulationRandomnessSize-1)); err == nil {
		t.Fatal("expected an error for a wrong randomness length")
	}

	conf := hybridConf(opaque.DefaultConfiguration(), opaque.MLKEM768)
	env := newHybridEnv(t, conf)
	client, _ := conf.Client()
	ke1, _ := client.GenerateKE1(password)

	restore, err := kem.SetEncapsulationRandomness(bytes.Repeat([]byte{7}, kem.EncapsulationRandomnessSize))
	if err != nil {
		t.Fatal(err)
	}

	a, _, errA := env.server.GenerateKE2(ke1, env.record)
	b, _, errB := env.server.GenerateKE2(ke1, env.record)

	restore()

	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}

	if !bytes.Equal(a.ServerKEMCiphertext, b.ServerKEMCiphertext) {
		t.Fatal("fixed KEM randomness must give the same ciphertext")
	}

	c, _, err := env.server.GenerateKE2(ke1, env.record)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(a.ServerKEMCiphertext, c.ServerKEMCiphertext) {
		t.Fatal("restored encapsulation must use fresh randomness")
	}
}
