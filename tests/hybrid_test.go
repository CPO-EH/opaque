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
	"crypto/mlkem"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

var hybridKEMs = []opaque.KEM{opaque.MLKEM768, opaque.MLKEM1024}

// hybridConf returns a copy of a classical test configuration with the given KEM. Key stretching is disabled to keep
// the tests fast, except where explicitly tested.
func hybridConf(base *opaque.Configuration, k opaque.KEM) *opaque.Configuration {
	c := *base
	c.KEM = k
	c.KSF = 0
	c.Context = []byte("OPAQUE-hybrid-test")

	return &c
}

type hybridEnv struct {
	conf   *opaque.Configuration
	server *opaque.Server
	record *opaque.ClientRecord
}

// newHybridEnv sets up a server with key material and registers a client, returning the stored record.
func newHybridEnv(t *testing.T, conf *opaque.Configuration) *hybridEnv {
	t.Helper()

	server, err := conf.Server()
	if err != nil {
		t.Fatal(err)
	}

	sk, pk := conf.KeyGen()
	if err = server.SetKeyMaterial(&opaque.ServerKeyMaterial{
		Identity:       serverIdentity,
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}); err != nil {
		t.Fatal(err)
	}

	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}

	req, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec, _, err := client.RegistrationFinalize(resp, clientIdentity, serverIdentity)
	if err != nil {
		t.Fatal(err)
	}

	return &hybridEnv{
		conf:   conf,
		server: server,
		record: &opaque.ClientRecord{
			CredentialIdentifier: credentialIdentifier,
			ClientIdentity:       clientIdentity,
			RegistrationRecord:   rec,
		},
	}
}

// login runs a full login over the wire encoding, and returns the client and server session keys.
func (e *hybridEnv) login(t *testing.T) (clientKey, serverKey []byte) {
	t.Helper()

	client, err := e.conf.Client()
	if err != nil {
		t.Fatal(err)
	}

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}

	ke1d, err := e.server.Deserialize.KE1(ke1.Serialize())
	if err != nil {
		t.Fatal(err)
	}

	ke2, out, err := e.server.GenerateKE2(ke1d, e.record)
	if err != nil {
		t.Fatal(err)
	}

	ke2d, err := client.Deserialize.KE2(ke2.Serialize())
	if err != nil {
		t.Fatal(err)
	}

	ke3, clientKey, _, err := client.GenerateKE3(ke2d, clientIdentity, serverIdentity)
	if err != nil {
		t.Fatal(err)
	}

	ke3d, err := e.server.Deserialize.KE3(ke3.Serialize())
	if err != nil {
		t.Fatal(err)
	}

	if err = e.server.LoginFinish(ke3d, out.ClientMAC); err != nil {
		t.Fatal(err)
	}

	return clientKey, out.SessionSecret
}

func forEachHybrid(t *testing.T, f func(t *testing.T, conf *opaque.Configuration)) {
	for _, base := range configurationTable {
		for _, k := range hybridKEMs {
			t.Run(fmt.Sprintf("%s/%s", base.name, k), func(t *testing.T) {
				f(t, hybridConf(base.conf, k))
			})
		}
	}
}

// TestHybrid_FullFlow verifies registration and login succeed in hybrid mode for every group and KEM, with matching
// session keys on both sides.
func TestHybrid_FullFlow(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		env := newHybridEnv(t, conf)

		clientKey, serverKey := env.login(t)
		if !bytes.Equal(clientKey, serverKey) {
			t.Fatal("session keys differ")
		}

		// Two logins must yield independent session keys.
		clientKey2, _ := env.login(t)
		if bytes.Equal(clientKey, clientKey2) {
			t.Fatal("session keys are reused across logins")
		}
	})
}

// TestHybrid_DefaultConfiguration verifies the default hybrid configuration (with Argon2id) works end to end.
func TestHybrid_DefaultConfiguration(t *testing.T) {
	conf := opaque.DefaultHybridConfiguration()
	if conf.KEM != opaque.MLKEM768 {
		t.Fatal("default hybrid configuration must use ML-KEM-768")
	}

	env := newHybridEnv(t, conf)

	clientKey, serverKey := env.login(t)
	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("session keys differ")
	}
}

// TestHybrid_MessageSizes verifies KE1 and KE2 grow by exactly the KEM key and ciphertext sizes, and that the
// registration messages are unchanged (the KEM is purely ephemeral).
func TestHybrid_MessageSizes(t *testing.T) {
	sizes := map[opaque.KEM][2]int{
		opaque.MLKEM768:  {mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768},
		opaque.MLKEM1024: {mlkem.EncapsulationKeySize1024, mlkem.CiphertextSize1024},
	}

	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		classic := *conf
		classic.KEM = opaque.NoKEM

		ic, err := toInternal(&classic)
		if err != nil {
			t.Fatal(err)
		}

		env := newHybridEnv(t, conf)
		client, _ := conf.Client()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := env.server.GenerateKE2(ke1, env.record)
		if err != nil {
			t.Fatal(err)
		}

		want := sizes[conf.KEM]
		if got := len(ke1.Serialize()); got != ic.Sizes.KE1+want[0] {
			t.Fatalf("KE1 size: want %d, got %d", ic.Sizes.KE1+want[0], got)
		}

		if got := len(ke2.Serialize()); got != ic.Sizes.KE2+want[1] {
			t.Fatalf("KE2 size: want %d, got %d", ic.Sizes.KE2+want[1], got)
		}

		if got := len(env.record.Serialize()); got != ic.Sizes.RegistrationRecord {
			t.Fatalf("record size changed: want %d, got %d", ic.Sizes.RegistrationRecord, got)
		}
	})
}

// TestHybrid_TamperedCiphertext verifies that a modified KEM ciphertext makes the client reject the server MAC
// (ML-KEM implicit rejection yields a different secret).
func TestHybrid_TamperedCiphertext(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		env := newHybridEnv(t, conf)
		client, _ := conf.Client()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := env.server.GenerateKE2(ke1, env.record)
		if err != nil {
			t.Fatal(err)
		}

		ke2.ServerKEMCiphertext[0] ^= 0xff

		_, _, _, err = client.GenerateKE3(ke2, clientIdentity, serverIdentity)
		if !errors.Is(err, internal.ErrInvalidServerMac) {
			t.Fatalf("expected server MAC failure, got %v", err)
		}
	})
}

// TestHybrid_SubstitutedKEMKey verifies that an attacker substituting the client's KEM key in KE1 (to learn the KEM
// secret) is detected, since the server's MAC covers the transcript with the original KE1.
func TestHybrid_SubstitutedKEMKey(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		env := newHybridEnv(t, conf)
		client, _ := conf.Client()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		attacker, _ := conf.Client()

		attackerKE1, err := attacker.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		forged := *ke1
		forged.ClientKEMKey = attackerKE1.ClientKEMKey

		ke2, _, err := env.server.GenerateKE2(&forged, env.record)
		if err != nil {
			t.Fatal(err)
		}

		_, _, _, err = client.GenerateKE3(ke2, clientIdentity, serverIdentity)
		if err == nil {
			t.Fatal("expected failure with a substituted KEM key")
		}
	})
}

// TestHybrid_ModeMismatch verifies classical and hybrid peers cannot be mixed: messages are rejected.
func TestHybrid_ModeMismatch(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		classic := *conf
		classic.KEM = opaque.NoKEM

		hybridEnv := newHybridEnv(t, conf)
		classicEnv := newHybridEnv(t, &classic)

		// Hybrid KE1 to a classical server.
		hc, _ := conf.Client()
		hke1, _ := hc.GenerateKE1(password)

		if _, err := classicEnv.server.Deserialize.KE1(hke1.Serialize()); !errors.Is(err, internal.ErrInvalidMessageLength) {
			t.Fatalf("expected length error, got %v", err)
		}

		if _, _, err := classicEnv.server.GenerateKE2(hke1, classicEnv.record); !errors.Is(err, internal.ErrInvalidClientKEMKey) {
			t.Fatalf("expected KEM key error, got %v", err)
		}

		// Classical KE1 to a hybrid server.
		cc, _ := classic.Client()
		cke1, _ := cc.GenerateKE1(password)

		if _, err := hybridEnv.server.Deserialize.KE1(cke1.Serialize()); !errors.Is(err, internal.ErrInvalidMessageLength) {
			t.Fatalf("expected length error, got %v", err)
		}

		if _, _, err := hybridEnv.server.GenerateKE2(cke1, hybridEnv.record); !errors.Is(err, internal.ErrInvalidClientKEMKey) {
			t.Fatalf("expected KEM key error, got %v", err)
		}

		// Classical KE2 to a hybrid client.
		cke2, _, err := classicEnv.server.GenerateKE2(cke1, classicEnv.record)
		if err != nil {
			t.Fatal(err)
		}

		if _, _, _, err = hc.GenerateKE3(cke2, clientIdentity, serverIdentity); !errors.Is(err, internal.ErrInvalidServerKEMCiphertext) {
			t.Fatalf("expected KEM ciphertext error, got %v", err)
		}
	})
}

// TestHybrid_InvalidKEMKey verifies a malformed KEM encapsulation key (coefficients out of range) is rejected.
func TestHybrid_InvalidKEMKey(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		env := newHybridEnv(t, conf)
		client, _ := conf.Client()
		ke1, _ := client.GenerateKE1(password)

		bad := *ke1
		bad.ClientKEMKey = bytes.Repeat([]byte{0xff}, len(ke1.ClientKEMKey))

		if _, _, err := env.server.GenerateKE2(&bad, env.record); !errors.Is(err, internal.ErrInvalidClientKEMKey) {
			t.Fatalf("expected KEM key error, got %v", err)
		}

		if _, err := env.server.Deserialize.KE1(bad.Serialize()); !errors.Is(err, internal.ErrInvalidClientKEMKey) {
			t.Fatalf("expected KEM key error, got %v", err)
		}
	})
}

// TestHybrid_Resumption verifies a login started by one client instance can be finished by another, given the
// password, blind, KE1, secret key share seed, and KEM seed.
func TestHybrid_Resumption(t *testing.T) {
	forEachHybrid(t, func(t *testing.T, conf *opaque.Configuration) {
		env := newHybridEnv(t, conf)
		ic, _ := toInternal(conf)

		blind := ic.OPRF.Group().NewScalar().Random()
		akeSeed := internal.RandomBytes(internal.SeedLength)
		kemSeed := internal.RandomBytes(mlkem.SeedSize)

		starter, _ := conf.Client()

		ke1, err := starter.GenerateKE1(password, &opaque.ClientOptions{
			OPRFBlind: blind,
			AKE:       &opaque.AKEOptions{SecretKeyShareSeed: akeSeed, KEMSeed: kemSeed},
		})
		if err != nil {
			t.Fatal(err)
		}

		ke2, out, err := env.server.GenerateKE2(ke1, env.record)
		if err != nil {
			t.Fatal(err)
		}

		// Missing KEM seed.
		finisher, _ := conf.Client()
		opts := &opaque.ClientOptions{
			OPRFBlind:      blind,
			ResumePassword: password,
			ResumeKE1:      ke1.Serialize(),
			AKE:            &opaque.AKEOptions{SecretKeyShareSeed: akeSeed},
		}

		if _, _, _, err = finisher.GenerateKE3(ke2, clientIdentity, serverIdentity, opts); !errors.Is(err, internal.ErrClientNoKEMSeed) {
			t.Fatalf("expected missing KEM seed error, got %v", err)
		}

		// Wrong-length KEM seed.
		opts.AKE.KEMSeed = kemSeed[:10]
		if _, _, _, err = finisher.GenerateKE3(ke2, clientIdentity, serverIdentity, opts); !errors.Is(err, internal.ErrInvalidKEMSeed) {
			t.Fatalf("expected invalid KEM seed error, got %v", err)
		}

		// Correct resumption.
		opts.AKE.KEMSeed = kemSeed

		_, clientKey, _, err := finisher.GenerateKE3(ke2, clientIdentity, serverIdentity, opts)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(clientKey, out.SessionSecret) {
			t.Fatal("session keys differ after resumption")
		}

		// The original client with state must refuse a duplicate KEM seed.
		_, _, _, err = starter.GenerateKE3(ke2, clientIdentity, serverIdentity, &opaque.ClientOptions{
			AKE: &opaque.AKEOptions{KEMSeed: kemSeed},
		})
		if !errors.Is(err, internal.ErrClientExistingKEMSeed) {
			t.Fatalf("expected duplicate KEM seed error, got %v", err)
		}
	})
}

// TestHybrid_KE1InvalidKEMSeedOption verifies GenerateKE1 rejects a wrong-length KEM seed without altering the state.
func TestHybrid_KE1InvalidKEMSeedOption(t *testing.T) {
	conf := hybridConf(opaque.DefaultConfiguration(), opaque.MLKEM768)
	client, _ := conf.Client()

	_, err := client.GenerateKE1(password, &opaque.ClientOptions{AKE: &opaque.AKEOptions{KEMSeed: []byte{1, 2, 3}}})
	if !errors.Is(err, internal.ErrInvalidKEMSeed) {
		t.Fatalf("expected invalid KEM seed error, got %v", err)
	}

	// The client must still be usable.
	if _, err = client.GenerateKE1(password); err != nil {
		t.Fatalf("client state was altered: %v", err)
	}
}

// TestHybrid_ClearState verifies ClearState wipes the KEM seed, so KE3 cannot be computed afterwards.
func TestHybrid_ClearState(t *testing.T) {
	conf := hybridConf(opaque.DefaultConfiguration(), opaque.MLKEM768)
	env := newHybridEnv(t, conf)
	client, _ := conf.Client()

	ke1, _ := client.GenerateKE1(password)
	ke2, _, err := env.server.GenerateKE2(ke1, env.record)
	if err != nil {
		t.Fatal(err)
	}

	client.ClearState()

	if _, _, _, err = client.GenerateKE3(ke2, clientIdentity, serverIdentity); err == nil {
		t.Fatal("expected an error after ClearState")
	}
}

// TestHybrid_ConfigurationSerialization verifies the KEM survives serialization, classical encodings are unchanged,
// and non-canonical or invalid KEM encodings are rejected.
func TestHybrid_ConfigurationSerialization(t *testing.T) {
	classic := opaque.DefaultConfiguration()
	hybrid := opaque.DefaultHybridConfiguration()

	cs, hs := classic.Serialize(), hybrid.Serialize()
	if len(hs) != len(cs)+1 || hs[len(hs)-1] != byte(opaque.MLKEM768) || !bytes.Equal(cs, hs[:len(cs)]) {
		t.Fatal("unexpected hybrid configuration encoding")
	}

	decoded, err := opaque.DeserializeConfiguration(hs)
	if err != nil {
		t.Fatal(err)
	}

	if err = decoded.Equals(hybrid); err != nil {
		t.Fatal(err)
	}

	if err = classic.Equals(hybrid); err == nil {
		t.Fatal("classical and hybrid configurations must differ")
	}

	for name, enc := range map[string][]byte{
		"explicit NoKEM": append(append([]byte{}, cs...), 0),
		"unknown KEM":    append(append([]byte{}, cs...), 99),
		"trailing bytes": append(append([]byte{}, hs...), 1),
	} {
		if _, err = opaque.DeserializeConfiguration(enc); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}

	bad := opaque.DefaultConfiguration()
	bad.KEM = 42

	if _, err = bad.Client(); !errors.Is(err, internal.ErrInvalidKEMid) {
		t.Fatalf("expected invalid KEM id error, got %v", err)
	}
}

// TestHybrid_ClassicalTranscriptUnchanged verifies no KEM fields leak into classical RFC 9807 messages (byte-level
// conformance is covered by the RFC test vectors).
func TestHybrid_ClassicalTranscriptUnchanged(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	conf.KSF = 0
	env := newHybridEnv(t, conf)
	client, _ := conf.Client()

	ke1, _ := client.GenerateKE1(password)
	if ke1.ClientKEMKey != nil {
		t.Fatal("classical KE1 must not carry a KEM key")
	}

	ke2, _, err := env.server.GenerateKE2(ke1, env.record)
	if err != nil {
		t.Fatal(err)
	}

	if ke2.ServerKEMCiphertext != nil {
		t.Fatal("classical KE2 must not carry a KEM ciphertext")
	}
}
