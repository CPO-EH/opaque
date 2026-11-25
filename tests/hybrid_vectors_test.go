// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 CPO-EH. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/kem"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/message"
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
// The server's encapsulation randomness can only be fixed in builds with the opaque_kat tag. Without the tag, this
// file checks the registration, the client side of the login and the key schedule. With the tag,
// hybrid_vectors_kat_test.go also reproduces KE2 and can regenerate the file:
//
//	go test -tags opaque_kat ./tests -run TestHybridVectors -update-hybrid-vectors

const hybridVectorsFile = "hybrid_vectors.json"

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

// parties returns a client and a server set up with the vector configuration and server keys.
func (v *hybridVector) parties(t *testing.T) (*opaque.Configuration, *opaque.Client, *opaque.Server) {
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

	return conf, client, server
}

func decodeBlind(t *testing.T, conf *opaque.Configuration, b []byte) *ecc.Scalar {
	t.Helper()

	s := conf.OPRF.Group().NewScalar()
	if err := s.Decode(b); err != nil {
		t.Fatal(err)
	}

	return s
}

// register runs the registration from the vector inputs, fills in the registration outputs and intermediates, and
// returns the client record.
func (v *hybridVector) register(
	t *testing.T,
	conf *opaque.Configuration,
	client *opaque.Client,
	server *opaque.Server,
) *opaque.ClientRecord {
	t.Helper()

	req, err := client.RegistrationInit(v.Inputs.Password,
		&opaque.ClientOptions{OPRFBlind: decodeBlind(t, conf, v.Inputs.BlindRegistration)})
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

	v.Outputs.RegistrationRequest = req.Serialize()
	v.Outputs.RegistrationResponse = resp.Serialize()
	v.Outputs.RegistrationRecord = record.Serialize()
	v.Outputs.ExportKey = exportKey
	v.Intermediates.ClientPublicKey = record.ClientPublicKey.Encode()
	v.Intermediates.MaskingKey = record.MaskingKey
	v.Intermediates.Envelope = record.Envelope

	return &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: v.Inputs.CredentialIdentifier,
		ClientIdentity:       v.Inputs.ClientIdentity,
	}
}

// startLogin generates KE1 from the vector inputs and fills in the matching output and intermediate.
func (v *hybridVector) startLogin(t *testing.T, conf *opaque.Configuration, client *opaque.Client) *message.KE1 {
	t.Helper()

	ke1, err := client.GenerateKE1(v.Inputs.Password, &opaque.ClientOptions{
		OPRFBlind: decodeBlind(t, conf, v.Inputs.BlindLogin),
		AKE: &opaque.AKEOptions{
			SecretKeyShareSeed: v.Inputs.ClientKeyshareSeed,
			Nonce:              v.Inputs.ClientNonce,
			KEMSeed:            v.Inputs.ClientKEMSeed,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v.Outputs.KE1 = ke1.Serialize()
	v.Intermediates.ClientKEMPublicKey = ke1.ClientKEMKey

	return ke1
}

// serverKE2 generates KE2 with the fixed server inputs of the vector. The KEM ciphertext is only reproducible when
// the encapsulation randomness has been fixed, which requires the opaque_kat build tag.
func (v *hybridVector) serverKE2(
	t *testing.T,
	server *opaque.Server,
	ke1 *message.KE1,
	record *opaque.ClientRecord,
) (*message.KE2, *opaque.ServerOutput) {
	t.Helper()

	ke2, output, err := server.GenerateKE2(ke1, record, &opaque.ServerOptions{
		MaskingNonce: v.Inputs.MaskingNonce,
		AKE: &opaque.AKEOptions{
			SecretKeyShareSeed: v.Inputs.ServerKeyshareSeed,
			Nonce:              v.Inputs.ServerNonce,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return ke2, output
}

// finishLogin runs KE3 on the client and fills in the remaining outputs.
func (v *hybridVector) finishLogin(t *testing.T, client *opaque.Client, ke2 *message.KE2) *message.KE3 {
	t.Helper()

	ke3, sessionKey, exportKey, err := client.GenerateKE3(ke2, v.Inputs.ClientIdentity, v.Inputs.ServerIdentity)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(exportKey, v.Outputs.ExportKey) {
		t.Fatal("registration and login export keys differ")
	}

	v.Outputs.KE2 = ke2.Serialize()
	v.Outputs.KE3 = ke3.Serialize()
	v.Outputs.SessionKey = sessionKey
	v.Intermediates.KEMCiphertext = ke2.ServerKEMCiphertext

	return ke3
}

// checkClientSide replays the vector without fixing the encapsulation randomness of the server. The registration,
// KE1 and the part of KE2 before the KEM ciphertext must be reproduced, a login with the server's own KE2 must
// succeed, and the client must turn the KE2 of the vector into the KE3 and session key of the vector.
func (v *hybridVector) checkClientSide(t *testing.T) {
	t.Helper()

	conf, client, server := v.parties(t)
	got := &hybridVector{Config: v.Config, Inputs: v.Inputs}

	record := got.register(t, conf, client, server)
	if !bytes.Equal(got.Outputs.RegistrationRequest, v.Outputs.RegistrationRequest) ||
		!bytes.Equal(got.Outputs.RegistrationResponse, v.Outputs.RegistrationResponse) ||
		!bytes.Equal(got.Outputs.RegistrationRecord, v.Outputs.RegistrationRecord) ||
		!bytes.Equal(got.Outputs.ExportKey, v.Outputs.ExportKey) {
		t.Fatal("registration differs from the vector")
	}

	ke1 := got.startLogin(t, conf, client)
	if !bytes.Equal(got.Outputs.KE1, v.Outputs.KE1) ||
		!bytes.Equal(got.Intermediates.ClientKEMPublicKey, v.Intermediates.ClientKEMPublicKey) {
		t.Fatal("KE1 differs from the vector")
	}

	// The server's own KE2 matches the vector up to the KEM ciphertext, and completes a login.
	ke2, output := got.serverKE2(t, server, ke1, record)
	kemStart := len(v.Outputs.KE2) - len(v.Intermediates.KEMCiphertext) - len(v.Outputs.KE3)

	if !bytes.Equal(ke2.Serialize()[:kemStart], v.Outputs.KE2[:kemStart]) {
		t.Fatal("KE2 differs from the vector before the KEM ciphertext")
	}

	live := &hybridVector{Config: v.Config, Inputs: v.Inputs, Outputs: got.Outputs}
	_, liveClient, _ := v.parties(t)
	live.startLogin(t, conf, liveClient)

	ke3 := live.finishLogin(t, liveClient, ke2)
	if err := server.LoginFinish(ke3, output.ClientMAC); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(live.Outputs.SessionKey, output.SessionSecret) {
		t.Fatal("client and server session keys differ")
	}

	// The client turns the KE2 of the vector into the KE3 and session key of the vector.
	vectorKE2, err := client.Deserialize.KE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	got.finishLogin(t, client, vectorKE2)

	if !bytes.Equal(got.Outputs.KE3, v.Outputs.KE3) || !bytes.Equal(got.Outputs.SessionKey, v.Outputs.SessionKey) {
		t.Fatal("client login differs from the vector")
	}
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

	// KEM: the client's seed gives the encapsulation key of KE1, and decapsulating the ciphertext gives the secret.
	if ekCheck, err := kemID.EncapsulationKey(v.Inputs.ClientKEMSeed); err != nil || !bytes.Equal(ek, ekCheck) {
		t.Fatal("KEM encapsulation key does not match the client seed")
	}

	ss, err := kemID.Decapsulate(v.Inputs.ClientKEMSeed, ct)
	if err != nil {
		t.Fatal(err)
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

func loadHybridVectors(t *testing.T) []*hybridVector {
	t.Helper()

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

	return vectors
}

// TestHybridVectors checks the hybrid mode test vectors on the client side and against the key schedule of the
// specification. Builds with the opaque_kat tag also run TestHybridVectorsKAT, which reproduces them in full.
func TestHybridVectors(t *testing.T) {
	for i, v := range loadHybridVectors(t) {
		t.Run(fmt.Sprintf("%d-%s-%s", i, v.Config.OPRF, v.Config.KEM), func(t *testing.T) {
			v.checkClientSide(t)
			v.checkKeySchedule(t)
		})
	}
}
