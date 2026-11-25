// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo. kemKey is the client's ephemeral KEM
// encapsulation key in hybrid mode, and nil otherwise.
func Start(g ecc.Group, esk *ecc.Scalar, nonce, kemKey []byte) *message.KE1 {
	epk := g.Base().Multiply(esk)

	return &message.KE1{
		CredentialRequest: message.CredentialRequest{
			BlindedMessage: nil,
		},
		ClientNonce:    nonce,
		ClientKeyShare: epk,
		ClientKEMKey:   kemKey,
	}
}

// Finalize verifies and responds to KE2. If the handshake is successful, this functions
// returns a KE3 message and the session secret. kemSecret is the decapsulated KEM shared secret in hybrid mode, and nil
// otherwise.
func Finalize(
	conf *internal.Configuration,
	secretKey, ephemeralSecretKey *ecc.Scalar,
	identities *Identities,
	serverPublicKey *ecc.Element,
	ke2 *message.KE2,
	ke1 []byte,
	kemSecret []byte,
) (*message.KE3, []byte, bool) {
	ikm := k3dh(
		ke2.ServerKeyShare,
		ephemeralSecretKey,
		serverPublicKey,
		ephemeralSecretKey,
		ke2.ServerKeyShare,
		secretKey,
		kemSecret,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, identities, ikm, ke1, ke2)

	if !conf.MAC.Equal(serverMac, ke2.ServerMac) {
		return nil, nil, false
	}

	return &message.KE3{ClientMac: clientMac}, sessionSecret, true
}
