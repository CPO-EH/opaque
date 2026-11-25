// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package kem wraps the post-quantum ML-KEM (FIPS 203) key encapsulation mechanisms used to harden the 3DH AKE
// into a hybrid (classical + post-quantum) key exchange.
package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"errors"
)

// ID identifies a KEM. The zero value means no KEM is used (classical RFC 9807 3DH).
type ID byte

const (
	// None disables the post-quantum KEM, i.e. the plain RFC 9807 3DH AKE.
	None ID = 0

	// MLKEM768 identifies ML-KEM-768 (NIST security category 3).
	MLKEM768 ID = 1

	// MLKEM1024 identifies ML-KEM-1024 (NIST security category 5).
	MLKEM1024 ID = 2
)

const (
	// SeedSize is the size of the seed from which a decapsulation key is derived.
	SeedSize = mlkem.SeedSize

	// SharedSecretSize is the size of the shared secret produced by encapsulation.
	SharedSecretSize = mlkem.SharedKeySize

	// EncapsulationRandomnessSize is the size of the randomness used by derandomized encapsulation.
	EncapsulationRandomnessSize = 32
)

var (
	errUnknownKEM = errors.New("unknown KEM")
	errSeedLength = errors.New("invalid KEM seed length")
)

// Available returns whether the identifier designates an implemented KEM (None is not a KEM).
func (i ID) Available() bool {
	return i == MLKEM768 || i == MLKEM1024
}

// Enabled returns whether a KEM is used.
func (i ID) Enabled() bool {
	return i != None
}

// String returns the KEM name.
func (i ID) String() string {
	switch i {
	case None:
		return "None"
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

// EncapsulationKeySize returns the byte length of an encapsulation (public) key, or 0 if None.
func (i ID) EncapsulationKeySize() int {
	switch i {
	case MLKEM768:
		return mlkem.EncapsulationKeySize768
	case MLKEM1024:
		return mlkem.EncapsulationKeySize1024
	default:
		return 0
	}
}

// CiphertextSize returns the byte length of a ciphertext, or 0 if None.
func (i ID) CiphertextSize() int {
	switch i {
	case MLKEM768:
		return mlkem.CiphertextSize768
	case MLKEM1024:
		return mlkem.CiphertextSize1024
	default:
		return 0
	}
}

// EncapsulationKey derives the decapsulation key from seed and returns the encoded encapsulation key.
func (i ID) EncapsulationKey(seed []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, errSeedLength
	}

	switch i {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}

		return dk.EncapsulationKey().Bytes(), nil
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, err
		}

		return dk.EncapsulationKey().Bytes(), nil
	default:
		return nil, errUnknownKEM
	}
}

// ValidateEncapsulationKey verifies the encapsulation key is well-formed (length and modulus check of FIPS 203).
func (i ID) ValidateEncapsulationKey(ek []byte) error {
	switch i {
	case MLKEM768:
		_, err := mlkem.NewEncapsulationKey768(ek)
		return err
	case MLKEM1024:
		_, err := mlkem.NewEncapsulationKey1024(ek)
		return err
	default:
		return errUnknownKEM
	}
}

// Encapsulate generates a fresh shared secret and its ciphertext for the encapsulation key.
func (i ID) Encapsulate(ek []byte) (sharedSecret, ciphertext []byte, err error) {
	switch i {
	case MLKEM768:
		k, err := mlkem.NewEncapsulationKey768(ek)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, ciphertext = k.Encapsulate()

		return sharedSecret, ciphertext, nil
	case MLKEM1024:
		k, err := mlkem.NewEncapsulationKey1024(ek)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, ciphertext = k.Encapsulate()

		return sharedSecret, ciphertext, nil
	default:
		return nil, nil, errUnknownKEM
	}
}

// EncapsulateDerand is the derandomized encapsulation (ML-KEM.Encaps_internal in FIPS 203), using the provided 32
// bytes of randomness. It must only be used to produce or check known-answer test vectors.
func (i ID) EncapsulateDerand(ek, randomness []byte) (sharedSecret, ciphertext []byte, err error) {
	switch i {
	case MLKEM768:
		k, err := mlkem.NewEncapsulationKey768(ek)
		if err != nil {
			return nil, nil, err
		}

		return mlkemtest.Encapsulate768(k, randomness)
	case MLKEM1024:
		k, err := mlkem.NewEncapsulationKey1024(ek)
		if err != nil {
			return nil, nil, err
		}

		return mlkemtest.Encapsulate1024(k, randomness)
	default:
		return nil, nil, errUnknownKEM
	}
}

// Decapsulate recovers the shared secret from the ciphertext, using the decapsulation key derived from seed.
// ML-KEM uses implicit rejection: an invalid ciphertext of correct length yields a pseudo-random secret, which
// subsequently makes the AKE MAC verification fail.
func (i ID) Decapsulate(seed, ciphertext []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, errSeedLength
	}

	switch i {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}

		return dk.Decapsulate(ciphertext)
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, err
		}

		return dk.Decapsulate(ciphertext)
	default:
		return nil, errUnknownKEM
	}
}
