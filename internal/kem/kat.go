// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 CPO-EH. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

//go:build opaque_kat

package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"errors"
	"slices"
	"sync"
)

// This file is only compiled with the opaque_kat build tag. It lets the test vectors fix the randomness of the
// server's ML-KEM encapsulation, so that KE2 is reproducible. Fixing that randomness in production would let anyone
// who knows it compute the KEM shared secret, which is why it is not part of the public API and not part of regular
// builds.

// EncapsulationRandomnessSize is the size of the randomness used by derandomized encapsulation.
const EncapsulationRandomnessSize = 32

var (
	errRandomnessLength = errors.New("invalid KEM encapsulation randomness length")

	katMu         sync.Mutex
	katRandomness []byte
)

// SetEncapsulationRandomness makes every following call to Encapsulate use the derandomized encapsulation with r,
// until the returned function is called. It returns an error if r is not EncapsulationRandomnessSize bytes long.
func SetEncapsulationRandomness(r []byte) (restore func(), err error) {
	if len(r) != EncapsulationRandomnessSize {
		return nil, errRandomnessLength
	}

	katMu.Lock()
	katRandomness = slices.Clone(r)
	katMu.Unlock()

	return func() {
		katMu.Lock()
		katRandomness = nil
		katMu.Unlock()
	}, nil
}

func (i ID) encapsulateKAT(ek []byte) (sharedSecret, ciphertext []byte, ok bool, err error) {
	katMu.Lock()
	r := katRandomness
	katMu.Unlock()

	if r == nil {
		return nil, nil, false, nil
	}

	sharedSecret, ciphertext, err = i.EncapsulateDerand(ek, r)

	return sharedSecret, ciphertext, true, err
}

// EncapsulateDerand is the derandomized encapsulation (ML-KEM.Encaps_internal in FIPS 203), using the provided 32
// bytes of randomness.
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
