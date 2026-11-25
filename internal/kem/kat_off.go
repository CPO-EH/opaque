// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 CPO-EH. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

//go:build !opaque_kat

package kem

// encapsulateKAT is disabled in regular builds: encapsulation always uses fresh randomness.
func (i ID) encapsulateKAT(_ []byte) (sharedSecret, ciphertext []byte, ok bool, err error) {
	return nil, nil, false, nil
}
