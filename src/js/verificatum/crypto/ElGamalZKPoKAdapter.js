
// Copyright 2008-2020 Douglas Wikstrom
//
// This file is part of Verificatum JavaScript Cryptographic library
// (VJSC).
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// ######################################################################
// ################### ElGamalZKPoKAdapter ##############################
// ######################################################################

M4_NEEDS(verificatum/crypto/ZKPoK.js)dnl

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Adapter for {@link verificatum.crypto.ElGamalZKPoK}
 * that creates {@link verificatum.crypto.ZKPoK} that imposes
 * restrictions on plaintexts and ciphertexts.
 * @abstract
 * @class
 * @memberof verificatum.crypto
 */
function ElGamalZKPoKAdapter() {};
ElGamalZKPoKAdapter.prototype = Object.create(Object.prototype);
ElGamalZKPoKAdapter.prototype.constructor = ElGamalZKPoKAdapter;

/**
 * @description Generates a {@link verificatum.crypto.ZKPoK} that
 * imposes restrictions on ciphertexts.
 * @param publicKey El Gamal public key.
 * @return Instance of {@link verificatum.crypto.ZKPoK}.
 * @method
 */
ElGamalZKPoKAdapter.prototype.getZKPoK = function (publicKey) {
    throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */
