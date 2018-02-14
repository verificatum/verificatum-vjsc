
// Copyright 2008-2018 Douglas Wikstrom
//
// This file is part of Verificatum JavaScript Cryptographic library
// (VJSC).
//
// VJSC is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// VJSC is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
// Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with VJSC. If not, see <http://www.gnu.org/licenses/>.

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
