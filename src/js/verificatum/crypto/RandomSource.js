
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

// ##################################################################
// ############### RandomSource #####################################
// ##################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Random source for cryptographic use.
 * @class
 * @memberof verificatum.crypto
 */
function RandomSource() {
};

/**
 * @description Generates the given number of random bytes.
 * @param len Number of bytes to generate.
 * @method
 */
RandomSource.prototype.getBytes = function (len) {
    throw new Error("Abstract method!");
};
/* jshint -W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */
