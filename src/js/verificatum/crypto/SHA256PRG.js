
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
// ############### SHA256PRG ########################################
// ##################################################################

/**
 * @description Pseudo-random generator based on SHA-256 in counter
 * mode.
 * @class
 * @memberof verificatum.crypto
 */
function SHA256PRG() {
    this.input = null;
};
SHA256PRG.prototype = Object.create(RandomSource.prototype);
SHA256PRG.prototype.constructor = SHA256PRG;
SHA256PRG.seedLength = 32;

/**
 * @description Initializes this PRG with the given seed.
 * @param seed Seed bytes.
 * @method
 */
SHA256PRG.prototype.setSeed = function (seed) {
    if (seed.length >= 32) {
        this.input = seed.slice(0, 32);
        this.input.length += 4;
        this.counter = 0;
        this.buffer = [];
        this.index = 0;
    } else {
        throw Error("Too short seed!");
    }
};

SHA256PRG.prototype.getBytes = function (len) {
    if (this.input === null) {
        throw Error("Uninitialized PRG!");
    }

    var res = [];
    res.length = len;

    for (var i = 0; i < res.length; i++) {

        if (this.index === this.buffer.length) {
            verificatum.util.setUint32ToByteArray(this.input, this.counter, 32);
            this.buffer = sha256.hash(this.input);
            this.index = 0;
            this.counter++;
        }
        res[i] = this.buffer[this.index];
        this.index++;
    }
    return res;
};
