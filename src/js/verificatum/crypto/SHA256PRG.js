
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
