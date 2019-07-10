
// Copyright 2008-2019 Douglas Wikstrom
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
// ################### FixModPow ########################################
// ######################################################################

M4_NEEDS(verificatum/arithm/ModPowProd.js)dnl

/**
 * @description Fixed-basis exponentiation based on simultantaneous
 * exponentiation with exponent slicing.
 *
 * @param basis Basis.
 * @param modulus Modulus.
 * @param size Expected number of exponentiations to compute.
 * @param width If given this determines the width of the pre-computed
 * table, and otherwise it is chosen theoretically optimally.
 * @class
 * @memberof verificatum.arithm
 */
function FixModPow(basis, modulus, size, width) {

    var bitLength = modulus.bitLength();

    if (typeof width === "undefined") {
        width = FixModPow.optimalWidth(bitLength, size);
    }

    // Determine the number of bits associated with each bases.
    this.sliceSize = Math.floor((bitLength + width - 1) / width);

    // Create radix element.
    var powerBasis = LargeInteger.ONE.shiftLeft(this.sliceSize);

    // Create generators.
    var bases = [];
    bases[0] = basis;
    for (var i = 1; i < width; i++) {
        bases[i] = bases[i - 1].modPow(powerBasis, modulus);
    }

    // Invoke the pre-computation of the simultaneous exponentiation
    // code.
    this.mpp = new ModPowProd(bases, modulus);
};

/**
 * @description Takes the bit length of the exponents and the number
 * of exponentiations that we expect to compute and returns the
 * theoretically optimal width.
 * @param bitLength Expected bit length of exponents.
 * @param size Expected number of exponentiations to compute.
 * @return Theoretically optimal choice of width for the expected bit
 * length and number of exponentiations.
 */
FixModPow.optimalWidth = function (bitLength, size) {

    var width = 2;
    var cost = 1.5 * bitLength;
    var oldCost;
    do {

        oldCost = cost;

        // Amortized cost for table.
        var t = ((1 << width) - width + bitLength) / size;

        // Cost for multiplication.
        var m = bitLength / width;

        cost = t + m;

        width++;

    } while (width <= 16 && cost < oldCost);

    // We reduce the theoretical value by one to account for the
    // overhead.
    return width - 1;
};

/**
 * @description Cuts an input integer into the appropriate number of
 * slices and outputs a list of integers such that the ith bit belongs
 * to the ith slice.
 * @param exponent Exponent.
 * @return Array of exponents.
 * @method
 */
FixModPow.prototype.slice = function (exponent) {

    var exponents = [];

    var bitLength = exponent.bitLength();
    var offset = 0;
    var i = 0;

    while (i < this.mpp.width - 1 && offset < bitLength) {
        exponents[i] = exponent.slice(offset, offset + this.sliceSize);
        offset += this.sliceSize;
        i++;
    }

    // There is no bound on the bit size of the last slice.
    if (offset < bitLength) {
        exponents[i] = exponent.slice(offset, bitLength);
        offset += this.sliceSize;
        i++;
    }
    while (i < this.mpp.width) {
        exponents[i] = LargeInteger.ZERO;
        i++;
    }

    return exponents;
};

/**
 * @description Raises the fixed basis to the given exponent given the
 * fixed modulus.
 * @param exponent Exponent.
 * @return Power of fixed basis to the given exponent.
 * @method
 */
FixModPow.prototype.modPow = function (exponent) {
    return this.mpp.modPowProd(this.slice(exponent));
};
