
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
// ################### ModPowProd ########################################
// ######################################################################

M4_NEEDS(verificatum/arithm/LargeInteger.js)dnl

/**
 * @description Pre-computes values to be used for simultaneous
 * exponentiation for a given list b of k bases and a modulus m. The
 * method {@link verificatum.arithm.ModPowProd#modPowProd} then takes
 * a list of exponents e and outputs the modular power product
 *
 * <p>
 *
 * g[0] ^ e[0] * ... * g[k - 1] ^ e[k - 1] mod m.
 *
 * <p>
 *
 * The number of exponents must match the number of bases for which
 * pre-computation is performed.
 *
 * @param bases List of bases.
 * @param modulus Modulus.
 * @class
 * @memberof verificatum.arithm
 */
function ModPowProd(bases, modulus) {

    var b = [];
    for (var i = 0; i < bases.length; i++) {
        b[i] = bases[i].value;
    }

    this.width = bases.length;
    this.t = li.modpowprodtab(b, modulus.value);
    this.modulus = modulus;
};

/**
 * @description Computes a power-product using the given exponents.
 * @param exponents Exponents.
 * @return Power product.
 * @method
 */
ModPowProd.prototype.modPowProd = function (exponents) {

    if (exponents.length !== this.width) {
        /* istanbul ignore next */
        throw Error("Wrong number of exponents! (" +
                    exponents.length + " != " + this.width + ")");
    }

    var e = [];
    for (var i = 0; i < exponents.length; i++) {
        e[i] = exponents[i].value;
    }

    var res = new LargeInteger(this.modulus.length);
    li.modpowprod(res.value, this.t, e, this.modulus.value);

    if (li.iszero(res.value)) {
        res.sign = 0;
    } else {
        res.sign = 1;
    }
    li.normalize(res.value);
    return res;
};

/**
 * @description Compute a power-product using the given bases,
 * exponents, and modulus. This is a naive implementation for simple
 * use and to debug {@link verificatum.arithm.ModPowProd#modPowProd}.
 * @param bases Bases.
 * @param exponents Exponents.
 * @param modulus Modulus.
 * @return Power product.
 * @method
 */
ModPowProd.naive = function (bases, exponents, modulus) {
    var result = LargeInteger.ONE;
    for (var i = 0; i < bases.length; i++) {
        result = result.modMul(bases[i].modPow(exponents[i], modulus), modulus);
    }
    return result;
};
