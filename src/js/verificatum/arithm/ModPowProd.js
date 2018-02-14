
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
