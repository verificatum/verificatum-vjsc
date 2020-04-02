
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
// ################### ExpHom ###########################################
// ######################################################################

M4_NEEDS(verificatum/arithm/Hom.js)dnl

/**
 * @description Exponentiation homomorphism from a ring to a
 * group. Note that the group is not necessarily a prime order group,
 * that the ring is not necessarily a field, and that the ring is not
 * necessarily the ring of exponents of group.
 * @param basis Basis element that is exponentiated.
 * @param domain Domain of homomorphism, which may be a subring of the
 * ring of exponents of the basis element.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function ExpHom(domain, basis) {
    Hom.call(this, domain, basis.pGroup);
    this.basis = basis;
}
ExpHom.prototype = Object.create(Hom.prototype);
ExpHom.prototype.constructor = ExpHom;

ExpHom.prototype.eva = function (value) {
    return this.basis.exp(value);
};
