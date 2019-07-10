
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
// ################### Hom ##############################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PField.js)dnl
M4_NEEDS(verificatum/arithm/PGroup.js)dnl

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Homomorphism from a ring to a group.
 * @param domain Domain of homomorphism.
 * @param range Range of homomorphism.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function Hom(domain, range) {
    this.domain = domain;
    this.range = range;
}
Hom.prototype = Object.create(Object.prototype);
Hom.prototype.constructor = Hom;

/**
 * @description Evaluates the homomorphism.
 * @param value Input to the homomorphism.
 * @return Value of the homomorphism at the given value.
 * @method
 */
Hom.prototype.eva = function (value) {
    throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */
