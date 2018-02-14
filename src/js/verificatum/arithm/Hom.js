
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
