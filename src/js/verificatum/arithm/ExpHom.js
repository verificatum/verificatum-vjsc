
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
