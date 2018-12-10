
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
// ################### ArithmObject #####################################
// ######################################################################

/* istanbul ignore next */
/**
 * @description Arithmetic object.
 * @abstract
 * @class
 * @memberof verificatum.crypto
 */
function ArithmObject() {
};
ArithmObject.prototype = Object.create(Object.prototype);
ArithmObject.prototype.constructor = ArithmObject;

ArithmObject.prototype.getName = function () {
    var regex = /function\s?([^(]{1,})\(/;
    var results = regex.exec(this.constructor.toString());
    return results && results.length > 1 ? results[1] : "";
};
