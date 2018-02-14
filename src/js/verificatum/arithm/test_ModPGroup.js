
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
// ################### Test ModPGroup.js ################################
// ######################################################################

M4_NEEDS(verificatum/arithm/ModPGroup.js)dnl
M4_NEEDS(verificatum/arithm/test_PGroup.js)dnl

var test_ModPGroup = (function () {
    var prefix = "verificatum.arithm.ModPGroup";
    var arithm = verificatum.arithm;

dnl Example groups.
M4_INCLUDE(verificatum/arithm/test_ModPGroup_params.js)dnl

    var pGroups = arithm.ModPGroup.getPGroups();

    var identities = function (testTime) {
        test_PGroup.identities(prefix, pGroups, testTime);
    };
    var multiplication_commutativity = function (testTime) {
        test_PGroup.multiplication_commutativity(prefix, pGroups, testTime);
    };
    var multiplication_associativity = function (testTime) {
        test_PGroup.multiplication_associativity(prefix, pGroups, testTime);
    };
    var exp = function (testTime) {
        test_PGroup.exp(prefix, pGroups, testTime);
    };
    var fixed = function (testTime) {
        test_PGroup.fixed(prefix, pGroups, testTime);
    };
    var inversion = function (testTime) {
        test_PGroup.inversion(prefix, pGroups, testTime);
    };
    var conversion = function (testTime) {
        test_PGroup.conversion(prefix, pGroups, testTime);
    };
    var encoding = function (testTime) {
        test_PGroup.encoding(prefix, pGroups, testTime);
    };
    var hex = function (testTime) {
        test_PGroup.hex(prefix, pGroups, testTime);
    };

    var run = function (testTime) {
        identities(testTime);
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        exp(testTime);
        fixed(testTime);
        inversion(testTime);
        conversion(testTime);
        encoding(testTime);
        hex(testTime);
    };
    return {
        pGroups: pGroups,
        run: run
    };
})();
