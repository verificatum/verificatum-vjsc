
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

M4_NEEDS(verificatum/verificatum.js)dnl
M4_NEEDS(verificatum/dev/dev.js)dnl
M4_NEEDS(verificatum/arithm/test_arithm.js)dnl
M4_NEEDS(verificatum/crypto/test_crypto.js)dnl

// ######################################################################
// ################### Test verificatum.js ##############################
// ######################################################################

M4_INCLUDE(verificatum/verificatum.js)dnl
M4_INCLUDE(verificatum/dev/dev.js)dnl

dnl Test utility functions.
M4_INCLUDEOPT(verificatum/util/test_util.js)dnl

dnl Test extended input and output routines. 
M4_INCLUDEOPT(verificatum/eio/test_eio.js)dnl

dnl Test arithmetic.
M4_INCLUDEOPT(verificatum/arithm/test_arithm.js)dnl

dnl Test cryptography.
M4_INCLUDEOPT(verificatum/crypto/test_crypto.js)dnl

var test_verificatum = (function () {

    var run = function (testTime) {
M4_RUNOPT(verificatum/util/test_util.js,test_util,testTime)
M4_RUNOPT(verificatum/eio/test_eio.js,test_eio,testTime)
M4_RUNOPT(verificatum/arithm/test_arithm.js,test_arithm,testTime)
M4_RUNOPT(verificatum/crypto/test_crypto.js,test_crypto,testTime)
    };
    return {
M4_EXPOPT(verificatum/util/test_util.js,test_util)
M4_EXPOPT(verificatum/eio/test_eio.js,test_eio)
M4_EXPOPT(verificatum/arithm/test_arithm.js,test_arithm)
M4_EXPOPT(verificatum/crypto/test_crypto.js,test_crypto)
        run: run
    };
})();

var testTime = parseInt(process.argv[2]);

var startMessage =
    "\n"
    + "---------------------------------------------------------------------\n"
    + " RUNNING TESTS\n\n"
    + " Please be patient. Some tests take a long time to complete due to\n"
    + " how comprehensive they are. This is particularly true for some \n"
    + " cryptographic routines\n"
    + "---------------------------------------------------------------------";

console.log(startMessage);

test_verificatum.run(testTime);
