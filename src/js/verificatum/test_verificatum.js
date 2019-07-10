
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
