
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
// ############## Javascript Verificatum Crypto Libary ##################
// ######################################################################

M4_NEEDS(verificatum/arithm/arithm.js)dnl
M4_NEEDS(verificatum/crypto/crypto.js)dnl

/**
 * @description
M4_INCLUDE(verificatum/README.js)dnl
 * @namespace verificatum
 */
var verificatum = (function () {

dnl Utility library.
M4_INCLUDE(verificatum/util/util.js)dnl

dnl Extended input/output library.
M4_INCLUDE(verificatum/eio/eio.js)dnl

dnl Library for arithmetic objects.
M4_INCLUDE(verificatum/arithm/arithm.js)dnl

dnl Library for cryptography.
M4_INCLUDE(verificatum/crypto/crypto.js)dnl

dnl Library for benchmarking.
M4_INCLUDEOPT(verificatum/benchmark/benchmark.js)dnl

    return {
        "version": "M4_VJSC_VERSION",

        "util": util,
        "eio": eio,
        "arithm": arithm,
        "crypto": crypto,
M4_EXPOPT(verificatum/benchmark/benchmark.js,benchmark)
    };
})();
