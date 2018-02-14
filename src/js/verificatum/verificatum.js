
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
