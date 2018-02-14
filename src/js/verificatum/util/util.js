
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

/**
 * @description Utility classes and functions.
 * @namespace util
 * @memberof verificatum
 */
var util = (function () {

dnl Utility functions.
M4_INCLUDE(verificatum/util/functions.js)dnl

    return {

        "time_ms": time_ms,
        "time": time,
        "ofType": ofType,
        "fill": fill,
        "full": full,
        "change_wordsize": change_wordsize,
        "asciiToByteArray": asciiToByteArray,
        "byteArrayToAscii": byteArrayToAscii,
        "byteArrayToHex": byteArrayToHex,
        "hexToByteArray": hexToByteArray,
        "equalsArray": equalsArray,
        "randomArray": randomArray,
        "readUint32FromByteArray": readUint32FromByteArray,
        "setUint32ToByteArray": setUint32ToByteArray,
        "readUint16FromByteArray": readUint16FromByteArray,
        "setUint16ToByteArray": setUint16ToByteArray
    };
})();
