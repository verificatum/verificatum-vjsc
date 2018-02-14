
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
// ################### Utility Functions ################################
// ######################################################################

/**
 * @description Returns the epoch in milliseconds.
 * @return Epoch in milliseconds.
 * @function time_ms
 * @memberof verificatum.util
 */
function time_ms() {
    return (new Date()).getTime();
};

/**
 * @description Returns the epoch in seconds.
 * @return Epoch in seconds.
 * @function time
 * @memberof verificatum.util
 */
function time() {
    return Math.floor(time_ms() / 1000);
};

/**
 * @description Tests if an object is of a given type.
 *
 * <p>
 *
 * ASSUMPTIONS: type is a string literal and not an instance of String.
 * @param obj Object to determine type of. (Here we can use either a
 * string literal or a String instance if obj is a string to patch the
 * intellectually challenged way JavaScript handles these.)
 * @param type Type of object.
 * @return True or false depending on if the object is of the given
 * type or not.
 * @function ofType
 * @memberof verificatum.util
 */
var ofType = function (obj, type) {

    // typeof s for a string literal s is always "string".
    if (typeof type === "string") {
        if (type === "array") {
            return Array.isArray(obj);
        } else if (type === "string") {
            return typeof obj === type || obj instanceof String;
        } else {
            return typeof obj === type;
        }
    } else {
        return obj.constructor === type;
    }
};

/**
 * @description Creates a list filled with the same value.
 * @param value Value to be repeated.
 * @param width Number of repetitions.
 * @return List containing the value.
 * @function full
 * @memberof verificatum.util
 */
var fill = function (value, width) {
    var a = [];
    for (var i = 0; i < width; i++) {
        a[i] = value;
    }
    return a;
};

/**
 * @description Creates a list filled with the same value or the value
 * itself if a single repetition is requested.
 * @param value Value to be repeated.
 * @param width Number of repetitions.
 * @return List containing the value or the value itself if width == 1.
 * @function full
 * @memberof verificatum.util
 */
var full = function (value, width) {
    if (typeof width === "undefined" || width === 1) {
        return value;
    } else {
        return fill(value, width);
    }
};

/**
 * @description Changes the wordsize of an array of words.
 * @param words Array of words.
 * @param orig_wordsize Original bitsize of words (at most 32).
 * @param new_wordsize Bitsize of output words (at most 32).
 * @return Representation of the input array of bits with new
 * wordsize.
 * @function change_wordsize
 * @memberof verificatum.util
 */
var change_wordsize = function (words, orig_wordsize, new_wordsize) {

    var mask_all = 0xFFFFFFFF >>> 32 - new_wordsize;

    // Array with new wordsize holding result.
    var new_words = [];
    new_words[0] = 0;

    // Encodes bit position in words.
    var j = 0;
    var jb = 0;

    // Encodes bit position in new_words.
    var i = 0;
    var ib = 0;

    while (j < words.length) {

        // Insert as many bits as possible from words[j] into new_words[i].
        new_words[i] |= words[j] >>> jb << ib & mask_all;

        // Number of inserted bits.
        var inserted_bits = Math.min(orig_wordsize - jb, new_wordsize - ib);

        // Determine if we have filled new_words[i] and if so, then move on
        // to the beginning of the next word.
        ib = ib + inserted_bits;
        if (ib === new_wordsize) {
            i++;
            ib = 0;
            new_words[i] = 0;
        }

        // Determine the number of remaining unused bits of words[j] and
        // if none are left, then move on to the beginning of the next
        // word.
        jb = jb + inserted_bits;
        if (jb === orig_wordsize) {
            j++;
            jb = 0;
        }
    }
    return new_words;
};

var digits = "0123456789abcdef";

var hex = function (b) {
    return digits[b >> 4 & 0xF] + digits[b & 0xF];
};

/**
 * @description Converts an ASCII string to a byte array.
 * @param ascii ASCII string.
 * @return Corresponding byte array.
 * @function asciiToByteArray
 * @memberof verificatum.util
 */
var asciiToByteArray = function (ascii) {
    var bytes = [];
    for (var i = 0; i < ascii.length; i++) {
        bytes.push(ascii.charCodeAt(i));
    }
    return bytes;
};

/**
 * @description Converts byte array to ASCII string.
 * @param bytes Input bytes.
 * @return ASCII string corresponding to the input.
 * @function byteArrayToAscii
 * @memberof verificatum.util
 */
var byteArrayToAscii = function (bytes) {
    var ascii = "";
    for (var i = 0; i < bytes.length; i++) {
        ascii += String.fromCharCode(bytes[i]);
    }
    return ascii;
};

/**
 * @description Converts a byte array to its hexadecimal encoding.
 * @param array Input byte array.
 * @return Hexadecimal representation of this array.
 * @function byteArrayToHex
 * @memberof verificatum.util
 */
var byteArrayToHex = function (array) {
    var hexString = "";
    for (var i = 0; i < array.length; i++) {
        hexString += hex(array[i]);
    }
    return hexString;
};

/**
 * @description Converts a hexadecimal encoding of a byte array to the
 * byte array.
 * @param hex Hexadecimal encoding of byte array.
 * @return Byte array corresponding to the input.
 * @function hexToByteArray
 * @memberof verificatum.util
 */
var hexToByteArray = function (hex) {

    // Correct hex strings of uneven length.
    if (hex.length % 2 === 1) {
        hex = "0" + hex;
    }

    // Convert bytes.
    var res = [];
    var i = 0;
    hex.replace(/(..)/g,
                function (hex) {
                    res[i++] = parseInt(hex, 16);
                });
    return res;
};

/**
 * @description Returns true or false depending on if the two input
 * arrays hold identical elements or not.
 * @param x Array of elements.
 * @param y Array of elements.
 * @return Value of boolean equality predicate for arrays.
 * @function equalsArray
 * @memberof verificatum.util
 */
var equalsArray = function (x, y) {

    if (x.length !== y.length) {
        return false;
    }
    for (var i = 0; i < x.length; i++) {
        if (x[i] !== y[i]) {
            return false;
        }
    }
    return true;
};

/**
 * @description Generates random array of the given length and
 * wordsize.
 * @param len Number of nominal bits in random output.
 * @param wordsize Number of bits in each word.
 * @param randomSource Source of randomness.
 * @return Array of randomly generated words.
 * @function randomArray
 * @memberof verificatum.util
 */
var randomArray = function (len, wordsize, randomSource) {

    var no_bytes = Math.floor((len * wordsize + 7) / 8);
    var bytes = randomSource.getBytes(no_bytes);

    var no_msbits = wordsize % 8;
    if (no_msbits !== 0) {
        bytes[no_bytes - 1] &= 0xFF >>> 8 - no_msbits;
    }

    if (wordsize === 8) {
        return bytes;
    } else {
        return change_wordsize(bytes, 8, wordsize);
    }
};

/**
 * @description Reads a 32-bit integer in little-endian byte order
 * from the given byte array.
 * @param bytes Source of bytes.
 * @param index Offset for reading.
 * @function readUint32FromByteArray
 * @memberof verificatum.util
 */
var readUint32FromByteArray = function (bytes, index) {
    if (typeof index === "undefined") {
        index = 0;
    }
    var value = 0;
    for (var i = index; i < index + 4; i++) {
        value <<= 8;
        value |= bytes[i];
    }
    return value >>> 0;
};

/**
 * @description Writes a 32-bit integer in little-endian byte order.
 * @param destination Destination of result.
 * @param value Value to write.
 * @param index Offset for writing.
 * @function setUint32ToByteArray
 * @memberof verificatum.util
 */
var setUint32ToByteArray = function (destination, value, index) {

    for (var i = index + 3; i >= index; i--) {
        destination[i] = value & 0xFF;
        value >>= 8;
    }
};

/**
 * @description Reads a 16-bit integer in little-endian byte order
 * from the given byte array.
 * @param bytes Source of bytes.
 * @param index Offset for reading.
 * @function readUint16FromByteArray
 * @memberof verificatum.util
 */
var readUint16FromByteArray = function (bytes, index) {
    if (typeof index === "undefined") {
        index = 0;
    }
    var value = 0;
    for (var i = index; i < index + 2; i++) {
        value <<= 8;
        value |= bytes[i];
    }
    return value >>> 0;
};

/**
 * @description Writes a 16-bit integer in little-endian byte order.
 * @param destination Destination of result.
 * @param value Value to write.
 * @param index Offset for writing.
 * @function setUint16ToByteArray
 * @memberof verificatum.util
 */
var setUint16ToByteArray = function (destination, value, index) {

    for (var i = index + 1; i >= index; i--) {
        destination[i] = value & 0xFF;
        value >>= 8;
    }
};
