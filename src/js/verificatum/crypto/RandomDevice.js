
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

// ##################################################################
// ############### RandomDevice #####################################
// ##################################################################

/**
 * @description Random device for cryptographic use. This is a wrapper
 * of a built-in source of randomness that is different depending on
 * the platform. The definition depends on the platform, but
 * guarantees a random output secure for cryptographic use (assuming
 * that these libraries are correctly implemented).
 * @class
 * @memberof verificatum.crypto
 */
function RandomDevice() {
};
RandomDevice.prototype = Object.create(RandomSource.prototype);
RandomDevice.prototype.constructor = RandomDevice;

/* eslint-disable no-negated-condition */
// We are in a browser.
if (typeof window !== "undefined" && typeof window.crypto !== "undefined") {

    RandomDevice.prototype.getBytes = function (len) {
        var byteArray = new Uint8Array(len);
        window.crypto.getRandomValues(byteArray);
        var bytes = [];
        for (var i = 0; i < len; i++) {
            bytes[i] = byteArray[i];
        }
        return bytes;
    };

    // We are in nodejs.
} else if (typeof require !== "undefined") {

    RandomDevice.prototype.getBytes = (function () {
        var crypto = require("crypto");

        return function (len) {
            var tmp = crypto.randomBytes(len);
            var res = [];
            for (var i = 0; i < tmp.length; i++) {
                res[i] = tmp[i];
            }
            return res;
        };
    })();

    // We do not know where we are.
} else {
    RandomDevice.prototype.getBytes = (function () {
        return function () {
            throw Error("Unable to find a suitable random device!");
        };
    })();
}
/* eslint-enable no-negated-condition */
