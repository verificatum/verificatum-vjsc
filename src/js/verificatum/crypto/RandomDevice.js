
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
