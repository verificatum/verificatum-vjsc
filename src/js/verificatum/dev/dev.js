
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

/* istanbul ignore next */
/**
 * @description Development functionality.
 * @namespace dev
 * @memberof verificatum
 */
verificatum.dev = (function () {

dnl Tuning routines.
M4_INCLUDE(verificatum/dev/tune/tune.js)dnl

/**
 * @description Testing and timing functions.
 * @namespace test
 * @memberof verificatum.dev
 */
var test = (function () {

    /**
     * @description Returns a hexadecimal representation of this input
     * array made for M4_WORDSIZE = 28. It separates words by spaces.
     * @param x Array of words.
     * @return Hexadecimal string representation of the array.
     * @function hex28
     * @memberof verificatum.arithm.li
     */
    var hex28 = function (x) {
        var h = hex(x);
        var offset = (7 - h.length % 7) % 7;

        var i = 0;
        var s = "";
        while (i < offset) {
            s += "0";
            i++;
        }

        var j = 0;
        while (j < h.length) {
            s += h[j];
            i++;
            if (j < h.length - 1 && i % 7 === 0) {
                s += " ";
            }
            j++;
        }
        return s;
    };

    /**
     * @description Converts an integer to its hexadecimal encoding.
     * @param x A 32-bit JavaScript "number" that is actually an integer.
     * @return Hexadecimal representation of this integer.
     * @function uint32ToHex
     * @memberof verificatum.util
     */
    var uint32ToHex = function (x) {
        var hexString = "";
        for (var i = 0; i < 4; i++) {
            hexString = hex(x & 0xFF) + hexString;
            x >>= 8;
        }
        return hexString;
    };

    /**
     * @description Converts a hexadecimal string into a binary string.
     * @param hexString Hexadecimal string.
     * @return Binary string.
     * @function hexToBin
     * @memberof verificatum.util
     */
    var hexToBin = function (hexString) {

        var hexToBinMap = {
            "0": "0000",
            "1": "0001",
            "2": "0010",
            "3": "0011",
            "4": "0100",
            "5": "0101",
            "6": "0110",
            "7": "0111",
            "8": "1000",
            "9": "1001",
            "A": "1010",
            "B": "1011",
            "C": "1100",
            "D": "1101",
            "E": "1110",
            "F": "1111"
        };

        var res = "";
        for (var i = 0; i < hexString.length; i++) {
            res += hexToBinMap[hexString[i]];
        }
        return res;
    };

    /**
     * @description Returns a list of the smallest available groups of
     * the implemented types of groups.
     * @function startSet
     * @memberof verificatum.dev.test
     */
    var getSmallPGroups = function () {
            var pGroups = [];

            if (typeof verificatum.arithm.ModPGroup !== "undefined") {
            var mpGroups = verificatum.arithm.ModPGroup.getPGroups();
            if (mpGroups.length > 0) {
                var ssmGroup = mpGroups[0];
                for (var j = 1; j < mpGroups.length; j++) {
                    if (mpGroups[j].getElementOrder().
                            cmp(ssmGroup.getElementOrder()) < 0) {
                        ssmGroup = mpGroups[j];
                    }
                }
                pGroups.push(ssmGroup);
            }
            }

            if (typeof verificatum.arithm.ECqPGroup !== "undefined") {
            var ecGroups = verificatum.arithm.ECqPGroup.getPGroups();
            if (ecGroups.length > 0) {
                var secGroup = ecGroups[0];
                for (var j = 1; j < ecGroups.length; j++) {
                    if (ecGroups[j].getElementOrder().
                            cmp(secGroup.getElementOrder()) < 0) {
                        secGroup = ecGroups[j];
                    }
                }
                pGroups.push(secGroup);
            }
            }

        if (pGroups.length === 0) {
            throw Error("No standard groups available for testing!");
        }
            return pGroups;
    };

    /**
     * @description Starts a test.
     * @param module Module name as string.
     * @function startSet
     * @memberof verificatum.dev.test
     */
    var startSet = function (module) {
        process.stdout.write("\nEntering " + module + "\n");
    };

    /**
     * @description Starts a test.
     * @param headers Names for tests.
     * @param seconds Running time of test.
     * @return End time of started test.
     * @function start
     * @memberof verificatum.dev.test
     */
    var start = function (headers, seconds) {
        var s = "";
        if (verificatum.util.ofType(headers, "string")) {
            s = "Test: " + headers + "...";
        } else {
            s = "Test: ";
            for (var i = 0; i < headers.length; i++) {
                if (i > 0) {
                    s += "\n      ";
                }
                s += headers[i];
            }
            s += "... ";
        }
        process.stdout.write(s);
        return verificatum.util.time() + seconds;
    };

    /**
     * @description Returns true if the test should continued to run
     * and false otherwise.
     * @param endEpoch End time of test.
     * @return True or false depending on if the test should be ended.
     * @function done
     * @memberof verificatum.dev.test
     */
    var done = function (endEpoch) {
        return verificatum.util.time() > endEpoch;
    };

    /**
     * @description Prints the end of a test.
     * @function end
     * @memberof verificatum.dev.test
     */
    var end = function () {
        process.stdout.write(" done.\n");
    };

    /**
     * @description Prints error.
     * @param msg Error message.
     * @function error
     * @memberof verificatum.dev.test
     */
    var error = function (msg) {
        process.stdout.write("\n\n" + msg + "\n\n");
        process.stdout.write("");
        process.exit(0);
    };

    /**
     * Runs tests of target if it is defined.
     *
     * @param target Potential target.
     * @param testTime Approximate time of each individual test in target.
     */
    var run = function (target, testTime) {
        if (typeof target !== "undefined") {
            target.run(testTime);
        }
    };

    return {
        "hex28": hex28,
        "uint32ToHex": uint32ToHex,
        "hexToBin": hexToBin,
        "getSmallPGroups": getSmallPGroups,
        "startSet": startSet,
        "start": start,
        "done": done,
        "end": end,
        "error": error,
        "run": run
    };
})();

    return {
        test: test,
M4_EXPOPT(verificatum/dev/tune/tune.js,tune)
    };
})();
