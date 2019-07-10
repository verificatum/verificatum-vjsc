
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

// ##################################################################
// ############### Test ByteTree.js #################################
// ##################################################################

var test_ByteTree = (function () {

    var prefix = "verificatum.eio.ByteTree ";

    var valid = function (testTime) {

        var endEpoch = test.start([prefix + "(valid)"], testTime);

        var simpleLen = 20;
        var len = 1;
        while (!test.done(endEpoch)) {

            var data = verificatum.util.randomArray(len, 8, randomSource);

            // Create leaf from raw data.
            var btc = new eio.ByteTree(data);
            if (!verificatum.util.equalsArray(data, btc.value)
                || btc.type !== eio.ByteTree.LEAF) {
                throw Error("Failed to create leaf from raw data!")
            }

            // Turn it into a byte array, recover it, turn it into a byte
            // array and compare.
            var bt1 = new eio.ByteTree(data);
            var ba1 = bt1.toByteArray();
            var bt2 = eio.ByteTree.readByteTreeFromByteArray(ba1);
            var ba2 = bt2.toByteArray();
            if (!verificatum.util.equalsArray(ba1, ba2)) {
                throw Error("Failed to store and recover leaf to/from " +
                            "byte array!")
            }

            // Turn it into a hex string, recover it, turn it into a hex
            // string and compare.
            var hex1 = bt1.toHexString();
            var hexbt2 = new eio.ByteTree(hex1);
            var hex2 = hexbt2.toHexString();
            if (hex1 !== hex2) {
                throw Error("Failed to store and recover leaf to/from hex " +
                            "string!")
            }

            // Create complex tree.
            var bts = [];
            for (var i = 1; i < 20; i++) {
                var t = verificatum.util.randomArray(i * len, 8, randomSource);
                bts.push(new eio.ByteTree(t));
            }

            var c1 = new eio.ByteTree(bts.slice(0, 3));
            var c2 = new eio.ByteTree(bts.slice(3, 5));
            var c3 = new eio.ByteTree(bts.slice(5, 8));
            var c4 = new eio.ByteTree([c1, c2]);
            var c5 = new eio.ByteTree([c3, bts[15]]);

            // Turn it into a hex string, recover it, turn it into a
            // hex string and compare.
            var cbt1 = new eio.ByteTree([c1, c2, c3, c4, c5]);
            var hexcbt1 = cbt1.toHexString();
            var cbt2 = new eio.ByteTree(hexcbt1);
            var hexcbt2 = cbt2.toHexString();

            if (hexcbt1 !== hexcbt2) {
                throw Error("Failed to store and recover byte tree to/from " +
                            "hex string!")
            }

            var si = cbt1.size();
            var le = cbt1.toByteArray().length;
            if (si != le) {
                throw Error("Computation of size is wrong! (");
            }

            len = len % (simpleLen - 1) + 1;
        };
        test.end();
    };

    var invalid = function (testTime) {

        var endEpoch =
            test.start([prefix + "(invalid)"], testTime);
        var len = 10;
        var failed;
        var iba;
        var ibt;

        var data = verificatum.util.randomArray(len, 8, randomSource);
        var bt = new eio.ByteTree(data);

        iba = bt.toByteArray();
        iba[0] = 2;
        failed = true;
        try {
            ibt = eio.ByteTree.readByteTreeFromByteArray(iba);
        } catch (err) {
            failed = false;
        }
        if (failed) {
            throw Error("Failed to complain about invalid type!");
        }

        iba = bt.toByteArray();
        iba[1] |= 0x80
        failed = true;
        try {
            ibt = eio.ByteTree.readByteTreeFromByteArray(iba);
        } catch (err) {
            failed = false;
        }
        if (failed) {
            throw Error("Failed to complain about negative length!");
        }

        iba = bt.toByteArray();
        iba[4] += 1
        failed = true;
        try {
            ibt = eio.ByteTree.readByteTreeFromByteArray(iba);
        } catch (err) {
            failed = false;
        }
        if (failed) {
            throw Error("Failed to complain about missing bytes!");
        }

        test.end();
    };

    var run = function (testTime) {
        valid(testTime);
        invalid(testTime);
    };
    return {run: run};
})();
