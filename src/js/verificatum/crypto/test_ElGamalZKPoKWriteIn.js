
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
// ################### Test ElGamalZKPoKWriteIn.js ######################
// ######################################################################

M4_NEEDS(verificatum/crypto/ElGamalZKPoKWriteIn.js)dnl

var test_ElGamalZKPoKWriteIn = (function () {
    var prefix = "verificatum.crypto.ElGamalZKPoKWriteIn";
    var arithm = verificatum.arithm;
    var crypto = verificatum.crypto;
    var test = verificatum.dev.test;

    var gen_encrypt_decrypt = function (testTime) {
        var e;
        var end = test.start([prefix + " (encrypt and decrypt)"], testTime);

        var pGroups = test.getSmallPGroups();

        var maxKeyWidth = 3;
        var maxWidth = 4;

        var i = 1;
        while (!test.done(end)) {

            var keyWidth = 1;
            while (keyWidth <= maxKeyWidth) {

                var yGroup = arithm.PGroup.getWideGroup(pGroups[i], keyWidth);
                
                for (var l = 0; l < 2; l++) {

                    var ny = new crypto.ElGamalZKPoKWriteIn(l === 0,
                                                            yGroup,
                                                            crypto.sha256,
                                                            randomSource,
                                                            statDist);
                    var label = randomSource.getBytes(10)
                    var keys = ny.gen(yGroup);

                    var pk = keys[0];
                    var sk = keys[1];

                    var width = 1;
                    while (width <= maxWidth) {

                        var wpk = ny.widePublicKey(pk, width);
                        var wsk = ny.widePrivateKey(sk, width);

                        var m =
                            wpk.project(1).pGroup.randomElement(randomSource,
                                                                10);

                        var c = ny.encrypt(label, wpk, m);
                        var a = ny.decrypt(label, wpk, wsk, c);

                        if (a == null || !a.equals(m)) {
                            var e = "NaorYung failed!"
                                + "\npk = " + pk.toString()
                                + "\nsk = " + sk.toString()
                                + "\nkeyWidth = " + keyWidth
                                + "\nwpk = " + wpk.toString()
                                + "\nwsk = " + wsk.toString()
                                + "\nwidth = " + width
                                + "\nm = " + m.toString()
                                + "\nc = " + c.toString();
                            if (a != null) {
                                e += "\na = " + a.toString();
                            }
                            test.error(e);
                        }
                        width++;
                    }
                }
                keyWidth++;
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };


    var run = function (testTime) {
        gen_encrypt_decrypt(testTime);
    };
    return {run: run};
})();
