
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
