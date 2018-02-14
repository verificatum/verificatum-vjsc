
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
// ################### Test SigmaProof ##################################
// ######################################################################

M4_NEEDS(verificatum/crypto/SigmaProof.js)dnl

var test_SigmaProof = (function () {
    var util = verificatum.util;
    var test = verificatum.dev.test;

    var prove_and_verify = function (sp, instance, witness, hashfunction) {
        var e;

        // Verify that honestly computed proofs validate and that
        // slightly modified proofs do not.
        for (var j = 0; j < 5; j++) {
            label = randomSource.getBytes(j);

            var proof = sp.prove(label, instance, witness,
                                 hashfunction, randomSource, 50);
            if (!sp.verify(label, instance, hashfunction, proof)) {
                e = "Valid proof was rejected!"
                    + "\nlabel = " + util.byteArrayToHex(label)
                    + "\nwitness = " + witness.toString()
                    + "\ninstance = " + instance.toString()
                    + "\nproof = " + util.byteArrayToHex(proof);
                test.error(e);
                return false;
            }

            var rand = randomSource.getBytes(proof.length);
            var epsilon = randomSource.getBytes(proof.length);
            for (var l = 0; l < proof.length; l++) {

                if (rand[l] == 0) {
                    
                    // Introduce random single-bit errors in each byte.
                    var modproof = proof.slice();
                    modproof[l] ^= (1 << (epsilon[l] % 8));

                    if (sp.verify(label, instance, hashfunction, modproof)) {
                        e = "Invalid proof was accepted!"
                            + "\nlabel = " + util.byteArrayToHex(label)
                            + "\nwitness = " + witness.toString()
                            + "\ninstance = " + instance.toString()
                            + "\nproof = " + util.byteArrayToHex(proof);
                            + "\nmodproof = " + util.byteArrayToHex(modproof);
                        test.error(e);
                        return false;
                    }
                }
            }
        }
    }
    return {
        prove_and_verify: prove_and_verify
    };
})();
