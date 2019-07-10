
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
