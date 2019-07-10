
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
// ################### Test SchnorrProof ################################
// ######################################################################

M4_NEEDS(verificatum/crypto/SchnorrProof.js)dnl

var test_SchnorrProof = (function () {
    var prefix = "verificatum.crypto.SchnorrProof";
    var arithm = verificatum.arithm;
    var crypto = verificatum.crypto;
    var util = verificatum.util;
    var test = verificatum.dev.test;

    var pGroups = test.getSmallPGroups();

    var prove_and_verify = function (testTime) {

        var end = test.start([prefix + " (prove and verify)"], testTime);

        while (!test.done(end)) {

            for (var i = 0; !test.done(end) && i < pGroups.length; i++) {

                var pGroup = pGroups[i];
                var eh;
                var sp;
                var witness;
                var instance;

                // eh(x) = g^x
                eh = new arithm.ExpHom(pGroup.pRing, pGroup.getg());
                sp = new crypto.SchnorrProof(eh);
                witness = eh.domain.randomElement(randomSource, statDist);
                instance = eh.eva(witness);

                test_SigmaProof.prove_and_verify(sp, instance, witness,
                                                 crypto.sha256);

                // pPGroup = pGroup x pGroup
                var pPGroup = new arithm.PPGroup([pGroup, pGroup]);

                // b = (c, d)
                var t = pGroup.pRing.randomElement(randomSource, statDist);
                var c = pGroup.getg().exp(t);

                var s = pGroup.pRing.randomElement(randomSource, statDist);
                var d = pGroup.getg().exp(s);

                var b = pPGroup.prod([c, d]);

                // eh(x) = (c^x, d^x)
                eh = new arithm.ExpHom(pGroup.pRing, b);
                sp = new crypto.SchnorrProof(eh);
                witness = eh.domain.randomElement(randomSource, statDist);
                instance = eh.eva(witness);

                test_SigmaProof.prove_and_verify(sp, instance, witness,
                                                 crypto.sha256);
            }
        }
        test.end();
    };

    var run = function (testTime) {
        prove_and_verify(testTime);
    };
    return {run: run};
})();
