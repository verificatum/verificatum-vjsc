
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
// ################### Test SigmaProofAnd ###############################
// ######################################################################

M4_NEEDS(verificatum/crypto/SigmaProofAnd.js)dnl

var test_SigmaProofAnd = (function () {
    var prefix = "verificatum.crypto.SigmaProofAnd";
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
                var sp;
                var witness;
                var instance;

                // eh(x) = g^x
                sps = [];
                witness = [];
                instance = [];
                for (var j = 0; j < 4; j++) {
                    eh = new arithm.ExpHom(pGroup.pRing, pGroup.getg());
                    sps[j] = new crypto.SchnorrProof(eh);
                    witness[j] =
                        eh.domain.randomElement(randomSource, statDist);
                    instance[j] = eh.eva(witness[j]);
                }
                var sp = new crypto.SigmaProofAnd(sps);

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
