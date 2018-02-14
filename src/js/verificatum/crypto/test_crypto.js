
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
// ################### Test crypto.js ###################################
// ######################################################################

M4_INCLUDE(verificatum/verificatum.js)dnl
M4_INCLUDE(verificatum/dev/dev.js)dnl

var test_crypto = (function () {
    var test = verificatum.dev.test;
    var crypto = verificatum.crypto;
    var randomSource = new verificatum.crypto.RandomDevice();
    var statDist = 50;

dnl Tests SHA-2.
M4_INCLUDE(verificatum/crypto/test_sha2.js)dnl

dnl Tests ElGamal.
M4_INCLUDEOPT(verificatum/crypto/test_ElGamal.js)dnl

dnl Tests Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/test_SigmaProof.js)dnl

dnl Tests conjunction of Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/test_SigmaProofAnd.js)dnl

dnl Tests disjunction of Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/test_SigmaProofOr.js)dnl

dnl Tests Schnorr proofs.
M4_INCLUDEOPT(verificatum/crypto/test_SchnorrProof.js)dnl

dnl Tests ElGamal with zero-knowledge proofs of knowledge.
M4_INCLUDEOPT(verificatum/crypto/test_ElGamalZKPoKWriteIn.js)dnl

    var run = function (testTime) {
        test.startSet("verificatum/crypto/");
        verificatum.dev.test.run(test_sha2, testTime);
M4_RUNOPT(verificatum/crypto/test_ElGamal.js,test_ElGamal,testTime)
M4_RUNOPT(verificatum/crypto/test_SchnorrProof.js,test_SchnorrProof,testTime)
M4_RUNOPT(verificatum/crypto/test_SigmaProofAnd.js,test_SigmaProofAnd,testTime)
M4_RUNOPT(verificatum/crypto/test_SigmaProofOr.js,test_SigmaProofOr,testTime)
M4_RUNOPT(verificatum/crypto/test_ElGamalZKPoKWriteIn.js,test_ElGamalZKPoKWriteIn,testTime)
    };
    return {
        test_sha2: test_sha2,
M4_EXPOPT(verificatum/crypto/test_ElGamal.js,test_ElGamal)
M4_EXPOPT(verificatum/crypto/test_SchnorrProof.js,test_SchnorrProof)
M4_EXPOPT(verificatum/crypto/test_SigmaProofAnd.js,test_SigmaProofAnd)
M4_EXPOPT(verificatum/crypto/test_SigmaProofOr.js,test_SigmaProofOr)
M4_EXPOPT(verificatum/crypto/test_ElGamalZKPoKWriteIn.js,test_ElGamalZKPoKWriteIn)
        run: run
    };
})();
