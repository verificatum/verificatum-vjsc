
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
