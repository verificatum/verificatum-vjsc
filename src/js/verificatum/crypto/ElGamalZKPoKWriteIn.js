
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
// ################### ElGamalZKPoKWriteIn ##############################
// ######################################################################

M4_NEEDS(verificatum/crypto/ElGamal.js)dnl
M4_NEEDS(verificatum/crypto/ZKPoKWriteInAdapter.js)dnl

/**
 * @description Generalized Naor-Yung cryptosystem, i.e., a
 * generalized El Gamal with zero-knowledge proof of knowledge of the
 * plaintext without any restrictions on the plaintext.
 * @param standard Determines if the standard or variant El Gamal
 * cryptosystem is used.
 * @param pGroup Group G over which the cryptosystem is defined.
 * @param hashfunction Hash function used to implement the Fiat-Shamir
 * heuristic in ZKPoKs.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @class
 * @memberof verificatum.crypto
 */
function ElGamalZKPoKWriteIn(standard, pGroup, hashfunction, randomSource,
                             statDist) {
    ElGamalZKPoK.call(this, standard, pGroup, new ZKPoKWriteInAdapter(),
                      hashfunction, randomSource, statDist);
};
ElGamalZKPoKWriteIn.prototype = Object.create(ElGamalZKPoK.prototype);
ElGamalZKPoKWriteIn.prototype.constructor = ElGamalZKPoKWriteIn;


/**
 * @description Estimates the running time of encryption in
 * milliseconds.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroup Group over which the cryptosystem is defined.
 * @param hashfunction Hash function used for Fiat-Shamir heuristic.
 * @param width Width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Estimated running time of encryption in milliseconds.
 */
ElGamalZKPoKWriteIn.benchEncryptPGroupWidth = function (standard,
                                                        pGroup,
                                                        hashfunction,
                                                        width,
                                                        minSamples,
                                                        randomSource,
                                                        statDist) {
    var eg = new ElGamalZKPoKWriteIn(standard, pGroup, hashfunction,
                                     randomSource, statDist);

    var keys = eg.gen();
    var wpk = eg.widePublicKey(keys[0], width);
    var m = wpk.pGroup.project(1).getg();
    var label = randomSource.getBytes(10);

    var start = util.time_ms();
    var j = 0;
    while (j < minSamples) {
        eg.encrypt(label, wpk, m);
        j++;
    }
    return (util.time_ms() - start) / j;
};

/**
 * @description Estimates the running time of encryption in
 * milliseconds for various widths.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroup Group over which the cryptosystem is defined.
 * @param hashfunction Hash function used for Fiat-Shamir heuristic.
 * @param maxWidth Maximal width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Array of estimated running times of encryption in
 * milliseconds.
 */
ElGamalZKPoKWriteIn.benchEncryptPGroup = function (standard,
                                                   pGroup,
                                                   hashfunction,
                                                   maxWidth,
                                                   minSamples,
                                                   randomSource,
                                                   statDist) {
    var results = [];
    for (var i = 1; i <= maxWidth; i++) {
        var t = ElGamalZKPoKWriteIn.benchEncryptPGroupWidth(standard,
                                                            pGroup,
                                                            hashfunction,
                                                            i,
                                                            minSamples,
                                                            randomSource,
                                                            statDist);
        results.push(t);
    }
    return results;
};

/**
 * @description Estimates the running time of encryption in
 * milliseconds for various groups and widths.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroups Groups over which the cryptosystem is defined.
 * @param hashfunction Hash function used for Fiat-Shamir heuristic.
 * @param maxWidth Maximal width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Array or arrays of estimated running time of encryption in
 * milliseconds.
 */
ElGamalZKPoKWriteIn.benchEncrypt = function (standard, pGroups,
                                             hashfunction, maxWidth,
                                             minSamples, randomSource,
                                             statDist) {
    var results = [];
    for (var i = 0; i < pGroups.length; i++) {
        results[i] = ElGamalZKPoKWriteIn.benchEncryptPGroup(standard,
                                                            pGroups[i],
                                                            hashfunction,
                                                            maxWidth,
                                                            minSamples,
                                                            randomSource,
                                                            statDist);
    }
    return results;
};
