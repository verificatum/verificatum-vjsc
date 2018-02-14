
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
// ################### ZKPoK ############################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Labeled non-interactive zero-knowledge proof of
 * knowledge in the random oracle model.
 * @class
 * @abstract
 * @memberof verificatum.crypto
 */
function ZKPoK() {
};
ZKPoK.prototype = Object.create(Object.prototype);
ZKPoK.prototype.constructor = ZKPoK;

/* istanbul ignore next */
/**
 * @description Number of bytes or randomness needed to compute a proof.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Number of bytes needed to compute a proof.
 * @method
 */
ZKPoK.prototype.randomnessByteLength = function (statDist) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Performs pre-computation.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Pre-computed values.
 * @method
 */
ZKPoK.prototype.precompute = function (randomSource, statDist) {
    throw Error("Abstract method!");
};

/**
 * @description Indicates if pre-computation requires the
 * instance. This allows choosing the right pre-computation function.
 * @return True or false depending on if pre-computation requires the
 * instance or not.
 * @method
 */
ZKPoK.prototype.precomputeRequiresInstance = function() {
    return false;
};

/* istanbul ignore next */
/**
 * @description Performs pre-computation when the instance is needed.
 * @param instance Instance.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Pre-computed values.
 * @method
 */
ZKPoK.prototype.precomputeWithInstance = function (instance,
                                                   randomSource,
                                                   statDist) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Completes a proof using pre-computed values.
 * @param precomputed Pre-computed values.
 * @param label Label as an array of bytes or byte tree.
 * @param instance Instance.
 * @param witness Witness of instance belonging to the right language.
 * @param hashfunction Hash function used to implement the random
 * oracle.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Proof in the form of a byte array.
 * @method
 */
ZKPoK.prototype.completeProof = function (precomputed,
                                          label, instance, witness,
                                          hashfunction,
                                          randomSource, statDist) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Verifies a proof. This is meant to be used for
 * debugging, so the granularity in error handling is rudimentary.
 * @param label Label as an array of bytes or byte tree.
 * @param instance Instance.
 * @param hashfunction Hash function used to implement the random
 * oracle.
 * @param proof Candidate proof in the form of a byte array.
 * @return True or false depending on if the candidate proof is valid
 * or not.
 * @method
 */
ZKPoK.prototype.verify = function (label, instance, hashfunction, proof) {
    throw Error("Abstract method!");
};

/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */

/**
 * @description Computes a proof.
 * @param label Label as an array of bytes or byte tree.
 * @param instance Instance.
 * @param witness Witness of instance belonging to the right language.
 * @param hashfunction Hash function used to implement the random
 * oracle.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Proof in the form of a byte array.
 * @method
 */
ZKPoK.prototype.prove = function (label, instance, witness,
                                  hashfunction, randomSource, statDist) {
    var precomputed;
    if (this.precomputeRequiresInstance()) {
        precomputed =
            this.precomputeWithInstance(instance, randomSource, statDist);
    } else {
        precomputed = this.precompute(randomSource, statDist);
    }
    return this.completeProof(precomputed, label, instance, witness,
                              hashfunction, randomSource, statDist);
};
