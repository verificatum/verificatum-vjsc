
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
// ################### Test PPRing.js ###################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PPRing.js)dnl
M4_NEEDS(verificatum/arithm/test_PRing.js)dnl

var test_PPRing = (function () {

dnl Lists of primes.
M4_INCLUDE(verificatum/arithm/test_primes.js)dnl

    var getPPRings = function () {
        var tmp;

        var smallPField =
            new verificatum.arithm.PField(small_primes[0]);
        var largePField =
            new verificatum.arithm.PField(safe_primes[0]);

        var smallFlatPPRing =
            new verificatum.arithm.PPRing([smallPField, smallPField,
                                           smallPField]);
        var largeFlatPPRing =
            new verificatum.arithm.PPRing([largePField, largePField,
                                           largePField]);

        tmp = new verificatum.arithm.PPRing([smallPField, smallPField]);
        tmp = new verificatum.arithm.PPRing([smallPField, tmp]);
        var smallCompPPRing =
            new verificatum.arithm.PPRing([tmp, smallPField, smallPField]);

        tmp = new verificatum.arithm.PPRing([largePField, largePField]);
        tmp = new verificatum.arithm.PPRing([largePField, tmp]);
        var largeCompPPRing =
            new verificatum.arithm.PPRing([tmp, largePField, largePField]);

        return [smallFlatPPRing, smallCompPPRing, largeFlatPPRing,
                largeCompPPRing]
    };
    var pPRings = getPPRings();
    var prefix = "verificatum.arithm.PPRing";

    var identities = function (testTime) {
        test_PRing.identities(prefix, pPRings, testTime);
    };
    var addition_commutativity = function (testTime) {
        test_PRing.addition_commutativity(prefix, pPRings, testTime);
    };
    var addition_associativity = function (testTime) {
        test_PRing.addition_associativity(prefix, pPRings, testTime);
    };
    var multiplication_commutativity = function (testTime) {
        test_PRing.multiplication_commutativity(prefix, pPRings, testTime);
    };
    var multiplication_associativity = function (testTime) {
        test_PRing.multiplication_associativity(prefix, pPRings, testTime);
    };
    var distributivity = function (testTime) {
        test_PRing.distributivity(prefix, pPRings, testTime);
    };
    var subtraction = function (testTime) {
        test_PRing.subtraction(prefix, pPRings, testTime);
    };
    var inversion = function (testTime) {
        test_PRing.inversion(prefix, pPRings, testTime);
    };
    var conversion = function (testTime) {
        test_PRing.conversion(prefix, pPRings, testTime);
    };
    var projprodring = function (testTime) {
        var end = test.start([prefix + " (proj and prod group)"], testTime);

        var i = 0;
        while (!test.done(end) && i < pPRings.length) {

            var pPRing = pPRings[i];

            var newPRings = [];
            for (var j = 0; j < pPRing.getWidth(); j++) {
                newPRings[j] = pPRing.project(j);
            }
            var newPPRing = new verificatum.arithm.PPRing(newPRings);

            if (!newPPRing.equals(pPRing)) {                
                var e = "Projecting to parts and taking product failed!";
                test.error(e);
            }
            i++;
        }
        test.end();
    };
    var projprodel = function (testTime) {
        var end = test.start([prefix + " (proj and prod element)"], testTime);

        var i = 0;
        while (!test.done(end) && i < pPRings.length) {

            var x = pPRings[i].randomElement(randomSource, statDist);
            var xs = [];
            for (var j = 0; j < x.pRing.getWidth(); j++) {
                xs[j] = x.project(j);
            }
            var y = pPRings[i].prod(xs);

            if (!y.equals(x)) {
                var e = "Projecting to parts and taking product failed!";
                test.error(e);
            }
            i++;
        }
        test.end();    
    };

    var run = function (testTime) {
        identities(testTime);
        addition_commutativity(testTime);
        addition_associativity(testTime);
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        distributivity(testTime);
        subtraction(testTime);
        conversion(testTime);
        projprodring(testTime);
        projprodel(testTime);
    };
    return {run: run};
})();
