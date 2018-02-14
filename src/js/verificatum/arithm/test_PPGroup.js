
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
// ################### Test PPGroup.js ##################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PPGroup.js)dnl
M4_NEEDS(verificatum/arithm/test_PGroup.js)dnl

var test_PPGroup = (function () {
    var prefix = "verificatum.arithm.PPGroup";
    var test = verificatum.dev.test;

    var getPPGroups = function () {
        var tmp;

        var smallPGroups = test.getSmallPGroups();

        // Generate some PPGroups of different types.
        var pPGroups = [];
        for (var j = 0; j < smallPGroups.length; j++) {
            var flatPPGroup =
                new verificatum.arithm.PPGroup([smallPGroups[j],
                                                smallPGroups[j],
                                                smallPGroups[j]]);
            pPGroups.push(flatPPGroup);

            tmp = new verificatum.arithm.PPGroup([smallPGroups[j],
                                                  smallPGroups[j]]);
            tmp = new verificatum.arithm.PPGroup([smallPGroups[j], tmp]);
            var compPPGroup = new verificatum.arithm.PPGroup([tmp,
                                                              smallPGroups[j],
                                                              smallPGroups[j]]);
            pPGroups.push(compPPGroup);
        }
        return pPGroups;
    };

    var pPGroups = getPPGroups();

    var identities = function (testTime) {
        test_PGroup.identities(prefix, pPGroups, testTime);
    };
    var multiplication_commutativity = function (testTime) {
        test_PGroup.multiplication_commutativity(prefix, pPGroups, testTime);
    };
    var multiplication_associativity = function (testTime) {
        test_PGroup.multiplication_associativity(prefix, pPGroups, testTime);
    };
    var exp = function (testTime) {
        test_PGroup.exp(prefix, pPGroups, testTime);
    };
    var inversion = function (testTime) {
        test_PGroup.inversion(prefix, pPGroups, testTime);
    };
    var conversion = function (testTime) {
        test_PGroup.conversion(prefix, pPGroups, testTime);
    };
    var encoding = function (testTime) {
        test_PGroup.encoding(prefix, pPGroups, testTime);
    };
    var projprodgroup = function (testTime) {
        var end = test.start([prefix + " (proj and prod group)"], testTime);

        var i = 0;
        while (!test.done(end) && i < pPGroups.length) {

            var pPGroup = pPGroups[i];

            var newPGroups = [];
            for (var j = 0; j < pPGroup.getWidth(); j++) {
                newPGroups[j] = pPGroup.project(j);
            }
            var newPPGroup = new verificatum.arithm.PPGroup(newPGroups);

            if (!newPPGroup.equals(pPGroup)) {
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
        while (!test.done(end) && i < pPGroups.length) {

            var x = pPGroups[i].randomElement(randomSource, statDist);
            var xs = [];
            for (var j = 0; j < x.pGroup.getWidth(); j++) {
                xs[j] = x.project(j);
            }
            var y = pPGroups[i].prod(xs);

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
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        exp(testTime);
        inversion(testTime);
        conversion(testTime);
        encoding(testTime);
        projprodgroup(testTime);
        projprodel(testTime);
    };
    return {run: run};
})();
