
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
