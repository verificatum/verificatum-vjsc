
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

var benchworker = function () {

var randomSource = null;
var statDist = 50;
var maxWidth = 4;

var crypto;
var benchmark;
var arithm;
var hashfunction;

var getPGroups = function (groupNames) {
    var pGroups = [];
    for (var i = 0; i < groupNames.length; i++) {
        pGroups[i] = arithm.PGroup.getPGroup(groupNames[i]);
    }
    return pGroups;
};

var getIndices = function (maxWidth) {
    var indices = [];
    for (var i = 0; i < maxWidth; i++) {
        indices[i] = i + 1;
    }
    return indices;
};
    
onmessage = function(e) {

    var command = e.data[0];

    if (command == "importScripts") {

        importScripts(e.data[1] + '/min-vjsc-M4_VJSC_VERSION.js');
        crypto = verificatum.crypto;
        benchmark = verificatum.benchmark;
        arithm = verificatum.arithm;
        hashfunction = crypto.sha256;
        randomSource = new crypto.SHA256PRG();
        randomSource.setSeed(e.data[2]);

        postMessage(["importScripts"]);

    } else {
        
        var minSamples = e.data[1];
        var params = e.data.slice(1);

        if (command == "ModPGroup.exp") {
            var pGroupNames = arithm.ModPGroup.getPGroupNames();
            var pGroups = arithm.ModPGroup.getPGroups();
            var results = arithm.PGroup.benchExp(pGroups,
                                                 minSamples,
                                                 randomSource);
            postMessage(["ModPGroup.exp",
                         benchmark.grpTable(pGroupNames, results)]);

        } else if (command == "ECqPGroup.exp") {
            var pGroupNames = arithm.ECqPGroup.getPGroupNames();
            var pGroups = arithm.ECqPGroup.getPGroups();
            var results = arithm.PGroup.benchExp(pGroups,
                                                 minSamples,
                                                 randomSource);
            postMessage(["ECqPGroup.exp",
                         benchmark.grpTable(pGroupNames, results)]);

        } else if (command == "FixModPow.exp") {
            var pGroupNames = ["modp3072", "modp4096", "modp6144"];
            var exps = [0, 1, 2, 4, 8, 16, 32];
            var results = arithm.PGroup.benchFixExp(getPGroups(pGroupNames),
                                                    minSamples,
                                                    exps,
                                                    randomSource);
            var tableString =
                benchmark.grpIntTable("Exps", exps, pGroupNames, results);
            postMessage(["FixModPow.exp", tableString]);

        } else if (command == "ElGamal") {        
            var indices = getIndices(maxWidth);
            var pGroupNames = ["modp3072", "modp4096", "modp6144",
                               "P-256", "secp384r1", "P-521"];
            var results = crypto.ElGamal.benchEncrypt(true,
                                                      getPGroups(pGroupNames),
                                                      maxWidth,
                                                      minSamples,
                                                      randomSource,
                                                      statDist);
            var tableString = benchmark.grpIntTable("Width",
                                                    indices,
                                                    pGroupNames,
                                                    results);
            postMessage(["ElGamal", tableString]);

        } else if (command == "ElGamalZKPoKWriteIn") {
        
            var indices = getIndices(maxWidth);
            var pGroupNames = ["modp3072", "modp4096", "modp6144",
                               "P-256", "secp384r1", "P-521"];
            var results =
                crypto.ElGamalZKPoKWriteIn.benchEncrypt(true,
                                                        getPGroups(pGroupNames),
                                                        hashfunction,
                                                        maxWidth,
                                                        minSamples,
                                                        randomSource,
                                                        statDist);

            var tableString =
                benchmark.grpIntTable("Width", indices, pGroupNames, results);
            postMessage(["ElGamalZKPoKWriteIn", tableString]);

        } else if (command == "NaorYung") {
        
            var indices = getIndices(maxWidth);
            var pGroupNames = ["modp3072", "modp4096", "modp6144",
                               "P-256", "secp384r1", "P-521"];
            var results =
                crypto.ElGamalZKPoKWriteIn.benchEncrypt(false,
                                                        getPGroups(pGroupNames),
                                                        hashfunction,
                                                        maxWidth,
                                                        minSamples,
                                                        randomSource,
                                                        statDist);
            var tableString =
                benchmark.grpIntTable("Width", indices, pGroupNames, results);
            postMessage(["NaorYung", tableString]);
        } else {
            throw Error("Unknown command! (" + command + ")");
        }
    }
};

}

// This is in case of normal worker start
if (window != self) {
    bench_vjsc();
}
