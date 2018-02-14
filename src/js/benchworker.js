
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
