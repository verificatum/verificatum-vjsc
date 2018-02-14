
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
// ################### Test arithm.js ###################################
// ######################################################################

M4_INCLUDE(verificatum/verificatum.js)dnl
M4_INCLUDE(verificatum/dev/dev.js)dnl

var test_arithm = (function () {
    var test = verificatum.dev.test;
    var arithm = verificatum.arithm;
    var randomSource = new verificatum.crypto.RandomDevice();
    var statDist = 50;

dnl Lists of primes.
M4_INCLUDE(verificatum/arithm/test_primes.js)dnl

dnl Test li.
M4_INCLUDEOPT(verificatum/arithm/test_li.js)dnl

dnl Test LargeInteger.
M4_INCLUDEOPT(verificatum/arithm/test_LargeInteger.js)dnl

dnl Test ModPowProd.
M4_INCLUDEOPT(verificatum/arithm/test_ModPowProd.js)dnl

dnl Test FixModPow.
M4_INCLUDEOPT(verificatum/arithm/test_FixModPow.js)dnl

dnl Generic tests for subclasses of PRing.
M4_INCLUDEOPT(verificatum/arithm/test_PRing.js)dnl

dnl Tests for PField.
M4_INCLUDEOPT(verificatum/arithm/test_PField.js)dnl

dnl Tests for PPRing.
M4_INCLUDEOPT(verificatum/arithm/test_PPRing.js)dnl

dnl Generic tests for PGroup.
M4_INCLUDEOPT(verificatum/arithm/test_PGroup.js)dnl

dnl Tests for ModPGroup.
M4_INCLUDEOPT(verificatum/arithm/test_ModPGroup.js)dnl

dnl Tests for ECqPGroup.
M4_INCLUDEOPT(verificatum/arithm/test_ECqPGroup.js)dnl

dnl Tests for PPGroup.
M4_INCLUDEOPT(verificatum/arithm/test_PPGroup.js)dnl

    var run = function (testTime) {
        test.startSet("verificatum/arithm/");

// This is mainly used for debugging, and only makes sense to run
// during development. It does exhaustive testing for every input in
// some functions, which takes a lot of time.
M4_RUNOPT(verificatum/arithm/test_li.js,test_li,testTime)

M4_RUNOPT(verificatum/arithm/test_LargeInteger.js,test_LargeInteger,testTime)
M4_RUNOPT(verificatum/arithm/test_ModPowProd.js,test_ModPowProd,testTime)
M4_RUNOPT(verificatum/arithm/test_FixModPow.js,test_FixModPow,testTime)
M4_RUNOPT(verificatum/arithm/test_PField.js,test_PField,testTime)
M4_RUNOPT(verificatum/arithm/test_PPRing.js,test_PPRing,testTime)
M4_RUNOPT(verificatum/arithm/test_ModPGroup.js,test_ModPGroup,testTime)
M4_RUNOPT(verificatum/arithm/test_ECqPGroup.js,test_ECqPGroup,testTime)
M4_RUNOPT(verificatum/arithm/test_PPGroup.js,test_PPGroup,testTime)
    };

    return {
M4_EXPOPT(verificatum/arithm/test_li.js,test_li.js,test_li)
M4_EXPOPT(verificatum/arithm/test_LargeInteger.js,test_LargeInteger,test_LargeInteger)
M4_EXPOPT(verificatum/arithm/test_ModPowProd.js,test_ModPowProd)
M4_EXPOPT(verificatum/arithm/test_FixModPow.js,test_FixModPow)
M4_EXPOPT(verificatum/arithm/test_PField.js,test_PField)
M4_EXPOPT(verificatum/arithm/test_PPRing.js,test_PPRing)
M4_EXPOPT(verificatum/arithm/test_ModPGroup.js,test_ModPGroup)
M4_EXPOPT(verificatum/arithm/test_ECqPGroup.js,test_ECqPGroup)
M4_EXPOPT(verificatum/arithm/test_PPGroup.js,test_PPGroup)
        run: run
    };
})();
