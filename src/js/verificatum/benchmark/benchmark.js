
// Copyright 2008-2019 Douglas Wikstrom
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
// ################### Javascript Verificatum Client ####################
// ######################################################################
//
// Javascript Verificatum client library for implementing clients. We
// refer the reader to the accompanying README file for more
// information.

/**
 * @description Provide html formatting functions for benchmarks.
 * @namespace benchmark
 */
var benchmark = (function () {

/**
 * @description Returns a string representation of the today's date.
 * @return Today's date.
 * @function today
 * @memberof verificatum.benchmark
 */
var today = function () {
    var today = new Date();
    var dd = today.getDate();
    var mm = today.getMonth() + 1;
    var yyyy = today.getFullYear();

    if (dd < 10) {
        dd = "0" + dd;
    }

    if (mm < 10) {
        mm = "0" + mm;
    }

    return yyyy + "-" + mm + "-" + dd;
};

/* jshint -W117 */ /* Ignore undefinitions. */
/* eslint-disable spaced-comment */
/* eslint-disable no-implicit-coercion */
/* eslint-disable no-undef */
/* eslint-disable no-extra-boolean-cast */
/**
 * @description Makes a decent attempt to identify the browser
 * used. This is a horrible hack that probes properties that are not
 * stable with versions. Do not use this for anything important.
 * @return Browser string.
 * @function browser
 * @memberof verificatum.benchmark
 */
var browser = function () {
        
    if (!!window.opr && !!opr.addons || !!window.opera ||
        navigator.userAgent.indexOf(" OPR/") >= 0) {
        return "Opera 8.0+";
    } else if (typeof InstallTrigger !== "undefined") {
        return "Firefox 1.0+";
    } else if (Object.prototype.toString.call(window.HTMLElement).
               indexOf("Constructor") > 0) {
        return "Safari 3+";
    } else if (/*@cc_on!@*/false || !!document.documentMode) {
        return "Internet Explorer 6-11";
    } else if (!!window.StyleMedia) {
        return "Edge 20+";
    } else if (!!window.chrome && !!window.chrome.webstore) {
        return "Chrome 1+";
    } else {
        return "Unable to detect";
    }
};
/* jshint +W117 */ /* Stop ignoring undefinitions. */
/* eslint-enable spaced-comment */
/* eslint-enable no-implicit-coercion */
/* eslint-enable no-undef */
/* eslint-enable no-extra-boolean-cast */
    
/**
 * @description Formats a list of benchmark results.
 * @param pGroupNames List of names of groups.
 * @param restuls List of timings.
 * @return HTML code for output.
 * @function grpTable
 * @memberof verificatum.benchmark
 */
var grpTable = function (pGroupNames, results) {
    var s = "<table>\n";
    s += "<tr>" +
        "<th>Group</th>" +
        "<th>ms / exp</th>" +
        "</tr>\n";
    for (var i = 0; i < results.length; i++) {
        s += "<tr>";
        s += "<td>" + pGroupNames[i] + "</td>";
        s += "<td style=\"text-align:right\">" + results[i].toFixed(1) + "</td>";
        s += "</tr>\n";
    }
    s += "</table>";
    return s;
};

var grpIntHeader = function (header, indices) {
    var s = "<tr>\n<th>Group \\ " + header + "</th>\n";
    for (var i = 0; i < indices.length; i++) {
        s += "<th>" + indices[i] + "</th>\n";
    }
    return s + "</tr><h>\n";
};

var grpIntRow = function (pGroupName, results) {
    var s = "<tr>\n<td>" + pGroupName + "</td>\n";
    for (var i = 0; i < results.length; i++) {
        s += "<td style=\"text-align:right\">" + results[i].toFixed(1) + "</td>\n";
    }
    return s + "</tr>\n";
};

var grpIntTable = function (header, indices, pGroupNames, results) {
    var s = "<table>\n";
    s += grpIntHeader(header, indices);
    for (var i = 0; i < results.length; i++) {
        s += grpIntRow(pGroupNames[i], results[i]);
    }
    s += "</table>";
    return s;
};

    
    return {
        "today": today,
        "browser": browser,
        "grpTable": grpTable,
        "grpIntTable": grpIntTable
    };
})();
