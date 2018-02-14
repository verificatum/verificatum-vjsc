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

var verificatum = (function () {
    var util = (function () {
        function time_ms() {
            return (new Date()).getTime();
        };
        function time() {
            return Math.floor(time_ms() / 1000);
        };
        var ofType = function (obj, type) {
            if (typeof type === "string") {
                if (type === "array") {
                    return Array.isArray(obj);
                } else if (type === "string") {
                    return typeof obj === type || obj instanceof String;
                } else {
                    return typeof obj === type;
                }
            } else {
                return obj.constructor === type;
            }
        };
        var fill = function (value, width) {
            var a = [];
            for (var i = 0; i < width; i++) {
                a[i] = value;
            }
            return a;
        };
        var full = function (value, width) {
            if (typeof width === "undefined" || width === 1) {
                return value;
            } else {
                return fill(value, width);
            }
        };
        var change_wordsize = function (words, orig_wordsize, new_wordsize) {
            var mask_all = 0xFFFFFFFF >>> 32 - new_wordsize;
            var new_words = [];
            new_words[0] = 0;
            var j = 0;
            var jb = 0;
            var i = 0;
            var ib = 0;
            while (j < words.length) {
                new_words[i] |= words[j] >>> jb << ib & mask_all;
                var inserted_bits = Math.min(orig_wordsize - jb, new_wordsize - ib);
                ib = ib + inserted_bits;
                if (ib === new_wordsize) {
                    i++;
                    ib = 0;
                    new_words[i] = 0;
                }
                jb = jb + inserted_bits;
                if (jb === orig_wordsize) {
                    j++;
                    jb = 0;
                }
            }
            return new_words;
        };
        var digits = "0123456789abcdef";
        var hex = function (b) {
            return digits[b >> 4 & 0xF] + digits[b & 0xF];
        };
        var asciiToByteArray = function (ascii) {
            var bytes = [];
            for (var i = 0; i < ascii.length; i++) {
                bytes.push(ascii.charCodeAt(i));
            }
            return bytes;
        };
        var byteArrayToAscii = function (bytes) {
            var ascii = "";
            for (var i = 0; i < bytes.length; i++) {
                ascii += String.fromCharCode(bytes[i]);
            }
            return ascii;
        };
        var byteArrayToHex = function (array) {
            var hexString = "";
            for (var i = 0; i < array.length; i++) {
                hexString += hex(array[i]);
            }
            return hexString;
        };
        var hexToByteArray = function (hex) {
            if (hex.length % 2 === 1) {
                hex = "0" + hex;
            }
            var res = [];
            var i = 0;
            hex.replace(/(..)/g,
                        function (hex) {
                            res[i++] = parseInt(hex, 16);
                        });
            return res;
        };
        var equalsArray = function (x, y) {
            if (x.length !== y.length) {
                return false;
            }
            for (var i = 0; i < x.length; i++) {
                if (x[i] !== y[i]) {
                    return false;
                }
            }
            return true;
        };
        var randomArray = function (len, wordsize, randomSource) {
            var no_bytes = Math.floor((len * wordsize + 7) / 8);
            var bytes = randomSource.getBytes(no_bytes);
            var no_msbits = wordsize % 8;
            if (no_msbits !== 0) {
                bytes[no_bytes - 1] &= 0xFF >>> 8 - no_msbits;
            }
            if (wordsize === 8) {
                return bytes;
            } else {
                return change_wordsize(bytes, 8, wordsize);
            }
        };
        var readUint32FromByteArray = function (bytes, index) {
            if (typeof index === "undefined") {
                index = 0;
            }
            var value = 0;
            for (var i = index; i < index + 4; i++) {
                value <<= 8;
                value |= bytes[i];
            }
            return value >>> 0;
        };
        var setUint32ToByteArray = function (destination, value, index) {
            for (var i = index + 3; i >= index; i--) {
                destination[i] = value & 0xFF;
                value >>= 8;
            }
        };
        var readUint16FromByteArray = function (bytes, index) {
            if (typeof index === "undefined") {
                index = 0;
            }
            var value = 0;
            for (var i = index; i < index + 2; i++) {
                value <<= 8;
                value |= bytes[i];
            }
            return value >>> 0;
        };
        var setUint16ToByteArray = function (destination, value, index) {
            for (var i = index + 1; i >= index; i--) {
                destination[i] = value & 0xFF;
                value >>= 8;
            }
        };
        return {
            "time_ms": time_ms,
            "time": time,
            "ofType": ofType,
            "fill": fill,
            "full": full,
            "change_wordsize": change_wordsize,
            "asciiToByteArray": asciiToByteArray,
            "byteArrayToAscii": byteArrayToAscii,
            "byteArrayToHex": byteArrayToHex,
            "hexToByteArray": hexToByteArray,
            "equalsArray": equalsArray,
            "randomArray": randomArray,
            "readUint32FromByteArray": readUint32FromByteArray,
            "setUint32ToByteArray": setUint32ToByteArray,
            "readUint16FromByteArray": readUint16FromByteArray,
            "setUint16ToByteArray": setUint16ToByteArray
        };
    })();
    var eio = (function () {
        function ByteTree(value) {
            if (verificatum.util.ofType(value, "array")) {
                if (typeof value[0] === "number") {
                    this.type = ByteTree.LEAF;
                    this.value = value;
                } else {
                    this.type = ByteTree.NODE;
                    this.value = value;
                }
            } else if (verificatum.util.ofType(value, "string")) {
                var start = value.indexOf("::");
                if (start > 0) {
                    value = value.slice(start + 2);
                }
                var array = util.hexToByteArray(value);
                var bt = ByteTree.readByteTreeFromByteArray(array);
                this.type = bt.type;
                this.value = bt.value;
            } else {
                throw Error("Unexpected type of input!");
            }
        };
        ByteTree.LEAF = 1;
        ByteTree.NODE = 0;
        ByteTree.readByteTreeFromByteArray = function (source, index) {
            var outputPair = true;
            if (typeof index === "undefined") {
                index = 0;
                outputPair = false;
            }
            var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);
            if (outputPair) {
                return pair;
            } else {
                return pair[0];
            }
        };
        ByteTree.readByteTreeFromByteArrayInner = function (source, index) {
            var origIndex = index;
            var type = source[index];
            if (type !== ByteTree.LEAF && type !== ByteTree.NODE) {
                throw Error("Unknown type! (" + type + ")");
            }
            index++;
            var length = verificatum.util.readUint32FromByteArray(source, index);
            if (length <= 0) {
                throw Error("Non-positive length! (" + length + ")");
            }
            index += 4;
            var byteTree;
            if (type === ByteTree.LEAF) {
                if (index + length <= source.length) {
                    var data = source.slice(index, index + length);
                    index += length;
                    byteTree = new ByteTree(data);
                } else {
                    throw new Error("Unable to read data for leaf, missing bytes! (" +
                                    "index = " + index + ", length = " + length + ")");
                }
            } else {
                var children = [];
                for (var i = 0; i < length; i++) {
                    var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);
                    children.push(pair[0]);
                    index += pair[1];
                }
                byteTree = new ByteTree(children);
            }
            return [byteTree, index - origIndex];
        };
        ByteTree.asByteTree = function (value) {
            if (util.ofType(value, eio.ByteTree)) {
                return value;
            } else {
                return new eio.ByteTree(value);
            }
        };
        ByteTree.prototype.isLeaf = function () {
            return this.type === ByteTree.LEAF;
        };
        ByteTree.prototype.size = function () {
            if (this.type === ByteTree.LEAF) {
                return 1 + 4 + this.value.length;
            } else if (this.type === ByteTree.NODE) {
                var size = 1 + 4;
                for (var i = 0; i < this.value.length; i++) {
                    size += this.value[i].size();
                }
                return size;
            } else {
                throw Error("Unknown type! (" + this.type + ")");
            }
        };
        ByteTree.prototype.setToByteArray = function (destination, index) {
            if (this.type === ByteTree.LEAF) {
                destination[index] = ByteTree.LEAF;
                index++;
                verificatum.util.setUint32ToByteArray(destination,
                                                      this.value.length,
                                                      index);
                index += 4;
                var i = index;
                var j = 0;
                while (j < this.value.length) {
                    destination[i] = this.value[j];
                    i++;
                    j++;
                }
                return 1 + 4 + this.value.length;
            } else {
                var origIndex = index;
                destination[index] = ByteTree.NODE;
                index++;
                verificatum.util.setUint32ToByteArray(destination,
                                                      this.value.length,
                                                      index);
                index += 4;
                for (var k = 0; k < this.value.length; k++) {
                    index += this.value[k].setToByteArray(destination, index);
                }
                return index - origIndex;
            }
        };
        ByteTree.prototype.toByteArray = function () {
            var array = [];
            this.setToByteArray(array, 0);
            return array;
        };
        ByteTree.prototype.toHexString = function () {
            var ba = this.toByteArray();
            return verificatum.util.byteArrayToHex(ba);
        };
        ByteTree.prototype.toPrettyStringInner = function (indent) {
            if (this.type === ByteTree.LEAF) {
                return indent +
                    "\"" + verificatum.util.byteArrayToHex(this.value) + "\"";
            } else if (this.type === ByteTree.NODE) {
                var s = indent + "[\n";
                for (var i = 0; i < this.value.length; i++) {
                    if (i > 0) {
                        s += ",\n";
                    }
                    s += this.value[i].toPrettyString(indent + "    ");
                }
                s += "\n" + indent + "]";
                return s;
            } else {
                throw Error("Unknown type! (" + this.type + ")");
            }
        };
        ByteTree.prototype.toPrettyString = function () {
            return this.toPrettyStringInner("");
        };
        return {
            "ByteTree": ByteTree
        };
    })();
    var arithm = (function () {
        function ArithmObject() {
        };
        ArithmObject.prototype = Object.create(Object.prototype);
        ArithmObject.prototype.constructor = ArithmObject;
        ArithmObject.prototype.getName = function () {
            var regex = /function\s?([^\(]{1,})\(/;
            var results = regex.exec(this.constructor.toString());
            return results && results.length > 1 ? results[1] : "";
        };
        var li = (function () {
            var WORDSIZE = 28;
            var KARATSUBA_MUL_THRESHOLD = 24;
            var KARATSUBA_SQR_THRESHOLD = 35;
            var KARATSUBA_RELATIVE = 0.8;
            var setzero = function (x) {
                for (var i = 0; i < x.length; i++) {
                    x[i] = 0;
                }
            };
            var set = function (w, x) {
                if (typeof x === "number") {
                    setzero(w);
                    w[0] = x;
                } else {
                    var i = 0;
                    while (i < Math.min(w.length, x.length)) {
                        w[i] = x[i];
                        i++;
                    }
                    while (i < w.length) {
                        w[i] = 0;
                        i++;
                    }
                }
            };
            var newarray = function (len) {
                var x = [];
                x.length = len;
                setzero(x);
                return x;
            };
            var copyarray = function (x, len) {
                if (typeof len === "undefined") {
                    len = 0;
                }
                var w = newarray(Math.max(x.length, len));
                set(w, x);
                return w;
            };
            var resize = function (x, len) {
                var xlen = x.length;
                x.length = len;
                if (len > xlen) {
                    for (var i = xlen; i < len; i++) {
                        x[i] = 0;
                    }
                }
            };
            var normalize = function (x, mask_top) {
                if (typeof mask_top === "undefined") {
                    mask_top = 0x8000000;
                }
                var l = x.length - 1;
                if (x[l] === 0) {
                    while (l > 0 && x[l] === 0) {
                        l--;
                    }
                    if ((x[l] & mask_top) !== 0) {
                        l++;
                    }
                    x.length = l + 1;
                } else if ((x[l] & mask_top) !== 0) {
                    x.length++;
                    x[x.length - 1] = 0;
                }
            };
            var setone = function (x) {
                setzero(x);
                x[0] = 1;
            };
            var msbit = function (x) {
                for (var i = x.length - 1; i >= 0; i--) {
                    if (x[i] !== 0) {
                        var msbit = (i + 1) * 28 - 1;
                        for (var mask = 0x8000000; mask !== 0; mask >>>= 1) {
                            if ((x[i] & mask) === 0) {
                                msbit--;
                            } else {
                                return msbit;
                            }
                        }
                    }
                }
                return 0;
            };
            var lsbit = function (x) {
                var i = 0;
                while (i < x.length && x[i] === 0) {
                    i++;
                }
                if (i === x.length) {
                    return 0;
                } else {
                    var j = 0;
                    while ((x[i] >>> j & 0x1) === 0) {
                        j++;
                    }
                    return i * 28 + j;
                }
            };
            var msword = function (x) {
                for (var i = x.length - 1; i > 0; i--) {
                    if (x[i] !== 0) {
                        return i;
                    }
                }
                return 0;
            };
            var getbit = function (x, index) {
                var wordIndex = Math.floor(index / 28);
                var bitIndex = index % 28;
                if (wordIndex >= x.length) {
                    return 0;
                }
                if ((x[wordIndex] & 1 << bitIndex) === 0) {
                    return 0;
                } else {
                    return 1;
                }
            };
            var iszero = function (x) {
                for (var i = 0; i < x.length; i++) {
                    if (x[i] !== 0) {
                        return false;
                    }
                }
                return true;
            };
            var cmp = function (x, y) {
                var sign = 1;
                if (x.length < y.length) {
                    var t = x;
                    x = y;
                    y = t;
                    sign = -1;
                }
                var i = x.length - 1;
                while (i >= y.length) {
                    if (x[i] === 0) {
                        i--;
                    } else {
                        return sign;
                    }
                }
                while (i >= 0) {
                    if (x[i] > y[i]) {
                        return sign;
                    } else if (x[i] < y[i]) {
                        return -sign;
                    }
                    i--;
                }
                return 0;
            };
            var shiftleft = function (x, offset) {
                if (offset === 0) {
                    return;
                }
                if (offset >= x.length * 28) {
                    setzero(x);
                    return;
                }
                var wordOffset = Math.floor(offset / 28);
                if (wordOffset > 0) {
                    var j = x.length - 1;
                    while (j >= wordOffset) {
                        x[j] = x[j - wordOffset];
                        j--;
                    }
                    while (j >= 0) {
                        x[j] = 0;
                        j--;
                    }
                }
                var bitOffset = offset % 28;
                var negBitOffset = 28 - bitOffset;
                if (bitOffset !== 0) {
                    for (var i = x.length - 1; i > 0; i--) {
                        var left = x[i] << bitOffset & 0xfffffff;
                        var right = x[i - 1] >>> negBitOffset;
                        x[i] = left | right;
                    }
                    x[0] = x[0] << bitOffset & 0xfffffff;
                }
            };
            var shiftright = function (x, offset) {
                if (offset === 0) {
                    return;
                }
                if (offset >= x.length * 28) {
                    setzero(x);
                    return;
                }
                var wordOffset = Math.floor(offset / 28);
                if (wordOffset > 0) {
                    var j = 0;
                    while (j < x.length - wordOffset) {
                        x[j] = x[j + wordOffset];
                        j++;
                    }
                    while (j < x.length) {
                        x[j] = 0;
                        j++;
                    }
                }
                var bitOffset = offset % 28;
                var negBitOffset = 28 - bitOffset;
                if (bitOffset !== 0) {
                    for (var i = 0; i < x.length - 1; i++) {
                        var left = x[i] >>> bitOffset;
                        var right = x[i + 1] << negBitOffset & 0xfffffff;
                        x[i] = left | right;
                    }
                    x[x.length - 1] = x[x.length - 1] >>> bitOffset;
                }
            };
            var add = function (w, x, y) {
                var tmp;
                var c = 0;
                if (x.length < y.length) {
                    var t = x;
                    x = y;
                    y = t;
                }
                var i = 0;
                var len = Math.min(w.length, y.length);
                while (i < len) {
                    tmp = x[i] + y[i] + c;
                    w[i] = tmp & 0xfffffff;
                    c = tmp >> 28;
                    i++;
                }
                len = Math.min(w.length, x.length);
                while (i < len) {
                    tmp = x[i] + c;
                    w[i] = tmp & 0xfffffff;
                    c = tmp >> 28;
                    i++;
                }
                if (i < w.length) {
                    w[i] = c;
                    i++;
                }
                while (i < w.length) {
                    w[i] = 0;
                    i++;
                }
            };
            var neg = function (w, x) {
                var i;
                var c;
                var tmp;
                c = 1;
                i = 0;
                while (i < x.length) {
                    tmp = (x[i] ^ 0xfffffff) + c;
                    w[i] = tmp & 0xfffffff;
                    c = (tmp >> 28) & 0xfffffff;
                    i++;
                }
                while (i < w.length) {
                    tmp = 0xfffffff + c;
                    w[i] = tmp & 0xfffffff;
                    c = (tmp >> 28) & 0xfffffff;
                    i++;
                }
            };
            var sub = function (w, x, y) {
                var tmp;
                var c = 0;
                var len = Math.min(w.length, x.length, y.length);
                var i = 0;
                while (i < len) {
                    tmp = x[i] - y[i] + c;
                    w[i] = tmp & 0xfffffff;
                    c = tmp >> 28;
                    i++;
                }
                if (x.length > y.length) {
                    len = Math.min(w.length, x.length);
                    while (i < len) {
                        tmp = x[i] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >> 28;
                        i++;
                    }
                } else {
                    len = Math.min(w.length, y.length);
                    while (i < len) {
                        tmp = -y[i] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >> 28;
                        i++;
                    }
                }
                while (i < w.length) {
                    w[i] = c & 0xfffffff;
                    c = tmp >> 28;
                    i++;
                }
                return c;
            };
            var muladd_loop = function (w, x, start, end, Y, i, c) {
                var hx;
                var lx;
                var cross;
                var hy = (Y >>> 14);
                var ly = (Y & 0x3fff);
                for (var j = start; j < end; j++) {
                    hx = (x[j] >>> 14);
                    lx = (x[j] & 0x3fff);
                    cross = (hx * ly + lx * hy) | 0;
                    lx = (((w[j + i] | 0) + lx * ly +
                           ((cross & 0x3fff) << 14)) | 0) + c;
                    c = ((lx >>> 28) + hx * hy +
                         (cross >>> 14) ) | 0;
                    w[j + i] = lx & 0xfffffff;
                }
                return c;
            };
            var word_mul = function (w, x, y) {
                var hx;
                var lx;
                var cross;
                var hy;
                var ly;
                w[0] = 0;
                w[1] = 0;
                hy = (y >>> 14);
                ly = (y & 0x3fff);
                hx = (x >>> 14);
                lx = (x & 0x3fff);
                cross = (hx * ly + lx * hy) | 0;
                lx = (((w[0] | 0) + lx * ly +
                       ((cross & 0x3fff) << 14)) | 0) + w[1];
                w[1] = ((lx >>> 28) + hx * hy +
                        (cross >>> 14) ) | 0;
                w[0] = lx & 0xfffffff;
            };
            var square_naive = function (w, x) {
                var n = msword(x) + 1;
                var c;
                var sc = 0;
                setzero(w);
                var i = 0;
                while (i < n) {
                    var l = x[i] & 0x3fff;
                    var h = x[i] >>> 14;
                    var cross = l * h << 1;
                    l = (w[i << 1] | 0) + l * l +
                        ((cross & 0x3fff) << 14);
                    c = ((l >>> 28) + (cross >>> 14) + h * h) | 0;
                    w[i << 1] = l & 0xfffffff;
                    sc = muladd_loop(w, x, i + 1, n, x[i] << 1, i, c) + sc;
                    w[i + n] = sc & 0xfffffff;
                    sc >>>= 28;
                    i++;
                }
            };
            var karatsuba_split = function (l, h, x) {
                var m = Math.min(l.length, x.length);
                var i = 0;
                while (i < m) {
                    l[i] = x[i];
                    i++;
                }
                while (i < l.length) {
                    l[i] = 0;
                    i++;
                }
                while (i < x.length) {
                    h[i - l.length] = x[i];
                    i++;
                }
                i -= l.length;
                while (i < l.length) {
                    h[i] = 0;
                    i++;
                }
            };
            var square_karatsuba = (function () {
                var scratch =
                    [
                        [[], [], [], [], [], [], []],
                        [[], [], [], [], [], [], []],
                        [[], [], [], [], [], [], []]
                    ];
                return function (w, x, depth, len) {
                    var s = scratch[depth];
                    var h = s[0];
                    var l = s[1];
                    var z2 = s[2];
                    var z1 = s[3];
                    var z0 = s[4];
                    var xdif = s[5];
                    if (typeof len === "undefined") {
                        len = x.length;
                    }
                    len += len % 2;
                    var half_len = len >>> 1;
                    if (h.length !== half_len) {
                        resize(h, half_len);
                        resize(l, half_len);
                        resize(z2, len);
                        resize(z1, len);
                        resize(z0, len);
                        resize(xdif, half_len);
                    }
                    karatsuba_split(l, h, x);
                    if (depth < 1) {
                        square_naive(z2, h);
                        square_naive(z0, l);
                    } else {
                        square_karatsuba(z2, h, depth - 1);
                        square_karatsuba(z0, l, depth - 1);
                    }
                    if (sub(xdif, h, l) < 0) {
                        sub(xdif, l, h);
                    }
                    if (depth < 1) {
                        square_naive(z1, xdif);
                    } else {
                        square_karatsuba(z1, xdif, depth - 1);
                    }
                    var tmp;
                    var c = 0;
                    var i = 0;
                    while (i < half_len) {
                        w[i] = z0[i];
                        i++;
                    }
                    while (i < len) {
                        tmp = z0[i] + z0[i - half_len] + z2[i - half_len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    while (i < len + half_len) {
                        tmp = z0[i - half_len] + z2[i - half_len] + z2[i - len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    while (i < 2 * len) {
                        tmp = z2[i - len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    i = half_len;
                    c = 0;
                    while (i < len + half_len) {
                        tmp = w[i] - z1[i - half_len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >> 28;
                        i++;
                    }
                    while (i < 2 * len) {
                        tmp = w[i] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >> 28;
                        i++;
                    }
                    while (i < w.length) {
                        w[i] = 0;
                        i++;
                    }
                };
            })();
            var square = function (w, x, len) {
                var xlen = msword(x) + 1;
                if (xlen > KARATSUBA_SQR_THRESHOLD) {
                    square_karatsuba(w, x, 0, len);
                } else {
                    square_naive(w, x);
                }
            };
            var mul_naive = function (w, x, y) {
                var n = msword(x) + 1;
                var t = msword(y) + 1;
                setzero(w);
                for (var i = 0; i < t; i++) {
                    w[i + n] = muladd_loop(w, x, 0, n, y[i], i, 0);
                }
            };
            var mul_karatsuba = (function () {
                var scratch =
                    [
                        [[], [], [], [], [], [], [], [], [], [], []],
                        [[], [], [], [], [], [], [], [], [], [], []],
                        [[], [], [], [], [], [], [], [], [], [], []]
                    ];
                return function (w, x, y, depth, len) {
                    var s = scratch[depth];
                    var hx = s[0];
                    var lx = s[1];
                    var hy = s[2];
                    var ly = s[3];
                    var z2 = s[4];
                    var z1 = s[5];
                    var z0 = s[6];
                    var xsum = s[7];
                    var ysum = s[8];
                    var tmp1 = s[9];
                    var tmp2 = s[10];
                    setzero(w);
                    if (typeof len === "undefined") {
                        len = Math.max(x.length, y.length);
                    }
                    len += len % 2;
                    var half_len = len >>> 1;
                    if (hx.length !== half_len) {
                        resize(hx, half_len);
                        resize(lx, half_len);
                        resize(hy, half_len);
                        resize(ly, half_len);
                        resize(z2, len);
                        resize(z1, len + 2);
                        resize(z0, len);
                        resize(xsum, half_len + 1);
                        resize(ysum, half_len + 1);
                        resize(tmp1, len + 2);
                        resize(tmp2, len + 2);
                    }
                    karatsuba_split(lx, hx, x);
                    karatsuba_split(ly, hy, y);
                    if (depth < 1) {
                        mul_naive(z2, hx, hy);
                        mul_naive(z0, lx, ly);
                    } else {
                        mul_karatsuba(z2, hx, hy, depth - 1);
                        mul_karatsuba(z0, lx, ly, depth - 1);
                    }
                    add(xsum, hx, lx);
                    add(ysum, hy, ly);
                    if (depth < 1) {
                        mul_naive(tmp1, xsum, ysum);
                    } else {
                        mul_karatsuba(tmp1, xsum, ysum, depth - 1);
                    }
                    sub(tmp2, tmp1, z2);
                    sub(z1, tmp2, z0);
                    var tmp;
                    var c = 0;
                    var i = 0;
                    while (i < half_len) {
                        w[i] = z0[i];
                        i++;
                    }
                    while (i < len) {
                        tmp = z0[i] + z1[i - half_len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    while (i < len + half_len + 2) {
                        tmp = z1[i - half_len] + z2[i - len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    while (i < 2 * len) {
                        tmp = z2[i - len] + c;
                        w[i] = tmp & 0xfffffff;
                        c = tmp >>> 28;
                        i++;
                    }
                    while (i < w.length) {
                        w[i] = 0;
                        i++;
                    }
                };
            })();
            var mul = function (w, x, y, len) {
                if (x === y) {
                    square(w, x);
                } else {
                    var xlen = msword(x) + 1;
                    var ylen = msword(y) + 1;
                    if (xlen > KARATSUBA_MUL_THRESHOLD &&
                        Math.min(xlen / ylen, ylen / xlen) > KARATSUBA_RELATIVE) {
                        mul_karatsuba(w, x, y, 0, len);
                    } else {
                        mul_naive(w, x, y);
                    }
                }
            };
            var reciprocal_word = (function () {
                var q = [0, 0];
                var a = [0, 0];
                var p = [0, 0, 0];
                var r = [0, 0, 0];
                var one = [1];
                var zero = [0];
                var dd = [0];
                var two_masks = [0xfffffff, 0xfffffff];
                return function (d) {
                    var s;
                    var N;
                    var A;
                    dd[0] = d;
                    set(r, two_masks);
                    setzero(q);
                    do {
                        s = Math.max(0, msbit(r) - 53);
                        N = r[1] * Math.pow(2, 28 - s) + (r[0] >> s);
                        A = Math.floor(N / d);
                        a[0] = A & 0xfffffff;
                        a[1] = (A >>> 28);
                        shiftleft(a, s);
                        mul(p, a, dd);
                        while (cmp(p, r) > 0) {
                            sub(a, a, one);
                            sub(p, p, dd);
                        }
                        sub(r, r, p);
                        add(q, q, a);
                    } while (cmp(a, zero) > 0);
                    while (cmp(r, dd) >= 0) {
                        add(q, q, one);
                        sub(r, r, dd);
                    }
                    return q[0] & 0xfffffff;
                };
            })();
            var reciprocal_word_3by2 = (function () {
                var t = [0, 0];
                return function (d) {
                    var v = reciprocal_word(d[1]);
                    word_mul(t, d[1], v);
                    var p = t[0];
                    p = (p + d[0]) & 0xfffffff;
                    if (p < d[0]) {
                        v--;
                        if (p >= d[1]) {
                            v--;
                            p = p - d[1];
                        }
                        p = (p + 0x10000000 - d[1]) & 0xfffffff;
                    }
                    word_mul(t, v, d[0]);
                    p = (p + t[1]) & 0xfffffff;
                    if (p < t[1]) {
                        v--;
                        if (p > d[1] || (p === d[1] && t[0] >= d[0])) {
                            v--;
                        }
                    }
                    return v;
                };
            })();
            var div3by2 = (function () {
                var q = [0, 0];
                var neg_t = [0, 0];
                return function (r, u, d, neg_d, v) {
                    var tmp = 0;
                    word_mul(q, v, u[2]);
                    tmp = q[0] + u[1];
                    q[0] = tmp & 0xfffffff;
                    q[1] = (q[1] + u[2] + (tmp >>> 28)) & 0xfffffff;
                    word_mul(r, q[1], d[1]);
                    r[1] = (u[1] + 0x10000000 - r[0]) & 0xfffffff;
                    word_mul(neg_t, d[0], q[1]);
                    neg(neg_t, neg_t);
                    r[0] = u[0];
                    tmp = r[0] + neg_t[0];
                    r[0] = tmp & 0xfffffff;
                    r[1] = (r[1] + neg_t[1] + (tmp >>> 28)) & 0xfffffff;
                    tmp = r[0] + neg_d[0];
                    r[0] = tmp & 0xfffffff;
                    r[1] = (r[1] + neg_d[1] + (tmp >>> 28)) & 0xfffffff;
                    q[1] = (q[1] + 1) & 0xfffffff;
                    if (r[1] >= q[0]) {
                        q[1] = (q[1] + 0xfffffff) & 0xfffffff;
                        tmp = r[0] + d[0];
                        r[0] = tmp & 0xfffffff;
                        r[1] = (r[1] + d[1] + (tmp >>> 28)) & 0xfffffff;
                    }
                    if (r[1] > d[1] || (r[1] === d[1] && r[0] >= d[0])) {
                        q[1] = q[1] + 1;
                        tmp = r[0] + neg_d[0];
                        r[0] = tmp & 0xfffffff;
                        r[1] = (r[1] + neg_d[1] + (tmp >>> 28)) & 0xfffffff;
                    }
                    return q[1];
                };
            })();
            var div_qr = (function () {
                var old_y = null;
                var ny = [];
                var neg_ny = [];
                var normdist;
                var t;
                var v;
                var u = [0, 0, 0];
                var d = [0, 0];
                var neg_d = [0, 0];
                var r = [0, 0];
                var initialize_y = function (y) {
                    if (y === old_y) {
                        return;
                    }
                    old_y = y;
                    if (neg_ny.length !== y.length + 1) {
                        resize(neg_ny, y.length + 1);
                        ny.length = y.length;
                    }
                    set(ny, y);
                    normdist =
                        (28 - (msbit(ny) + 1) % 28) % 28;
                    shiftleft(ny, normdist);
                    neg(neg_ny, ny);
                    t = msword(ny);
                    d[1] = ny[t];
                    d[0] = t > 0 ? ny[t - 1] : 0;
                    neg(neg_d, d);
                    v = reciprocal_word_3by2(d);
                };
                var shiftleft_ge = function (x, n, y, t) {
                    var i = n;
                    var j = t;
                    while (j >= 0) {
                        if (x[i] > y[j]) {
                            return true;
                        } else if (x[i] < y[j]) {
                            return false;
                        }
                        i--;
                        j--;
                    }
                    return true;
                };
                return function (w, x, y) {
                    var n;
                    var i;
                    var j;
                    var k;
                    var l;
                    var tmp;
                    var c;
                    setzero(w);
                    if (cmp(x, y) < 0) {
                        return;
                    }
                    initialize_y(y);
                    shiftleft(x, normdist);
                    n = msword(x);
                    while (shiftleft_ge(x, n, ny, t)) {
                        i = 0;
                        j = n - t;
                        c = 0;
                        while (i < t + 1) {
                            tmp = x[j] - ny[i] + c;
                            x[j] = tmp & 0xfffffff;
                            c = tmp >> 28;
                            i++;
                            j++;
                        }
                        w[n - t]++;
                    }
                    for (i = n; i >= t + 1; i--) {
                        k = i - t - 1;
                        u[2] = x[i];
                        u[1] = i > 0 ? x[i - 1] : 0;
                        u[0] = i > 1 ? x[i - 2] : 0;
                        if (u[2] === d[1] && u[1] >= d[0]) {
                            w[k] = 0xfffffff;
                        } else {
                            w[k] = div3by2(r, u, d, neg_d, v);
                        }
                        muladd_loop(x, neg_ny, 0, t + 2, w[k], k, 0);
                        if (x[k + t + 1] === 0xfffffff) {
                            l = 0;
                            j = k;
                            c = 0;
                            while (l < t + 1) {
                                tmp = x[j] + ny[l] + c;
                                x[j] = tmp & 0xfffffff;
                                c = tmp >> 28;
                                l++;
                                j++;
                            }
                            tmp = x[j] + c;
                            x[j] = tmp & 0xfffffff;
                            j++;
                            if (j < x.length) {
                                x[j] = 0;
                            }
                            w[k]--;
                        }
                    }
                    shiftright(x, normdist);
                };
            })();
            var modpow_naive = (function () {
                var p = [];
                var q = [];
                var A = [];
                return function (w, b, e, m) {
                    if (A.length !== m.length) {
                        resize(p, 2 * m.length + 2);
                        resize(q, m.length);
                        resize(A, m.length);
                    }
                    var n = msbit(e);
                    if (getbit(e, n) === 1) {
                        set(p, b);
                        div_qr(q, p, m);
                        set(A, p);
                    }
                    for (var i = n - 1; i >= 0; i--) {
                        square(p, A);
                        div_qr(q, p, m);
                        set(A, p);
                        if (getbit(e, i) === 1) {
                            mul(p, A, b);
                            div_qr(q, p, m);
                            set(A, p);
                        }
                    }
                    set(w, A);
                };
            })();
            var getuh = function (uh, x, i, wordsize) {
                var bitIndex = i * wordsize;
                uh[0] = 0;
                for (var j = 0; j < wordsize; j++) {
                    uh[0] = uh[0] | getbit(x, bitIndex) << j;
                    bitIndex++;
                }
                uh[1] = 0;
                if (uh[0] !== 0) {
                    while ((uh[0] & 0x1) === 0) {
                        uh[0] = uh[0] >>> 1;
                        uh[1]++;
                    }
                }
            };
            var modpow = (function () {
                var p = [];
                var q = [];
                var A = [];
                var B = [];
                return function (w, b, e, m) {
                    var i;
                    var j;
                    var msb = msbit(m) + 1;
                    var k = 2;
                    if (msb > 512) {
                        k++;
                    }
                    if (msb > 640) {
                        k++;
                    }
                    if (msb > 768) {
                        k++;
                    }
                    if (msb > 896) {
                        k++;
                    }
                    if (msb > 1280) {
                        k++;
                    }
                    if (msb > 2688) {
                        k++;
                    }
                    if (msb > 3840) {
                        k++;
                    }
                    if (A.length !== m.length) {
                        resize(p, 2 * m.length + 2);
                        resize(q, m.length);
                        resize(A, m.length);
                        var len = B.length;
                        for (i = 0; i < len; i++) {
                            if (B[i].length !== m.length) {
                                resize(B[i], m.length);
                            }
                        }
                        if (len < 1 << k) {
                            B.length = 1 << k;
                            for (i = len; i < B.length; i++) {
                                B[i] = newarray(m.length);
                            }
                        }
                    }
                    B[0][0] = 1;
                    set(B[1], b);
                    square(p, b);
                    div_qr(q, p, m);
                    set(B[2], p);
                    for (i = 1; i < 1 << k - 1; i++) {
                        mul(p, B[2 * i - 1], B[2]);
                        div_qr(q, p, m);
                        set(B[2 * i + 1], p);
                    }
                    setzero(A);
                    A[0] = 1;
                    var n = Math.floor((msbit(e) + k - 1) / k);
                    var uh = [0, 0];
                    for (i = n; i >= 0; i--) {
                        getuh(uh, e, i, k);
                        for (j = 0; j < k - uh[1]; j++) {
                            square(p, A);
                            div_qr(q, p, m);
                            set(A, p);
                        }
                        if (uh[0] !== 0) {
                            mul(p, A, B[uh[0]]);
                            div_qr(q, p, m);
                            set(A, p);
                        }
                        for (j = 0; j < uh[1]; j++) {
                            square(p, A);
                            div_qr(q, p, m);
                            set(A, p);
                        }
                    }
                    set(w, A);
                };
            })();
            var modpowprodtab = (function () {
                var p = [];
                var q = [];
                return function (b, m) {
                    var i;
                    var j;
                    if (q.length !== m.length) {
                        resize(p, 2 * m.length + 2);
                        resize(q, m.length);
                    }
                    var t = [];
                    for (i = 0; i < 1 << b.length; i++) {
                        t[i] = newarray(m.length);
                        t[i][0] = 1;
                    }
                    for (i = 1, j = 0; i < t.length; i = i * 2, j++) {
                        set(t[i], b[j]);
                    }
                    for (var mask = 1; mask < t.length; mask++) {
                        var onemask = mask & -mask;
                        mul(p, t[mask ^ onemask], t[onemask]);
                        div_qr(q, p, m);
                        set(t[mask], p);
                    }
                    return t;
                };
            })();
            var modpowprod = (function () {
                var p = [];
                var q = [];
                var A = [];
                return function (w, t, e, m) {
                    var i;
                    if (A.length !== m.length) {
                        resize(p, 2 * m.length + 2);
                        resize(q, m.length);
                        resize(A, m.length);
                    }
                    var l = msbit(e[0]);
                    for (i = 1; i < e.length; i++) {
                        l = Math.max(msbit(e[i]), l);
                    }
                    setone(A);
                    for (i = l; i >= 0; i--) {
                        var x = 0;
                        square(p, A);
                        div_qr(q, p, m);
                        set(A, p);
                        for (var j = 0; j < e.length; j++) {
                            if (getbit(e[j], i) === 1) {
                                x |= 1 << j;
                            }
                        }
                        if (x !== 0) {
                            mul(p, A, t[x]);
                            div_qr(q, p, m);
                            set(A, p);
                        }
                    }
                    set(w, A);
                };
            })();
            var slice = function (x, s, e) {
                var m = msbit(x);
                e = Math.min(e, m + 1);
                var w = copyarray(x);
                shiftright(w, s);
                var bitlen = e - s;
                w.length = Math.floor((bitlen + 28 - 1) / 28);
                var topbits = bitlen % 28;
                if (topbits > 0) {
                    w[w.length - 1] &= 0xfffffff >>> 28 - topbits;
                }
                return w;
            };
            var hex = function (x) {
                var dense = util.change_wordsize(x, 28, 8);
                normalize(dense);
                return util.byteArrayToHex(dense.reverse());
            };
            var hex_to_li = function (s) {
                var b = util.hexToByteArray(s);
                var r = b.reverse();
                return util.change_wordsize(r, 8, 28);
            };
            var INSECURErandom = function (bitLength) {                        
                var noWords =                                                  
                    Math.floor((bitLength + 28 - 1) / 28);   
                var zeroBits = noWords * 28 - bitLength;              
                var x = [];                                                    
                for (var i = 0; i < noWords; i++) {                            
                    x[i] = Math.floor(Math.random() * 0x10000000);    
                }                                                              
                x[x.length - 1] &= 0xfffffff >>> zeroBits;                   
                normalize(x);                                                  
                return x;                                                      
            };                                                                 
            return {
                "WORDSIZE": WORDSIZE,
                "newarray": newarray,
                "copyarray": copyarray,
                "resize": resize,
                "normalize": normalize,
                "setzero": setzero,
                "setone": setone,
                "set": set,
                "msbit": msbit,
                "lsbit": lsbit,
                "msword": msword,
                "getbit": getbit,
                "iszero": iszero,
                "cmp": cmp,
                "shiftleft": shiftleft,
                "shiftright": shiftright,
                "add": add,
                "sub": sub,
                "mul": mul,
                "mul_naive": mul_naive,
                "mul_karatsuba": mul_karatsuba,
                "square": square,
                "square_naive": square_naive,
                "square_karatsuba": square_karatsuba,
                "div_qr": div_qr,
                "modpow_naive": modpow_naive,
                "modpow": modpow,
                "modpowprodtab": modpowprodtab,
                "modpowprod": modpowprod,
                "slice": slice,
                "hex": hex,
                "hex_to_li": hex_to_li,
                "muladd_loop": muladd_loop,
                "neg": neg,
                "reciprocal_word": reciprocal_word,
                "reciprocal_word_3by2": reciprocal_word_3by2,
                "div3by2": div3by2,
                "word_mul": word_mul,
                "INSECURErandom": INSECURErandom                               
            };
        })();
        var sli = (function () {
            function SLI(first, second) {
                if (typeof first === "undefined") {
                    this.sign = 1;
                    this.value = [];
                } else if (typeof second === "undefined") {
                    this.sign = 1;
                    this.value = li.newarray(first);
                } else {
                    this.sign = first;
                    this.value = second;
                }
                this.length = this.value.length;
            }
            SLI.prototype = Object.create(ArithmObject.prototype);
            SLI.prototype.constructor = SLI;
            var normalize = function (x, mask_top) {
                li.normalize(x.value, mask_top);
                this.length = x.value.length;
            };
            var resize = function (a, len) {
                li.resize(a.value, len);
                a.length = a.value.length;
            };
            var sign = function (n) {
                if (n > 0) {
                    return 1;
                } else if (n === 0) {
                    return 0;
                } else {
                    return -1;
                }
            };
            var set = function (a, b) {
                if (typeof b === "number") {
                    a.sign = sign(b);
                    li.setzero(a.value);
                    a.value[0] = a.sign * b;
                } else {
                    a.sign = b.sign;
                    li.set(a.value, b.value);
                }
            };
            var copy = function (a, len) {
                if (typeof len === "undefined") {
                    len = a.length;
                }
                return new SLI(a.sign, li.copyarray(a.value, len));
            };
            var cmp = function (a, b) {
                if (a.sign < b.sign) {
                    return -1;
                } else if (a.sign > b.sign) {
                    return 1;
                } else if (a.sign === 0) {
                    return 0;
                }
                return li.cmp(a.value, b.value) * a.sign;
            };
            var equals = function (a, b) {
                return a.sign === b.sign && li.cmp(a.value, b.value) === 0;
            };
            var iszero = function (a) {
                return a.sign === 0;
            };
            var isone = function (a) {
                return a.sign === 1 && a.value[0] === 1 && li.msword(a.value) === 0;
            };
            var shiftleft = function (a, offset) {
                li.shiftleft(a.value, offset);
            };
            var shiftright = function (a, offset) {
                li.shiftright(a.value, offset);
                if (li.iszero(a.value)) {
                    a.sign = 0;
                }
            };
            var add = function (a, b, c) {
                var w = a.value;
                var x = b.value;
                var y = c.value;
                if (b.sign === c.sign) {
                    li.add(w, x, y);
                    if (b.sign === 0) {
                        a.sign = -c.sign;
                    } else {
                        a.sign = b.sign;
                    }
                } else {
                    if (li.cmp(x, y) >= 0) {
                        li.sub(w, x, y);
                        a.sign = b.sign;
                    } else {
                        li.sub(w, y, x);
                        a.sign = c.sign;
                    }
                }
                if (li.iszero(w)) {
                    a.sign = 0;
                }
            };
            var sub = function (a, b, c) {
                var w = a.value;
                var x = b.value;
                var y = c.value;
                if (b.sign === c.sign) {
                    if (li.cmp(x, y) >= 0) {
                        li.sub(w, x, y);
                        a.sign = b.sign;
                    } else {
                        li.sub(w, y, x);
                        a.sign = -b.sign;
                    }
                } else {
                    li.add(w, x, y);
                    if (b.sign === 0) {
                        a.sign = -c.sign;
                    } else {
                        a.sign = b.sign;
                    }
                }
                if (li.iszero(w)) {
                    a.sign = 0;
                }
            };
            var mul = (function () {
                var t = [];
                return function (a, b, c) {
                    if (a === b || a === c) {
                        if (t.length !== a.length) {
                            li.resize(t, a.length);
                        }
                        li.mul(t, b.value, c.value);
                        li.set(a.value, t);
                    } else {
                        li.mul(a.value, b.value, c.value);
                    }
                    a.sign = b.sign * c.sign;
                };
            })();
            var mul_number = (function () {
                var C = new SLI(1);
                return function (a, b, c) {
                    set(C, c);
                    mul(a, b, C);
                };
            })();
            var square = function (a, b) {
                li.square(a.value, b.value);
                a.sign = b.sign * b.sign;
            };
            var div_qr = function (q, a, b) {
                var qsign;
                var asign;
                li.div_qr(q.value, a.value, b.value);
                if (li.iszero(a.value)) {
                    qsign = a.sign * b.sign;
                    asign = 0;
                } else {
                    if (a.sign * b.sign === 1) {
                        asign = a.sign;
                        qsign = a.sign;
                    } else {
                        li.sub(a.value, b.value, a.value);
                        li.add(q, q, [1]);
                        asign = b.sign;
                        qsign = a.sign;
                    }
                }
                q.sign = qsign;
                a.sign = asign;
            };
            var mod = (function () {
                var q = new SLI();
                var r = new SLI();
                return function (a, b, c) {
                    var qlen = b.length + 1;
                    if (q.length < qlen) {
                        resize(q, qlen);
                    }
                    var rlen = b.length + 2;
                    if (r.length < rlen) {
                        resize(r, rlen);
                    }
                    set(r, b);
                    div_qr(q, r, c);
                    set(a, r);
                };
            })();
            var egcd_binary_reduce = function (u, A, B, x, y) {
                while ((u.value[0] & 0x1) === 0) {
                    shiftright(u, 1);
                    if ((A.value[0] & 0x1) === 0 && (B.value[0] & 0x1) === 0) {
                        shiftright(A, 1);
                        shiftright(B, 1);
                    } else {
                        add(A, A, y);
                        shiftright(A, 1);
                        sub(B, B, x);
                        shiftright(B, 1);
                    }
                }
            };
            var egcd = (function () {
                var xs = new SLI();
                var ys = new SLI();
                var A = new SLI();
                var B = new SLI();
                var C = new SLI();
                var D = new SLI();
                var u = new SLI();
                return function (a, b, v, x, y) {
                    if (iszero(x) || iszero(y)) {
                        set(a, 0);
                        set(b, 0);
                        set(v, 0);
                        return;
                    }
                    var len = Math.max(x.length, y.length) + 1;
                    if (A.length !== len) {
                        resize(xs, len);
                        resize(ys, len);
                        resize(A, len);
                        resize(B, len);
                        resize(C, len);
                        resize(D, len);
                        resize(u, len);
                    }
                    set(xs, x);
                    set(ys, y);
                    set(A, 1);
                    set(B, 0);
                    set(C, 0);
                    set(D, 1);
                    var common_twos = Math.min(li.lsbit(xs.value), li.lsbit(ys.value));
                    shiftright(xs, common_twos);
                    shiftright(ys, common_twos);
                    set(u, xs);
                    set(v, ys);
                    while (!iszero(u)) {
                        egcd_binary_reduce(u, A, B, xs, ys);
                        egcd_binary_reduce(v, C, D, xs, ys);
                        if (cmp(u, v) >= 0) {
                            sub(u, u, v);
                            sub(A, A, C);
                            sub(B, B, D);
                        } else {
                            sub(v, v, u);
                            sub(C, C, A);
                            sub(D, D, B);
                        }
                    }
                    set(a, C);
                    set(b, D);
                    shiftleft(v, common_twos);
                };
            })();
            var modinv = (function () {
                var a = new SLI();
                var b = new SLI();
                var v = new SLI();
                return function (w, x, p) {
                    var len = Math.max(p.length, x.length);
                    if (a.length !== len) {
                        resize(a, len);
                        resize(b, len);
                        resize(v, len);
                    }
                    egcd(a, b, v, x, p);
                    if (a.sign < 0) {
                        add(w, p, a);
                    } else {
                        set(w, a);
                    }
                };
            })();
            var modpow = function (w, b, e, m) {
                li.modpow(w.value, b.value, e.value, m.value);
                w.sign = 1;
            };
            var legendre = function (a, b) {
                a = copy(a);
                b = copy(b);
                var s = 1;
                for (;;) {
                    if (iszero(a)) {
                        return 0;
                    } else if (isone(a)) {
                        return s;
                    } else {
                        var e = li.lsbit(a.value);
                        shiftright(a, e);
                        var aw = a.value[0];
                        var bw = b.value[0];
                        if (e % 2 === 1 && (bw % 8 === 3 || bw % 8 === 5)) {
                            s = -s;
                        }
                        if (bw % 4 === 3 && aw % 4 === 3) {
                            s = -s;
                        }
                        if (isone(a)) {
                            return s;
                        }
                        mod(b, b, a);
                        var t = a;
                        a = b;
                        b = t;
                    }
                }
            };
            var modsqrt = (function () {
                var ONE = new SLI(1);
                set(ONE, 1);
                var TWO = new SLI(1);
                set(TWO, 2);
                var a = new SLI();
                var n = new SLI();
                var v = new SLI();
                var k = new SLI();
                var r = new SLI();
                var z = new SLI();
                var c = new SLI();
                var tmp = new SLI();
                return function (w, x, p) {
                    var len = 2 * (li.msword(p.value) + 1);
                    if (a.length !== len) {
                        resize(a, len);
                        resize(n, len);
                        resize(v, len);
                        resize(k, len);
                        resize(r, len);
                        resize(z, len);
                        resize(c, len);
                        resize(tmp, len);
                    }
                    mod(a, x, p);
                    if (iszero(a)) {
                        set(w, 0);
                        return;
                    }
                    if (equals(p, TWO)) {
                        set(w, a);
                        return;
                    }
                    if ((p.value[0] & 0x3) === 0x3) {
                        add(v, p, ONE);
                        shiftright(v, 2);
                        modpow(w, a, v, p);
                        return;
                    }
                    sub(k, p, ONE);
                    var s = li.lsbit(k.value);
                    shiftright(k, s);
                    sub(k, k, ONE);
                    shiftright(k, 1);
                    modpow(r, a, k, p);
                    mul(tmp, r, r);
                    mod(n, tmp, p);
                    mul(tmp, n, a);
                    mod(n, tmp, p);
                    mul(tmp, r, a);
                    mod(r, tmp, p);
                    if (isone(n)) {
                        set(w, r);
                        return;
                    }
                    set(z, 2);
                    while (legendre(z, p) === 1) {
                        add(z, z, ONE);
                    }
                    set(v, k);
                    shiftleft(v, 1);
                    add(v, v, ONE);
                    modpow(c, z, v, p);
                    var t = 0;
                    while (cmp(n, ONE) > 0) {
                        set(k, n);
                        t = s;
                        s = 0;
                        while (!isone(k)) {
                            mul(tmp, k, k);
                            mod(k, tmp, p);
                            s++;
                        }
                        t -= s;
                        set(v, ONE);
                        shiftleft(v, t - 1);
                        modpow(tmp, c, v, p);
                        set(c, tmp);
                        mul(tmp, r, c);
                        mod(r, tmp, p);
                        mul(tmp, c, c);
                        mod(c, tmp, p);
                        mul(tmp, n, c);
                        mod(n, tmp, p);
                    }
                    set(w, r);
                };
            })();
            var hex = function (a) {
                var s = "";
                if (a.sign < 0) {
                    s = "-";
                }
                return s + li.hex(a.value);
            };
            var INSECURErandom = function (bitLength) {                        
                var x = li.INSECURErandom(bitLength);                          
                var sign = 1;                                                  
                if (li.iszero(x)) {                                            
                    sign = 0;                                                  
                }                                                              
                return new SLI(sign, x);                                       
            };                                                                 
            return {
                "SLI": SLI,
                "set": set,
                "copy": copy,
                "resize": resize,
                "normalize": normalize,
                "cmp": cmp,
                "equals": equals,
                "iszero": iszero,
                "shiftleft": shiftleft,
                "shiftright": shiftright,
                "add": add,
                "sub": sub,
                "mul": mul,
                "mul_number": mul_number,
                "square": square,
                "div_qr": div_qr,
                "mod": mod,
                "modinv": modinv,
                "egcd": egcd,
                "legendre": legendre,
                "modsqrt": modsqrt,
                "INSECURErandom": INSECURErandom,
                "hex": hex
            };
        })();
        function LargeInteger(first, second) {
            sli.SLI.call(this);
            var sign;
            var value;
            if (typeof second !== "undefined") {
                if (util.ofType(second, "array")) {
                    sign = first;
                    value = second;
                } else {
                    var byteLength = LargeInteger.byteLengthRandom(first);
                    var topZeros = (8 - first % 8) % 8;
                    var data = second.getBytes(byteLength);
                    data[0] &= 0xFF >>> topZeros;
                    var reversed = data.reverse();
                    value = util.change_wordsize(reversed, 8, li.WORDSIZE);
                    if (li.iszero(value)) {
                        sign = 0;
                    } else {
                        sign = 1;
                    }
                }
            } else if (util.ofType(first, "array")) {
                value = util.change_wordsize(first.slice().reverse(), 8, li.WORDSIZE);
                if (li.iszero(value)) {
                    sign = 0;
                } else {
                    sign = 1;
                }
            } else if (util.ofType(first, "string")) {
                var hex = first;
                var i = 0;
                if (hex[i] === "-") {
                    sign = -1;
                    i++;
                } else {
                    sign = 1;
                }
                while (i < hex.length && hex[i] === "0") {
                    i++;
                }
                if (i === hex.length) {
                    sign = 0;
                    hex = "00";
                } else {
                    hex = hex.substring(i, hex.length);
                }
                var array = util.hexToByteArray(hex).reverse();
                value = util.change_wordsize(array, 8, li.WORDSIZE);
            } else if (util.ofType(first, "object")) {
                if (!first.isLeaf()) {
                    throw Error("Expected a leaf!");
                }
                var tmp = new LargeInteger(first.value);
                sign = tmp.sign;
                value = tmp.value;
            } else if (util.ofType(first, "number")) {
                sign = 0;
                value = li.newarray(first);
            } else {
                throw Error("Invalid parameters!");
            }
            this.sign = sign;
            this.value = value;
            this.length = value.length;
        }
        LargeInteger.prototype = Object.create(sli.SLI.prototype);
        LargeInteger.prototype.constructor = LargeInteger;
        LargeInteger.ZERO = new LargeInteger(0, [0]);
        LargeInteger.ONE = new LargeInteger(1, [1]);
        LargeInteger.TWO = new LargeInteger(1, [2]);
        LargeInteger.byteLengthRandom = function (bitLength) {
            return Math.floor((bitLength + 7) / 8);
        };
        LargeInteger.prototype.cmp = function (other) {
            if (this.sign < other.sign) {
                return -1;
            } else if (this.sign > other.sign) {
                return 1;
            } else if (this.sign === 0) {
                return 0;
            }
            return li.cmp(this.value, other.value) * this.sign;
        };
        LargeInteger.prototype.equals = function (other) {
            return this.cmp(other) === 0;
        };
        LargeInteger.prototype.iszero = function () {
            return this.sign === 0;
        };
        LargeInteger.prototype.bitLength = function () {
            return li.msbit(this.value) + 1;
        };
        LargeInteger.prototype.getBit = function (index) {
            return li.getbit(this.value, index);
        };
        LargeInteger.prototype.abs = function () {
            return new LargeInteger(1, li.copyarray(this.value));
        };
        LargeInteger.prototype.shiftLeft = function (offset) {
            var len =
                this.length + Math.floor((offset + li.WORDSIZE - 1) / li.WORDSIZE);
            var value = li.copyarray(this.value);
            li.resize(value, len);
            li.shiftleft(value, offset);
            return new LargeInteger(this.sign, value);
        };
        LargeInteger.prototype.shiftRight = function (offset) {
            var value = li.copyarray(this.value);
            li.shiftright(value, offset);
            li.normalize(value);
            var sign = this.sign;
            if (li.iszero(value)) {
                sign = 0;
            }
            return new LargeInteger(sign, value);
        };
        LargeInteger.prototype.neg = function () {
            return new LargeInteger(-this.sign, li.copyarray(this.value));
        };
        LargeInteger.prototype.add = function (term) {
            var len = Math.max(this.length, term.length) + 1;
            var res = new LargeInteger(len);
            sli.add(res, this, term);
            sli.normalize(res);
            return res;
        };
        LargeInteger.prototype.sub = function (term) {
            var len = Math.max(this.length, term.length) + 1;
            var res = new LargeInteger(len);
            sli.sub(res, this, term);
            sli.normalize(res);
            return res;
        };
        LargeInteger.prototype.mul = function (factor) {
            var len = this.length + factor.length;
            var res = new LargeInteger(len);
            sli.mul(res, this, factor);
            sli.normalize(res);
            return res;
        };
        LargeInteger.prototype.square = function () {
            var len = 2 * this.length;
            var res = new LargeInteger(len);
            sli.square(res, this);
            sli.normalize(res);
            return res;
        };
        LargeInteger.prototype.divQR = function (divisor) {
            if (divisor.sign === 0) {
                throw Error("Attempt to divide by zero!");
            }
            var dlen = divisor.length;
            var remainder = new LargeInteger(Math.max(this.length, dlen) + 2);
            sli.set(remainder, this);
            var qlen = Math.max(remainder.length - dlen, dlen, 0) + 1;
            var quotient = new LargeInteger(qlen);
            sli.div_qr(quotient, remainder, divisor);
            sli.normalize(quotient);
            sli.normalize(remainder);
            return [quotient, remainder];
        };
        LargeInteger.prototype.div = function (divisor) {
            return this.divQR(divisor)[0];
        };
        LargeInteger.prototype.mod = function (modulus) {
            return this.divQR(modulus)[1];
        };
        LargeInteger.prototype.modAdd = function (term, modulus) {
            return this.add(term).mod(modulus);
        };
        LargeInteger.prototype.modSub = function (term, modulus) {
            return this.sub(term).mod(modulus);
        };
        LargeInteger.prototype.modMul = function (factor, modulus) {
            return this.mul(factor).mod(modulus);
        };
        LargeInteger.prototype.modPow = function (exponent, modulus, naive) {
            if (this.sign < 0) {
                throw Error("Negative basis! (" + this.toHexString() + ")");
            }
            if (exponent.sign < 0) {
                throw Error("Negative exponent! (" + exponent.toHexString() + ")");
            }
            if (modulus.sign <= 0) {
                throw Error("Non-positive modulus! (" + modulus.toHexString() + ")");
            }
            if (modulus.equals(LargeInteger.ONE)) {
                return LargeInteger.ZERO;
            }
            if (exponent.sign === 0) {
                return LargeInteger.ONE;
            }
            var b = this.value;
            var g = b;
            var e = exponent.value;
            var m = modulus.value;
            if (b.length > m.length) {
                g = this.divQR(modulus)[1].value;
                li.resize(g, m.length);
            } else if (b.length < m.length) {
                g = li.newarray(m.length);
                li.set(g, b);
            }
            var w = li.newarray(m.length);
            if (naive) {
                li.modpow_naive(w, g, e, m);
            } else {
                li.modpow(w, g, e, m);
            }
            if (li.iszero(w)) {
                return LargeInteger.ZERO;
            } else {
                li.normalize(w);
                return new LargeInteger(1, w);
            }
        };
        LargeInteger.prototype.egcd = function (other) {
            var len = Math.max(this.length, other.length) + 1;
            var a = new LargeInteger(len);
            var b = new LargeInteger(len);
            var v = new LargeInteger(len);
            sli.egcd(a, b, v, this, other);
            sli.normalize(a);
            sli.normalize(b);
            sli.normalize(v);
            return [a, b, v];
        };
        LargeInteger.prototype.modInv = function (prime) {
            var a = this.egcd(prime)[0];
            if (a.sign < 0) {
                return prime.add(a);
            } else {
                return a;
            }
        };
        LargeInteger.prototype.legendre = function (prime) {
            return sli.legendre(this.mod(prime), prime);
        };
        LargeInteger.prototype.modSqrt = function (prime) {
            var res = new LargeInteger(prime.length);
            sli.modsqrt(res, this, prime);
            sli.normalize(res);
            return res;
        };
        LargeInteger.prototype.slice = function (start, end) {
            var value = li.slice(this.value, start, end);
            var sign = this.sign;
            if (li.iszero(value)) {
                sign = 0;
            }
            return new LargeInteger(sign, value);
        };
        LargeInteger.prototype.toByteArray = function (byteSize) {
            var MASK_TOP_8 = 0x80;
            var dense = util.change_wordsize(this.value, li.WORDSIZE, 8);
            if (typeof byteSize === "undefined") {
                li.normalize(dense, MASK_TOP_8);
            } else {
                li.resize(dense, byteSize);
            }
            return dense.reverse();
        };
        LargeInteger.prototype.toByteTree = function () {
            return new verificatum.eio.ByteTree(this.toByteArray());
        };
        LargeInteger.prototype.toHexString = function () {
            return sli.hex(this);
        };
        LargeInteger.INSECURErandom = function (bitLength) {               
            var x = sli.INSECURErandom(bitLength);                         
            return new LargeInteger(x.sign, x.value);                      
        };
        function ModPowProd(bases, modulus) {
            var b = [];
            for (var i = 0; i < bases.length; i++) {
                b[i] = bases[i].value;
            }
            this.width = bases.length;
            this.t = li.modpowprodtab(b, modulus.value);
            this.modulus = modulus;
        };
        ModPowProd.prototype.modPowProd = function (exponents) {
            if (exponents.length !== this.width) {
                throw Error("Wrong number of exponents! (" +
                            exponents.length + " != " + this.width + ")");
            }
            var e = [];
            for (var i = 0; i < exponents.length; i++) {
                e[i] = exponents[i].value;
            }
            var res = new LargeInteger(this.modulus.length);
            li.modpowprod(res.value, this.t, e, this.modulus.value);
            if (li.iszero(res.value)) {
                res.sign = 0;
            } else {
                res.sign = 1;
            }
            li.normalize(res.value);
            return res;
        };
        ModPowProd.naive = function (bases, exponents, modulus) {
            var result = LargeInteger.ONE;
            for (var i = 0; i < bases.length; i++) {
                result = result.modMul(bases[i].modPow(exponents[i], modulus), modulus);
            }
            return result;
        };
        function FixModPow(basis, modulus, size, width) {
            var bitLength = modulus.bitLength();
            if (typeof width === "undefined") {
                width = FixModPow.optimalWidth(bitLength, size);
            }
            this.sliceSize = Math.floor((bitLength + width - 1) / width);
            var powerBasis = LargeInteger.ONE.shiftLeft(this.sliceSize);
            var bases = [];
            bases[0] = basis;
            for (var i = 1; i < width; i++) {
                bases[i] = bases[i - 1].modPow(powerBasis, modulus);
            }
            this.mpp = new ModPowProd(bases, modulus);
        };
        FixModPow.optimalWidth = function (bitLength, size) {
            var width = 2;
            var cost = 1.5 * bitLength;
            var oldCost;
            do {
                oldCost = cost;
                var t = ((1 << width) - width + bitLength) / size;
                var m = bitLength / width;
                cost = t + m;
                width++;
            } while (width <= 16 && cost < oldCost);
            return width - 1;
        };
        FixModPow.prototype.slice = function (exponent) {
            var exponents = [];
            var bitLength = exponent.bitLength();
            var offset = 0;
            var i = 0;
            while (i < this.mpp.width - 1 && offset < bitLength) {
                exponents[i] = exponent.slice(offset, offset + this.sliceSize);
                offset += this.sliceSize;
                i++;
            }
            if (offset < bitLength) {
                exponents[i] = exponent.slice(offset, bitLength);
                offset += this.sliceSize;
                i++;
            }
            while (i < this.mpp.width) {
                exponents[i] = LargeInteger.ZERO;
                i++;
            }
            return exponents;
        };
        FixModPow.prototype.modPow = function (exponent) {
            return this.mpp.modPowProd(this.slice(exponent));
        };
        function PRing() {
        };
        PRing.prototype = Object.create(ArithmObject.prototype);
        PRing.prototype.constructor = PRing;
        PRing.prototype.getPField = function () {
            throw new Error("Abstract method!");
        };
        PRing.prototype.equals = function (other) {
            throw new Error("Abstract method!");
        };
        PRing.prototype.getZERO = function () {
            throw new Error("Abstract method!");
        };
        PRing.prototype.getONE = function () {
            throw new Error("Abstract method!");
        };
        PRing.prototype.randomElementByteLength = function (statDist) {
            throw new Error("Abstract method!");
        };
        PRing.prototype.randomElement = function (randomSource, statDist) {
            throw new Error("Abstract method!");
        };
        PRing.prototype.toElement = function (byteTree) {
            throw new Error("Abstract method!");
        };
        PRing.prototype.getByteLength = function () {
            throw new Error("Abstract method!");
        };
        PRing.prototype.getEncodeLength = function () {
            throw new Error("Abstract method!");
        };
        PRing.prototype.toString = function () {
            throw new Error("Abstract method!");
        };
        function PRingElement(pRing) {
            this.pRing = pRing;
        };
        PRingElement.prototype = Object.create(ArithmObject.prototype);
        PRingElement.prototype.constructor = PRingElement;
        PRingElement.prototype.assertType = function (other) {
            if (other.getName() !== this.getName()) {
                throw Error("Element of wrong class! (" +
                            other.getName() + " != " + this.getName() + ")");
            }
            if (!this.pRing.equals(other.pRing)) {
                throw Error("Distinct rings");
            }
        };
        PRingElement.prototype.getPRing = function () {
            return this.pRing;
        };
        PRingElement.prototype.equals = function (other) {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.neg = function () {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.mul = function (other) {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.add = function (other) {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.sub = function (other) {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.inv = function () {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.toByteTree = function () {
            throw new Error("Abstract method!");
        };
        PRingElement.prototype.toString = function () {
            throw new Error("Abstract method!");
        };
        function PPRingElement(pPRing, values) {
            PRingElement.call(this, pPRing);
            this.values = values;
        };
        PPRingElement.prototype = Object.create(PRingElement.prototype);
        PPRingElement.prototype.constructor = PPRingElement;
        PPRingElement.prototype.equals = function (other) {
            this.assertType(other);
            for (var i = 0; i < this.values.length; i++) {
                if (!this.values[i].equals(other.values[i])) {
                    return false;
                }
            }
            return true;
        };
        PPRingElement.prototype.add = function (other) {
            this.assertType(other);
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].add(other.values[i]);
            }
            return new PPRingElement(this.pRing, values);
        };
        PPRingElement.prototype.sub = function (other) {
            this.assertType(other);
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].sub(other.values[i]);
            }
            return new PPRingElement(this.pRing, values);
        };
        PPRingElement.prototype.neg = function () {
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].neg();
            }
            return new PPRingElement(this.pRing, values);
        };
        PPRingElement.prototype.mul = function (other) {
            var i;
            var values = [];
            if (this.pRing.equals(other.pRing)) {
                for (i = 0; i < this.values.length; i++) {
                    values[i] = this.values[i].mul(other.values[i]);
                }
            } else {
                for (i = 0; i < this.values.length; i++) {
                    values[i] = this.values[i].mul(other);
                }
            }
            return new PPRingElement(this.pRing, values);
        };
        PPRingElement.prototype.inv = function () {
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].inv();
            }
            return new PPRingElement(this.pRing, values);
        };
        PPRingElement.prototype.toByteTree = function () {
            var children = [];
            for (var i = 0; i < this.values.length; i++) {
                children[i] = this.values[i].toByteTree();
            }
            return new verificatum.eio.ByteTree(children);
        };
        PPRingElement.prototype.toString = function () {
            var s = "";
            for (var i = 0; i < this.values.length; i++) {
                s += "," + this.values[i].toString();
            }
            return "(" + s.slice(1) + ")";
        };
        PPRingElement.prototype.project = function (i) {
            return this.values[i];
        };
        function PPRing(value, width) {
            PRing.call(this);
            var values;
            var i;
            if (verificatum.util.ofType(value, "array")) {
                this.pRings = value;
            } else {
                this.pRings = verificatum.util.full(value, width);
            }
            values = [];
            for (i = 0; i < this.pRings.length; i++) {
                values[i] = this.pRings[i].getZERO();
            }
            this.ZERO = new PPRingElement(this, values);
            values = [];
            for (i = 0; i < this.pRings.length; i++) {
                values[i] = this.pRings[i].getONE();
            }
            this.ONE = new PPRingElement(this, values);
            this.byteLength = this.ONE.toByteTree().toByteArray().length;
        };
        PPRing.prototype = Object.create(PRing.prototype);
        PPRing.prototype.constructor = PPRing;
        PPRing.prototype.getPField = function () {
            return this.pRings[0].getPField();
        };
        PPRing.prototype.equals = function (other) {
            if (this === other) {
                return true;
            }
            if (other.getName() !== "PPRing") {
                return false;
            }
            if (this.pRings.length !== other.pRings.length) {
                return false;
            }
            for (var i = 0; i < this.pRings.length; i++) {
                if (!this.pRings[i].equals(other.pRings[i])) {
                    return false;
                }
            }
            return true;
        };
        PPRing.prototype.getZERO = function () {
            return this.ZERO;
        };
        PPRing.prototype.getONE = function () {
            return this.ONE;
        };
        PPRing.prototype.randomElementByteLength = function (statDist) {
            var byteLength = 0;
            for (var i = 0; i < this.pRings.length; i++) {
                byteLength += this.pRings[i].randomElementByteLength(statDist);
            }
            return byteLength;
        };
        PPRing.prototype.randomElement = function (randomSource, statDist) {
            var values = [];
            for (var i = 0; i < this.pRings.length; i++) {
                values[i] = this.pRings[i].randomElement(randomSource, statDist);
            }
            return new PPRingElement(this, values);
        };
        PPRing.prototype.toElement = function (byteTree) {
            if (!byteTree.isLeaf() ||
                byteTree.value.length === this.pRings.length) {
                var children = [];
                for (var i = 0; i < this.pRings.length; i++) {
                    children[i] = this.pRings[i].toElement(byteTree.value[i]);
                }
                return new PPRingElement(this, children);
            } else {
                throw Error("Input byte tree does not represent an element!");
            }
        };
        PPRing.prototype.getByteLength = function () {
            return this.byteLength;
        };
        PPRing.prototype.getEncodeLength = function () {
            return Math.floor((this.order.bitLength() + 1) / 8);
        };
        PPRing.prototype.toString = function () {
            var s = "";
            for (var i = 0; i < this.pRings.length; i++) {
                s += "," + this.pRings[i].toString();
            }
            return "(" + s.slice(1) + ")";
        };
        PPRing.prototype.getWidth = function () {
            return this.pRings.length;
        };
        PPRing.prototype.project = function (i) {
            return this.pRings[i];
        };
        PPRing.prototype.prod = function (value) {
            var i;
            var elements;
            if (verificatum.util.ofType(value, "array")) {
                if (value.length === this.pRings.length) {
                    elements = value;
                } else {
                    throw Error("Wrong number of elements! (" +
                                elements.length + " != " + this.pRings.length + ")");
                }
            } else {
                elements = [];
                for (i = 0; i < this.pRings.length; i++) {
                    elements[i] = value;
                }
            }
            for (i = 0; i < this.pRings.length; i++) {
                if (!elements[i].pRing.equals(this.pRings[i])) {
                    throw Error("Element " + i + " belongs to the wrong subring!");
                }
            }
            return new PPRingElement(this, elements);
        };
        function PFieldElement(pField, value) {
            PRingElement.call(this, pField);
            this.value = value;
        };
        PFieldElement.prototype = Object.create(PRingElement.prototype);
        PFieldElement.prototype.constructor = PFieldElement;
        PFieldElement.prototype.equals = function (other) {
            this.assertType(other);
            return this.value.cmp(other.value) === 0;
        };
        PFieldElement.prototype.neg = function () {
            return new PFieldElement(this.pRing, this.pRing.order.sub(this.value));
        };
        PFieldElement.prototype.mul = function (other) {
            var v;
            if (util.ofType(other, PFieldElement)) {
                v = this.value.modMul(other.value, this.pRing.order);
            } else {
                v = this.value.modMul(other, this.pRing.order);
            }
            return new PFieldElement(this.pRing, v);
        };
        PFieldElement.prototype.add = function (other) {
            this.assertType(other);
            var v = this.value.modAdd(other.value, this.pRing.order);
            return new PFieldElement(this.pRing, v);
        };
        PFieldElement.prototype.sub = function (other) {
            this.assertType(other);
            var v = this.value.modSub(other.value, this.pRing.order);
            return new PFieldElement(this.pRing, v);
        };
        PFieldElement.prototype.inv = function () {
            var v = this.value.modInv(this.pRing.order);
            return new PFieldElement(this.pRing, v);
        };
        PFieldElement.prototype.toByteTree = function () {
            var byteLength = this.pRing.byteLength;
            return new verificatum.eio.ByteTree(this.value.toByteArray(byteLength));
        };
        PFieldElement.prototype.toString = function () {
            return this.value.toHexString();
        };
        function PField(order) {
            PRing.call(this);
            if (typeof order === "number") {
                this.order = new LargeInteger(order.toString(16));
            } else if (util.ofType(order, "string")) {
                this.order = new LargeInteger(order);
            } else {
                this.order = order;
            }
            this.bitLength = this.order.bitLength();
            this.byteLength = this.order.toByteArray().length;
        };
        PField.prototype = Object.create(PRing.prototype);
        PField.prototype.constructor = PField;
        PField.prototype.getPField = function () {
            return this;
        };
        PField.prototype.equals = function (other) {
            if (this === other) {
                return true;
            }
            if (other.getName() !== "PField") {
                return false;
            }
            return this.order.equals(other.order);
        };
        PField.prototype.getZERO = function () {
            return new PFieldElement(this, LargeInteger.ZERO);
        };
        PField.prototype.getONE = function () {
            return new PFieldElement(this, LargeInteger.ONE);
        };
        PField.prototype.randomElementByteLength = function (statDist) {
            return LargeInteger.byteLengthRandom(this.bitLength + statDist);
        };
        PField.prototype.randomElement = function (randomSource, statDist) {
            var r = new LargeInteger(this.bitLength + statDist, randomSource);
            return new PFieldElement(this, r.mod(this.order));
        };
        PField.prototype.toElement = function (param) {
            var integer;
            if (util.ofType(param, eio.ByteTree) &&
                param.isLeaf() &&
                param.value.length === this.getByteLength()) {
                integer = new LargeInteger(param.value);
            } else {
                integer = new LargeInteger(param);
            }
            return new PFieldElement(this, integer.mod(this.order));
        };
        PField.prototype.getByteLength = function () {
            return this.byteLength;
        };
        PField.prototype.getEncodeLength = function () {
            return Math.floor((this.order.bitLength() - 1) / 8);
        };
        PField.prototype.toString = function () {
            return this.order.toHexString();
        };
        var ec = (function () {
            var affine_raw = (function () {
                var I = new sli.SLI();
                var II = new sli.SLI();
                var III = new sli.SLI();
                return function (curve, A) {
                    if (I.length !== curve.length) {
                        sli.resize(I, curve.length);
                        sli.resize(II, curve.length);
                        sli.resize(III, curve.length);
                    }
                    if (!sli.iszero(A.z)) {
                        sli.modinv(I, A.z, curve.modulus); 
                        sli.mul(II, I, I);                 
                        sli.mod(II, II, curve.modulus);
                        sli.mul(III, II, I);               
                        sli.mod(III, III, curve.modulus);
                        sli.mul(A.x, A.x, II);             
                        sli.mod(A.x, A.x, curve.modulus);
                        sli.mul(A.y, A.y, III);            
                        sli.mod(A.y, A.y, curve.modulus);
                        sli.set(A.z, 1);                   
                    }
                };
            })();
            var jadd_generic = (function () {
                var t1 = new sli.SLI();
                var t2 = new sli.SLI();
                var t3 = new sli.SLI();
                var U1 = new sli.SLI();
                var U2 = new sli.SLI();
                var S1 = new sli.SLI();
                var S2 = new sli.SLI();
                var H = new sli.SLI();
                var r = new sli.SLI();
                return function (curve, A, B, C) {
                    var modulus = curve.modulus;
                    var len = curve.length;
                    if (t1.length !== len) {
                        sli.resize(t1, len);
                        sli.resize(t2, len);
                        sli.resize(t3, len);
                        sli.resize(U1, len);
                        sli.resize(U2, len);
                        sli.resize(S1, len);
                        sli.resize(S2, len);
                        sli.resize(H, len);
                        sli.resize(r, len);
                    }
                    if (sli.iszero(B.z)) {
                        if (sli.iszero(C.z)) {
                            curve.setzero(A);
                            return;
                        } else {
                            curve.set(A, C);
                            return;
                        }
                    } else if (sli.iszero(C.z)) {
                        curve.set(A, B);
                        return;
                    }
                    sli.mul(t1, C.z, C.z);                 
                    sli.mod(t1, t1, modulus);
                    sli.mul(S2, t1, C.z);                  
                    sli.mod(S2, S2, modulus);
                    sli.mul(t2, B.z, B.z);                 
                    sli.mod(t2, t2, modulus);
                    sli.mul(t3, t2, B.z);                  
                    sli.mod(t3, t3, modulus);
                    sli.mul(U1, B.x, t1);
                    sli.mod(U1, U1, modulus);
                    sli.mul(U2, C.x, t2);
                    sli.mul(S1, B.y, S2);
                    sli.mod(S1, S1, modulus);
                    sli.mul(S2, C.y, t3);
                    sli.sub(H, U2, U1);
                    sli.mod(H, H, modulus);
                    sli.sub(r, S2, S1);
                    sli.mod(r, r, modulus);
                    if (sli.iszero(H)) {
                        if (sli.iszero(r)) {
                            curve.jdbl_raw(curve, A, B);
                            return;
                        } else {
                            curve.setzero(A);
                            return;
                        }
                    }
                    sli.mul(t1, r, r);                     
                    sli.mod(t1, t1, modulus);
                    sli.mul(t2, H, H);                     
                    sli.mod(t2, t2, modulus);
                    sli.mul(t3, t2, H);                    
                    sli.mod(t3, t3, modulus);
                    sli.sub(A.x, t1, t3);                  
                    sli.mul(t1, U1, t2);                   
                    sli.shiftleft(t1, 1);                  
                    sli.mod(t1, t1, modulus);
                    sli.sub(A.x, A.x, t1);
                    sli.mod(A.x, A.x, modulus);
                    sli.mul(t1, U1, t2);                   
                    sli.mod(t1, t1, modulus);
                    sli.sub(t1, t1, A.x);
                    sli.mul(t1, r, t1);
                    sli.mod(t1, t1, modulus);
                    sli.mul(t2, S1, t3);                   
                    sli.mod(t2, t2, modulus);
                    sli.sub(A.y, t1, t2);
                    sli.mod(A.y, A.y, modulus);
                    sli.mul(A.z, B.z, C.z);
                    sli.mod(A.z, A.z, modulus);
                    sli.mul(A.z, A.z, H);
                    sli.mod(A.z, A.z, modulus);
                };
            })();
            var jdbl_generic = (function () {
                var t1 = new sli.SLI();
                var t2 = new sli.SLI();
                var t3 = new sli.SLI();
                var S = new sli.SLI();
                var M = new sli.SLI();
                var T = new sli.SLI();
                return function (curve, A, B) {
                    var modulus = curve.modulus;
                    var len = curve.length;
                    if (t1.length !== len) {
                        sli.resize(t1, len);
                        sli.resize(t2, len);
                        sli.resize(t3, len);
                        sli.resize(S, len);
                        sli.resize(M, len);
                        sli.resize(T, len);
                    }
                    if (sli.iszero(B.z) || sli.iszero(B.y)) {
                        curve.setzero(A);
                        return;
                    }
                    sli.mul(S, B.y, B.y);
                    sli.mod(S, S, modulus);
                    sli.mul(S, S, B.x);
                    sli.shiftleft(S, 2);                   
                    sli.mod(S, S, modulus);
                    sli.mul(t2, B.z, B.z);                 
                    sli.mod(t2, t2, modulus);
                    sli.mul(t1, B.x, B.x);                 
                    sli.mod(t1, t1, modulus);
                    sli.mul_number(t1, t1, 3);
                    sli.mod(t1, t1, modulus);
                    sli.mul(t3, t2, t2);                   
                    sli.mod(t3, t3, modulus);
                    sli.mul(t3, t3, curve.a);
                    sli.mod(t3, t3, modulus);
                    sli.add(M, t1, t3);
                    sli.mod(M, M, modulus);
                    sli.mul(T, M, M);
                    sli.set(t2, S);                        
                    sli.shiftleft(t2, 1);
                    sli.sub(T, T, t2);
                    sli.mod(T, T, modulus);
                    sli.set(A.x, T);
                    sli.sub(t1, S, T);                     
                    sli.mul(t1, t1, M);
                    sli.mod(t1, t1, modulus);
                    sli.mul(t2, B.y, B.y);                 
                    sli.mod(t2, t2, modulus);
                    sli.mul(t2, t2, t2);
                    sli.mod(t2, t2, modulus);
                    sli.shiftleft(t2, 3);                  
                    sli.mod(t2, t2, modulus);
                    sli.sub(t1, t1, t2);
                    sli.mul(t2, B.y, B.z);
                    sli.shiftleft(t2, 1);                  
                    sli.mod(A.y, t1, modulus);
                    sli.mod(A.z, t2, modulus);
                };
            })();
            var jdbl_a_eq_neg3 = (function () {
                var t1 = new sli.SLI();
                var t2 = new sli.SLI();
                var t3 = new sli.SLI();
                var alpha = new sli.SLI();
                var beta = new sli.SLI();
                var gamma = new sli.SLI();
                var delta = new sli.SLI();
                return function (curve, A, B) {
                    var modulus = curve.modulus;
                    var len = curve.length;
                    if (t1.length !== len) {
                        sli.resize(t1, len);
                        sli.resize(t2, len);
                        sli.resize(t3, len);
                        sli.resize(alpha, len);
                        sli.resize(beta, len);
                        sli.resize(gamma, len);
                        sli.resize(delta, len);
                    }
                    if (sli.iszero(B.z) || sli.iszero(B.y)) {
                        curve.setzero(A);
                        return;
                    }
                    sli.mul(delta, B.z, B.z);
                    sli.mod(delta, delta, modulus);
                    sli.mul(gamma, B.y, B.y);
                    sli.mod(gamma, gamma, modulus);
                    sli.mul(beta, B.x, gamma);
                    sli.mod(beta, beta, modulus);
                    sli.sub(t1, B.x, delta);
                    sli.add(t2, B.x, delta);
                    sli.mul_number(t1, t1, 3);
                    sli.mul(alpha, t1, t2);
                    sli.mod(alpha, alpha, modulus);
                    sli.mul(t1, alpha, alpha);
                    sli.set(t2, beta);                  
                    sli.shiftleft(t2, 3);
                    sli.sub(A.x, t1, t2);
                    sli.mod(A.x, A.x, modulus);
                    sli.add(t1, B.y, B.z);
                    sli.mul(t1, t1, t1);
                    sli.sub(t1, t1, gamma);
                    sli.sub(t1, t1, delta);
                    sli.mod(A.z, t1, modulus);
                    sli.set(t1, beta);                  
                    sli.shiftleft(t1, 2);
                    sli.sub(t1, t1, A.x);
                    sli.mul(t1, t1, alpha);
                    sli.mul(t2, gamma, gamma);
                    sli.shiftleft(t2, 3);               
                    sli.sub(A.y, t1, t2);
                    sli.mod(A.y, A.y, modulus);
                };
            })();
            var jmul_naive = function (curve, A, B, e) {
                var n = li.msbit(e.value);
                curve.setzero(A);
                for (var i = n; i >= 0; i--) {
                    curve.jdbl(A, A);
                    if (li.getbit(e.value, i) === 1) {
                        curve.jadd(A, A, B);
                    }
                }
            };
            function EC(modulus, a, b) {
                this.modulus = modulus;
                this.length = 2 * this.modulus.value.length + 4;
                this.a = a;
                this.b = b;
                var three = new sli.SLI(1, [3]);
                var t = new sli.SLI(modulus.length + 1);
                sli.add(t, this.a, three);
                if (sli.equals(this.modulus, t)) {
                    this.jdbl_raw = jdbl_a_eq_neg3;
                } else {
                    this.jdbl_raw = jdbl_generic;
                }
            };
            function ECP(len, x, y, z) {
                if (typeof x === "undefined") {
                    this.x = new sli.SLI(len);
                    this.y = new sli.SLI(len);
                    this.z = new sli.SLI(len);
                } else {
                    this.x = sli.copy(x, len);
                    this.y = sli.copy(y, len);
                    this.z = sli.copy(z, len);
                }
            };
            EC.prototype.affine = function (A) {
                affine_raw(this, A);
            };
            EC.prototype.equals = function (A, B) {
                this.affine(A);
                this.affine(B);
                return sli.cmp(A.x, B.x) === 0 &&
                    sli.cmp(A.y, B.y) === 0 &&
                    sli.cmp(A.z, B.z) === 0;
            };
            EC.prototype.set = function (A, B) {
                sli.set(A.x, B.x);
                sli.set(A.y, B.y);
                sli.set(A.z, B.z);
            };
            EC.prototype.setzero = function (A) {
                sli.set(A.x, 0);
                sli.set(A.y, 1);
                sli.set(A.z, 0);
            };
            EC.prototype.neg = function (A, B) {
                if (sli.iszero(B.z) || sli.iszero(B.y)) {
                    this.set(A, B);
                } else {
                    sli.set(A.x, B.x);
                    sli.sub(A.y, this.modulus, B.y);
                    sli.set(A.z, B.z);
                }
            };
            EC.prototype.jadd = function (A, B, C) {
                jadd_generic(this, A, B, C);
            };
            EC.prototype.jdbl = function (A, B) {
                this.jdbl_raw(this, A, B);
            };
            EC.prototype.jmul = function (A, B, e) {
                jmul_naive(this, A, B, e);
            };
            return {
                "EC": EC,
                "ECP": ECP
            };
        })();
        function PGroup(pRing) {
            this.pRing = pRing;
        };
        PGroup.prototype = Object.create(ArithmObject.prototype);
        PGroup.prototype.constructor = PGroup;
        PGroup.getPGroup = function (groupName) {
            var pGroup = ModPGroup.getPGroup(groupName);
            if (pGroup !== null) {
                return pGroup;
            }
            pGroup = ECqPGroup.getPGroup(groupName);
            if (pGroup !== null) {
                return pGroup;
            }
            throw Error("Unknown group name! (" + groupName + ")");
        };
        PGroup.getWideGroup = function (pGroup, keyWidth) {
            if (keyWidth > 1) {
                return new verificatum.arithm.PPGroup(pGroup, keyWidth);
            } else {
                return pGroup;
            }
        };
        PGroup.prototype.getPrimeOrderPGroup = function () {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.equals = function (other) {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.getElementOrder = function () {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.getg = function () {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.getONE = function () {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.toElement = function (byteTree) {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.encode = function (bytes, startIndex, length) {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.randomElement = function (randomSource, statDist) {
            throw new Error("Abstract method!");
        };
        PGroup.prototype.getEncodeLength = function () {
            return this.encodeLength;
        };
        PGroup.prototype.benchExp = function (minSamples, exps, randomSource) {
            var g = this.getg();
            var e = this.pRing.randomElement(randomSource, 50);
            g = g.exp(e);
            var fixed = exps > 0;
            exps = Math.max(1, exps);
            var start = util.time_ms();
            for (var i = 0; i < minSamples; i++) {
                if (fixed) {
                    g.fixed(exps);
                }
                for (var j = 0; j < exps; j++) {
                    e = this.pRing.randomElement(randomSource, 50);
                    var y = g.exp(e);
                }
            }
            return (util.time_ms() - start) / (exps * minSamples);
        };
        PGroup.prototype.benchFixExp = function (minSamples, exps, randomSource) {
            var results = [];
            for (var i = 0; i < exps.length; i++) {
                results[i] = this.benchExp(minSamples, exps[i], randomSource);
            }
            return results;
        };
        PGroup.benchExp = function (pGroups, minSamples, randomSource) {
            var results = [];
            for (var i = 0; i < pGroups.length; i++) {
                results[i] = pGroups[i].benchExp(minSamples, 0, randomSource);
            }
            return results;
        };
        PGroup.benchFixExp = function (pGroups, minSamples, exps, randomSource) {
            var results = [];
            for (var i = 0; i < pGroups.length; i++) {
                results[i] = pGroups[i].benchFixExp(minSamples, exps, randomSource);
            }
            return results;
        };
        function PGroupElement(pGroup) {
            this.pGroup = pGroup;
            this.fixExp = null;
            this.expCounter = 0;
        };
        PGroupElement.prototype = Object.create(ArithmObject.prototype);
        PGroupElement.prototype.constructor = PGroupElement;
        PGroupElement.prototype.assertType = function (other) {
            if (other.getName() !== this.getName()) {
                throw Error("Element of wrong class! (" +
                            other.getName() + " != " + this.getName() + ")");
            }
            if (!this.pGroup.equals(other.pGroup)) {
                throw Error("Distinct groups!");
            }
        };
        PGroupElement.prototype.equals = function (other) {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.mul = function (other) {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.exp = function (exponent) {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.inv = function () {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.toByteTree = function () {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.toString = function () {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.decode = function (destination, startIndex) {
            throw new Error("Abstract method!");
        };
        PGroupElement.prototype.fixed = function (exps) {
        };
        function ModPGroupElement(pGroup, value) {
            PGroupElement.call(this);
            this.pGroup = pGroup;
            this.value = value;
        };
        ModPGroupElement.prototype = Object.create(PGroupElement.prototype);
        ModPGroupElement.prototype.constructor = ModPGroupElement;
        ModPGroupElement.prototype.equals = function (other) {
            this.assertType(other);
            return this.value.equals(other.value);
        };
        ModPGroupElement.prototype.mul = function (factor) {
            this.assertType(factor);
            var value = this.value.mul(factor.value).mod(this.pGroup.modulus);
            return new ModPGroupElement(this.pGroup, value);
        };
        ModPGroupElement.prototype.fixed = function (exponentiations) {
            this.fixExp =
                new FixModPow(this.value, this.pGroup.modulus, exponentiations);
        };
        ModPGroupElement.prototype.exp = function (exponent) {
            this.expCounter++;
            if (exponent.constructor === PFieldElement) {
                exponent = exponent.value;
            }
            if (this.fixExp === null) {
                var value = this.value.modPow(exponent, this.pGroup.modulus);
                return new ModPGroupElement(this.pGroup, value);
            } else {
                return new ModPGroupElement(this.pGroup, this.fixExp.modPow(exponent));
            }
        };
        ModPGroupElement.prototype.inv = function () {
            var invValue = this.value.modInv(this.pGroup.modulus);
            return new ModPGroupElement(this.pGroup, invValue);
        };
        ModPGroupElement.prototype.toByteTree = function () {
            var byteArray = this.value.toByteArray(this.pGroup.modulusByteLength);
            return new eio.ByteTree(byteArray);
        };
        ModPGroupElement.prototype.toString = function () {
            return this.value.toHexString();
        };
        function ModPGroup(modulus, order, gi, encoding) {
            PGroup.call(this, ModPGroup.genPField(modulus, order));
            if (typeof order === "undefined") {
                var params = ModPGroup.getParams(modulus);
                this.modulus = new LargeInteger(params[0]);
                gi = new LargeInteger(params[1]);
                this.encoding = 1;
            } else {
                this.modulus = modulus;
                this.encoding = encoding;
            }
            this.generator = new ModPGroupElement(this, gi);
            this.modulusByteLength = this.modulus.toByteArray().length;
            this.ONE = new ModPGroupElement(this, LargeInteger.ONE);
            if (this.encoding === 0) {
                throw Error("RO encoding is not supported!");
            } else if (this.encoding === 1) {
                this.encodeLength = Math.floor((this.modulus.bitLength() - 2) / 8) - 4;
            } else if (this.encoding === 2) {
                throw Error("Subgroup encoding is not supported!");
            } else {
                throw new Error("Unsupported encoding! (" + this.encoding + ")");
            }
        };
        ModPGroup.prototype = Object.create(PGroup.prototype);
        ModPGroup.prototype.constructor = ModPGroup;
        ModPGroup.genPField = function (groupName, order) {
            if (typeof order === "undefined") {
                var params = ModPGroup.getParams(groupName);
                if (params.length < 4) {
                    var modulus = new LargeInteger(params[0]);
                    order = modulus.sub(LargeInteger.ONE).div(LargeInteger.TWO);
                } else {
                    order = new LargeInteger(params[3]);
                }
            }
            return new PField(order);
        };
        ModPGroup.fromByteTree = function (byteTree) {
            if (byteTree.isLeaf()) {
                throw Error("Byte tree is a leaf, expected four children!");
            }
            if (byteTree.value.length !== 4) {
                throw Error("Wrong number of children! (" +
                            byteTree.value.length + " !== 4)");
            }
            var modulus = new LargeInteger(byteTree.value[0]);
            var order = new LargeInteger(byteTree.value[1]);
            var gi = new LargeInteger(byteTree.value[2]);
            byteTree = byteTree.value[3];
            if (!byteTree.isLeaf() || byteTree.value.length !== 4) {
                throw Error("Malformed encoding number!");
            }
            var encoding = util.readUint32FromByteArray(byteTree.value);
            if (encoding >= 4) {
                throw Error("Unsupported encoding number!");
            }
            return new ModPGroup(modulus, order, gi, encoding);
        };
        ModPGroup.getPGroupNames = function () {
            return Object.keys(ModPGroup.named_groups);
        };
        ModPGroup.getPGroup = function (groupName) {
            var params = ModPGroup.named_groups[groupName];
            if (typeof params === "undefined") {
                return null;
            } else {
                return new ModPGroup(groupName);
            }
        };
        ModPGroup.getPGroups = function () {
            var pGroupNames = ModPGroup.getPGroupNames();
            var pGroups = [];
            for (var i = 0; i < pGroupNames.length; i++) {
                pGroups[i] = new ModPGroup(pGroupNames[i]);
            }
            return pGroups;
        };
        ModPGroup.named_groups = {
            "modp768":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
             "02"],
            "modp1024":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
             "02"],
            "modp1536":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
             "02"],
            "modp2048":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
             "02"],
            "modp3072":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
             "02"],
            "modp4096":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
             "02"],
            "modp6144":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
             "02"],
            "modp8192":
            ["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF",
             "02"]
        };
        ModPGroup.getParams = function (groupName) {
            var params = ModPGroup.named_groups[groupName];
            if (typeof params === "undefined") {
                throw Error("Unknown group name! (" + groupName + ")");
            } else {
                return params;
            }
        };
        ModPGroup.prototype.getPrimeOrderPGroup = function () {
            return this;
        };
        ModPGroup.prototype.equals = function (other) {
            if (this === other) {
                return true;
            }
            if (other.getName() !== "ModPGroup") {
                return false;
            }
            return this.modulus.equals(other.modulus) &&
                this.generator.equals(other.generator) &&
                this.encoding === other.encoding;
        };
        ModPGroup.prototype.getElementOrder = function () {
            return this.pRing.order;
        };
        ModPGroup.prototype.getg = function () {
            return this.generator;
        };
        ModPGroup.prototype.getONE = function () {
            return this.ONE;
        };
        ModPGroup.prototype.toElement = function (byteTree) {
            if (!byteTree.isLeaf()) {
                throw Error("Byte tree is not a leaf!");
            }
            if (byteTree.value.length !== this.modulusByteLength) {
                throw Error("Wrong number of bytes! (" +
                            byteTree.value.length + " = " +
                            this.modulusByteLength + ")");
            }
            var value = new LargeInteger(byteTree.value);
            if (this.modulus.cmp(value) <= 0) {
                throw Error("Integer representative not canonically reduced!");
            }
            return new ModPGroupElement(this, value);
        };
        ModPGroup.prototype.encode = function (bytes, startIndex, length) {
            var elen = this.encodeLength;
            if (length > elen) {
                throw Error("Input is too long! (" + length + " > " + elen + ")");
            }
            var bytesToUse = [];
            bytesToUse.length = elen + 4;
            verificatum.util.setUint32ToByteArray(bytesToUse, length, 0);
            var i = startIndex;
            var j = 4;
            while (j < length + 4) {
                bytesToUse[j] = bytes[i];
                i++;
                j++;
            }
            while (j < bytesToUse.length) {
                bytesToUse[j] = 0;
                j++;
            }
            if (length === 0) {
                bytesToUse[5] = 1;
            }
            var value = new LargeInteger(bytesToUse);
            if (value.legendre(this.modulus) !== 1) {
                value = this.modulus.sub(value);
            }
            return new ModPGroupElement(this, value);
        };
        ModPGroup.prototype.randomElement = function (randomSource, statDist) {
            var bits = 8 * this.modulusByteLength + statDist;
            var r = new LargeInteger(bits, randomSource);
            return new ModPGroupElement(this, r.mod(this.modulus));
        };
        ModPGroup.prototype.toString = function () {
            return this.modulus.toHexString() + ":" +
                this.getElementOrder().toHexString() + ":" +
                this.generator.toString() + ":encoding(" + this.encoding + ")";
        };
        PGroupElement.prototype.decode = function (destination, startIndex) {
            var i;
            var j;
            var val = this.pGroup.modulus.sub(this.value);
            if (this.value.cmp(val) < 0) {
                val = this.value;
            }
            var bytes = val.toByteArray();
            var ulen = this.pGroup.encodeLength + 4;
            if (bytes.length > ulen) {
                bytes = bytes.slice(bytes.length - ulen);
            }
            if (bytes.length < ulen) {
                var raw = [];
                i = 0;
                while (i < ulen - bytes.length) {
                    raw[i] = 0;
                    i++;
                }
                j = 0;
                while (j < bytes.length) {
                    raw[i] = bytes[j];
                    i++;
                    j++;
                }
                bytes = raw;
            }
            var len = verificatum.util.readUint32FromByteArray(bytes, 0);
            if (len < 0 || this.pGroup.encodeLength < len) {
                throw Error("Illegal length of data! (" + len + ")");
            }
            i = startIndex;
            j = 4;
            while (j < len + 4) {
                destination[i] = bytes[j];
                i++;
                j++;
            }
            return len;
        };
        function ECqPGroupElement(pGroup, x, y, z) {
            PGroupElement.call(this, pGroup);
            if (typeof y === "undefined") {
                this.value = x;
            } else {
                if (typeof z === "undefined") {
                    z = LargeInteger.ONE;
                }
                this.value = new ec.ECP(pGroup.curve.length, x, y, z);
            }
        };
        ECqPGroupElement.prototype = Object.create(PGroupElement.prototype);
        ECqPGroupElement.prototype.constructor = ECqPGroupElement;
        ECqPGroupElement.prototype.equals = function (other) {
            return this.pGroup.curve.equals(this.value, other.value);
        };
        ECqPGroupElement.prototype.mul = function (factor) {
            var A = new ec.ECP(this.pGroup.curve.length);
            var B = this.value;
            var C = factor.value;
            this.pGroup.curve.jadd(A, B, C);
            return new ECqPGroupElement(this.pGroup, A);
        };
        ECqPGroupElement.prototype.square = function () {
            var A = new ec.ECP(this.pGroup.curve.length);
            var B = this.value;
            this.pGroup.curve.jdbl(A, B);
            return new ECqPGroupElement(this.pGroup, A);
        };
        ECqPGroupElement.prototype.exp = function (exponent) {
            this.expCounter++;
            var A = new ec.ECP(this.pGroup.curve.length);
            var B = this.value;
            if (exponent.constructor === PFieldElement) {
                exponent = exponent.value;
            }
            this.pGroup.curve.jmul(A, B, exponent);
            return new ECqPGroupElement(this.pGroup, A);
        };
        ECqPGroupElement.prototype.inv = function () {
            var A = new ec.ECP(this.pGroup.curve.length);
            var B = this.value;
            this.pGroup.curve.neg(A, B);
            return new ECqPGroupElement(this.pGroup, A);
        };
        ECqPGroupElement.prototype.toByteTree = function () {
            var len = this.pGroup.modulusByteLength;
            this.pGroup.curve.affine(this.value);
            if (sli.iszero(this.value.z)) {
                var FF = verificatum.util.full(0xFF, len);
                return new verificatum.eio.ByteTree([new verificatum.eio.ByteTree(FF),
                                                     new verificatum.eio.ByteTree(FF)]);
            } else {
                var x = new LargeInteger(this.value.x.sign, this.value.x.value);
                var y = new LargeInteger(this.value.y.sign, this.value.y.value);
                var xbt = new verificatum.eio.ByteTree(x.toByteArray(len));
                var ybt = new verificatum.eio.ByteTree(y.toByteArray(len));
                return new verificatum.eio.ByteTree([xbt, ybt]);
            }
        };
        ECqPGroupElement.prototype.toString = function () {
            this.pGroup.curve.affine(this.value);
            if (sli.iszero(this.value.z)) {
                return "(O)";
            } else {
                var xs = sli.hex(this.value.x);
                var ys = sli.hex(this.value.y);
                return "(" + xs + "," + ys + ")";
            }
        };
        ECqPGroupElement.prototype.decode = function (destination, startIndex) {
            this.pGroup.curve.affine(this.value);
            if (sli.iszero(this.value.z)) {
                return 0;
            } else {
                var x = new LargeInteger(this.value.x.sign, this.value.x.value);
                var elen = this.pGroup.encodeLength;
                var xbytes = x.toByteArray(elen + 3);
                var len = verificatum.util.readUint16FromByteArray(xbytes, elen);
                var i = startIndex;
                var j = this.pGroup.encodeLength - len;
                while (j < this.pGroup.encodeLength) {
                    destination[i] = xbytes[j];
                    i++;
                    j++;
                }
                return len;
            }
        };
        function ECqPGroup(modulus, a, b, gx, gy, n) {
            PGroup.call(this, ECqPGroup.genPField(modulus, n));
            if (typeof a === "undefined") {
                var params = ECqPGroup.getParams(modulus);
                modulus = new LargeInteger(params[0]);
                a = new LargeInteger(params[1]);
                b = new LargeInteger(params[2]);
                gx = new LargeInteger(params[3]);
                gy = new LargeInteger(params[4]);
                n = new LargeInteger(params[5]);
            }
            this.curve = new verificatum.arithm.ec.EC(modulus, a, b);
            this.generator = new ECqPGroupElement(this, gx, gy);
            this.ONE = new ECqPGroupElement(this,
                                            LargeInteger.ZERO,
                                            LargeInteger.ONE,
                                            LargeInteger.ZERO);
            this.modulusByteLength = modulus.toByteArray().length;
            this.encodeLength = Math.floor((modulus.bitLength() - 1) / 8) - 3;
        };
        ECqPGroup.prototype = Object.create(PGroup.prototype);
        ECqPGroup.prototype.constructor = ECqPGroup;
        ECqPGroup.prototype.getEncodeLength = function () {
            return this.encodeLength;
        };
        ECqPGroup.prototype.equals = function (other) {
            if (this === other) {
                return true;
            }
            if (other.getName() !== "ECqPGroup") {
                return false;
            }
            return this.curve.modulus.equals(other.curve.modulus) &&
                this.curve.a.equals(other.curve.a) &&
                this.curve.b.equals(other.curve.b) &&
                this.getg().equals(other.getg());
        };
        ECqPGroup.genPField = function (curveName, n) {
            if (typeof n === "undefined") {
                var params = ECqPGroup.getParams(curveName);
                return new PField(new LargeInteger(params[5]));
            } else {
                return new PField(n);
            }
        };
        ECqPGroup.getParams = function (curveName) {
            var params = ECqPGroup.named_curves[curveName];
            if (typeof params === "undefined") {
                throw Error("Unknown curve name! (" + curveName + ")");
            } else {
                return params;
            }
        };
        ECqPGroup.getPGroupNames = function () {
            return Object.keys(ECqPGroup.named_curves);
        };
        ECqPGroup.getPGroup = function (groupName) {
            var params = ECqPGroup.named_curves[groupName];
            if (typeof params === "undefined") {
                return null;
            } else {
                return new ECqPGroup(groupName);
            }
        };
        ECqPGroup.getPGroups = function () {
            var pGroupNames = ECqPGroup.getPGroupNames();
            var pGroups = [];
            for (var i = 0; i < pGroupNames.length; i++) {
                pGroups[i] = new ECqPGroup(pGroupNames[i]);
            }
            return pGroups;
        };
        ECqPGroup.named_curves = {
            "prime192v1":
            ["fffffffffffffffffffffffffffffffeffffffffffffffff",
             "fffffffffffffffffffffffffffffffefffffffffffffffc",
             "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
             "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
             "7192b95ffc8da78631011ed6b24cdd573f977a11e794811",
             "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
             "1"],
            "prime192v2":
            ["fffffffffffffffffffffffffffffffeffffffffffffffff",
             "fffffffffffffffffffffffffffffffefffffffffffffffc",
             "cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953",
             "eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a",
             "6574d11d69b6ec7a672bb82a083df2f2b0847de970b2de15",
             "fffffffffffffffffffffffe5fb1a724dc80418648d8dd31",
             "1"],
            "prime192v3":
            ["fffffffffffffffffffffffffffffffeffffffffffffffff",
             "fffffffffffffffffffffffffffffffefffffffffffffffc",
             "22123dc2395a05caa7423daeccc94760a7d462256bd56916",
             "7d29778100c65a1da1783716588dce2b8b4aee8e228f1896",
             "38a90f22637337334b49dcb66a6dc8f9978aca7648a943b0",
             "ffffffffffffffffffffffff7a62d031c83f4294f640ec13",
             "1"],
            "prime256v1":
            ["ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
             "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
             "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
             "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
             "1"],
            "prime239v1":
            ["7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
             "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
             "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
             "ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
             "7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae",
             "7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b",
             "1"],
            "prime239v3":
            ["7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
             "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
             "255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e",
             "6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a",
             "1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3",
             "7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551",
             "1"],
            "secp192k1":
            ["fffffffffffffffffffffffffffffffffffffffeffffee37",
             "0",
             "3",
             "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
             "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
             "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
             "1"],
            "secp192r1":
            ["fffffffffffffffffffffffffffffffeffffffffffffffff",
             "fffffffffffffffffffffffffffffffefffffffffffffffc",
             "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
             "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
             "7192b95ffc8da78631011ed6b24cdd573f977a11e794811",
             "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
             "1"],
            "secp224k1":
            ["fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d",
             "0",
             "5",
             "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
             "7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5",
             "10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
             "1"],
            "secp224r1":
            ["ffffffffffffffffffffffffffffffff000000000000000000000001",
             "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
             "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
             "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
             "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
             "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
             "1"],
            "secp256k1":
            ["fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
             "0",
             "7",
             "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
             "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
             "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
             "1"],
            "secp256r1":
            ["ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
             "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
             "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
             "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
             "1"],
            "secp384r1":
            ["fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
             "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
             "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
             "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
             "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
             "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
             "1"],
            "secp521r1":
            ["1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
             "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
             "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
             "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
             "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
             "1"],
            "brainpoolp192r1":
            ["c302f41d932a36cda7a3463093d18db78fce476de1a86297",
             "6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
             "469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
             "c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
             "14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
             "c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
             "1"],
            "brainpoolp224r1":
            ["d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
             "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
             "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
             "d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
             "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
             "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
             "1"],
            "brainpoolp256r1":
            ["a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
             "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
             "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
             "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
             "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
             "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
             "1"],
            "brainpoolp320r1":
            ["d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
             "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
             "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
             "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
             "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
             "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
             "1"],
            "brainpoolp384r1":
            ["8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
             "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
             "4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
             "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
             "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
             "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
             "1"],
            "brainpoolp512r1":
            ["aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
             "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
             "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
             "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
             "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
             "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
             "1"],
            "P-192":
            ["fffffffffffffffffffffffffffffffeffffffffffffffff",
             "fffffffffffffffffffffffffffffffefffffffffffffffc",
             "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
             "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
             "7192b95ffc8da78631011ed6b24cdd573f977a11e794811",
             "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
             "1"],
            "P-224":
            ["ffffffffffffffffffffffffffffffff000000000000000000000001",
             "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
             "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
             "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
             "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
             "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
             "1"],
            "P-256":
            ["ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
             "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
             "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
             "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
             "1"],
            "P-384":
            ["fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
             "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
             "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
             "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
             "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
             "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
             "1"],
            "P-521":
            ["1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
             "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
             "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
             "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
             "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
             "1"]
        };
        ECqPGroup.fromByteTree = function (byteTree) {
            if (!byteTree.isLeaf()) {
                throw Error("Byte tree is not a leaf!");
            }
            var curveName = verificatum.util.byteArrayToAscii(byteTree.value);
            return new ECqPGroup(curveName);
        };
        ECqPGroup.prototype.getPrimeOrderPGroup = function () {
            return this;
        };
        ECqPGroup.prototype.f = function (x) {
            var p = this.curve.modulus;
            var x3 = x.mul(x).mod(p).mul(x).mod(p);
            var ax = this.curve.a.mul(x).mod(p);
            return x3.add(ax).add(this.curve.b).mod(p);
        };
        ECqPGroup.prototype.isOnCurve = function (x, y) {
            var fx = this.f(x);
            var y2 = y.mul(y).mod(this.curve.modulus);
            return fx.equals(y2);
        };
        ECqPGroup.prototype.getElementOrder = function () {
            return this.pRing.order;
        };
        ECqPGroup.prototype.getg = function () {
            return this.generator;
        };
        ECqPGroup.prototype.getONE = function () {
            return this.ONE;
        };
        ECqPGroup.prototype.toElement = function (byteTree) {
            if (byteTree.isLeaf()) {
                throw Error("Byte tree is a leaf, expected a node!");
            } else if (byteTree.value.length !== 2 ||
                       !byteTree.value[0].isLeaf() ||
                       !byteTree.value[1].isLeaf()) {
                throw Error("Byte tree does not have 2 leaves!");
            } else {
                var xa = byteTree.value[0].value;
                var ya = byteTree.value[1].value;
                if (xa.length !== this.modulusByteLength ||
                    ya.length !== this.modulusByteLength) {
                    throw Error("A coordinate array has the wrong length!");
                } else {
                    for (var i = 0; i < xa.length; i++) {
                        if (xa[i] !== 0xFF || ya[i] !== 0xFF) {
                            var x = new LargeInteger(xa);
                            var y = new LargeInteger(ya);
                            return new ECqPGroupElement(this, x, y);
                        }
                    }
                    return new ECqPGroupElement(this,
                                                LargeInteger.ZERO,
                                                LargeInteger.ONE,
                                                LargeInteger.ZERO);
                }
            }
        };
        ECqPGroup.prototype.encode = function (bytes, startIndex, length) {
            var fx;
            if (typeof startIndex === "undefined") {
                startIndex = 0;
                length = bytes.length;
            }
            if (length > this.encodeLength) {
                throw Error("Too many bytes to encode! (" +
                            length + " > " + this.encodeLength + ")");
            } else {
                var bytesToUse = [];
                bytesToUse.length = this.encodeLength + 3;
                var i = 0;
                while (i < this.encodeLength - length) {
                    bytesToUse[i] = 0;
                    i++;
                }
                var j = startIndex;
                while (i < this.encodeLength) {
                    bytesToUse[i] = bytes[j];
                    i++;
                    j++;
                }
                while (i < bytesToUse.length - 3) {
                    bytesToUse[i] = 0;
                    i++;
                }
                verificatum.util.setUint16ToByteArray(bytesToUse, length,
                                                      this.encodeLength);
                var x = new LargeInteger(bytesToUse);
                var square = false;
                while (!square) {
                    fx = this.f(x);
                    if (fx.legendre(this.curve.modulus) === 1) {
                        square = true;
                    } else {
                        x = x.add(LargeInteger.ONE);
                    }
                }
                var y = fx.modSqrt(this.curve.modulus);
                var yneg = this.curve.modulus.sub(y);
                if (yneg.cmp(y) < 0) {
                    y = yneg;
                }
                return new ECqPGroupElement(this, x, y);
            }
        };
        ECqPGroup.prototype.randomElement = function (randomSource, statDist) {
            var p = new LargeInteger(this.curve.modulus.sign, this.curve.modulus.value);
            var bitLength = p.bitLength() + statDist;
            var x;
            var fx;
            var square = false;
            while (!square) {
                x = new LargeInteger(bitLength, randomSource);
                x = x.mod(p);
                fx = this.f(x);
                if (fx.legendre(p) === 1) {
                    square = true;
                }
            }
            var y = fx.modSqrt(p);
            var yneg = p.sub(y);
            if (yneg.cmp(y) < 0) {
                y = yneg;
            }
            return new ECqPGroupElement(this, x, y);
        };
        ECqPGroup.prototype.toString = function () {
            return this.curve.modulus.toHexString() + ":" +
                this.getElementOrder().toHexString() + ":" +
                this.generator.toString();
        };
        function PPGroupElement(pPGroup, values) {
            PGroupElement.call(this, pPGroup);
            this.values = values;
        };
        PPGroupElement.prototype = Object.create(PGroupElement.prototype);
        PPGroupElement.prototype.constructor = PPGroupElement;
        PPGroupElement.prototype.equals = function (other) {
            this.assertType(other);
            for (var i = 0; i < this.values.length; i++) {
                if (!this.values[i].equals(other.values[i])) {
                    return false;
                }
            }
            return true;
        };
        PPGroupElement.prototype.mul = function (other) {
            this.assertType(other);
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].mul(other.values[i]);
            }
            return new PPGroupElement(this.pGroup, values);
        };
        PPGroupElement.prototype.exp = function (exponent) {
            var i;
            var values = [];
            if (exponent.getName() === "PPRingElement" &&
                exponent.pRing.equals(this.pGroup.pRing)) {
                for (i = 0; i < this.values.length; i++) {
                    values[i] = this.values[i].exp(exponent.values[i]);
                }
            } else {
                for (i = 0; i < this.values.length; i++) {
                    values[i] = this.values[i].exp(exponent);
                }
            }
            return new PPGroupElement(this.pGroup, values);
        };
        PPGroupElement.prototype.inv = function () {
            var values = [];
            for (var i = 0; i < this.values.length; i++) {
                values[i] = this.values[i].inv();
            }
            return new PPGroupElement(this.pGroup, values);
        };
        PPGroupElement.prototype.toByteTree = function () {
            var children = [];
            for (var i = 0; i < this.values.length; i++) {
                children[i] = this.values[i].toByteTree();
            }
            return new verificatum.eio.ByteTree(children);
        };
        PPGroupElement.prototype.toString = function () {
            var s = "";
            for (var i = 0; i < this.values.length; i++) {
                s += "," + this.values[i].toString();
            }
            return "(" + s.slice(1) + ")";
        };
        PPGroupElement.prototype.project = function (i) {
            return this.values[i];
        };
        PPGroupElement.prototype.decode = function (destination, startIndex) {
            var origStartIndex = startIndex;
            for (var i = 0; i < this.values.length; i++) {
                startIndex += this.values[i].decode(destination, startIndex);
            }
            return startIndex - origStartIndex;
        };
        var genPRing = function (value) {
            if (verificatum.util.ofType(value, "array")) {
                var pRings = [];
                for (var i = 0; i < value.length; i++) {
                    pRings[i] = value[i].pRing;
                }
                return new PPRing(pRings);
            } else {
                return value;
            }
        };
        function PPGroup(value, width) {
            PGroup.call(this, genPRing(verificatum.util.full(value, width)));
            var values;
            var i;
            if (verificatum.util.ofType(value, "array")) {
                this.pGroups = value;
            } else {
                this.pGroups = verificatum.util.full(value, width);
            }
            this.encodeLength = 0;
            for (i = 0; i < this.pGroups.length; i++) {
                this.encodeLength += this.pGroups[i].encodeLength;
            }
            values = [];
            for (i = 0; i < this.pGroups.length; i++) {
                values[i] = this.pGroups[i].getg();
            }
            this.generator = new PPGroupElement(this, values);
            values = [];
            for (i = 0; i < this.pGroups.length; i++) {
                values[i] = this.pGroups[i].getONE();
            }
            this.ONE = new PPGroupElement(this, values);
            this.byteLength = this.ONE.toByteTree().toByteArray().length;
        };
        PPGroup.prototype = Object.create(PGroup.prototype);
        PPGroup.prototype.constructor = PPGroup;
        PGroup.prototype.getPrimeOrderPGroup = function () {
            return this.pGroups[0].getPrimeOrderPGroup();
        };
        PPGroup.prototype.equals = function (other) {
            if (this === other) {
                return true;
            }
            if (other.getName() !== "PPGroup") {
                return false;
            }
            if (this.pGroups.length !== other.pGroups.length) {
                return false;
            }
            for (var i = 0; i < this.pGroups.length; i++) {
                if (!this.pGroups[i].equals(other.pGroups[i])) {
                    return false;
                }
            }
            return true;
        };
        PPGroup.prototype.getWidth = function () {
            return this.pGroups.length;
        };
        PPGroup.prototype.project = function (i) {
            return this.pGroups[i];
        };
        PPGroup.prototype.prod = function (value) {
            var i;
            var elements;
            if (verificatum.util.ofType(value, "array")) {
                if (value.length === this.pGroups.length) {
                    elements = value;
                } else {
                    throw Error("Wrong number of elements! (" +
                                value.length + " != " + this.pGroups.length + ")");
                }
            } else {
                elements = [];
                for (i = 0; i < this.pGroups.length; i++) {
                    elements[i] = value;
                }
            }
            for (i = 0; i < this.pGroups.length; i++) {
                if (!elements[i].pGroup.equals(this.pGroups[i])) {
                    throw Error("Element " + i + " belongs to the wrong group!");
                }
            }
            return new PPGroupElement(this, elements);
        };
        PPGroup.prototype.getElementOrder = function () {
            return this.pGroups[0].getElementOrder();
        };
        PPGroup.prototype.getg = function () {
            return this.generator;
        };
        PPGroup.prototype.getONE = function () {
            return this.ONE;
        };
        PPGroup.prototype.randomElement = function (randomSource, statDist) {
            var values = [];
            for (var i = 0; i < this.pGroups.length; i++) {
                values[i] = this.pGroups[i].randomElement(randomSource, statDist);
            }
            return new PPGroupElement(this, values);
        };
        PPGroup.prototype.toElement = function (byteTree) {
            if (!byteTree.isLeaf() ||
                byteTree.value.length === this.pGroups.length) {
                var children = [];
                for (var i = 0; i < this.pGroups.length; i++) {
                    children[i] = this.pGroups[i].toElement(byteTree.value[i]);
                }
                return new PPGroupElement(this, children);
            } else {
                throw Error("Input byte tree does not represent an element!");
            }
        };
        PPGroup.prototype.getByteLength = function () {
            return this.byteLength;
        };
        PPGroup.prototype.toString = function () {
            var s = "";
            for (var i = 0; i < this.pGroups.length; i++) {
                s += "," + this.pGroups[i].toString();
            }
            return "(" + s.slice(1) + ")";
        };
        PPGroup.prototype.encode = function (bytes, startIndex, length) {
            var elements = [];
            for (var i = 0; i < this.pGroups.length; i++) {
                var len = Math.min(length, this.pGroups[i].encodeLength);
                elements[i] = this.pGroups[i].encode(bytes, startIndex, len);
                startIndex += len;
                length -= len;
            }
            return new PPGroupElement(this, elements);
        };
        PPGroup.prototype.randomElement = function (randomSource, statDist) {
            var elements = [];
            for (var i = 0; i < this.pGroups.length; i++) {
                elements[i] = this.pGroups[i].randomElement(randomSource, statDist);
            }
            return new PPGroupElement(this, elements);
        };
        PPGroup.fromByteTree = function (byteTree) {
            if (byteTree.isLeaf() || byteTree.value.length !== 2) {
                throw Error("Invalid representation of a group!");
            }
            var atomicPGroups = PPGroup.atomicPGroups(byteTree.value[0]);
            return PPGroup.fromStructure(byteTree.value[1], atomicPGroups);
        };
        PPGroup.atomicPGroups = function (byteTree) {
            if (byteTree.isLeaf() || byteTree.value.length === 0) {
                throw Error("Invalid representation of atomic groups!");
            }
            var pGroups = [];
            for (var i = 0; i < byteTree.value.length; i++) {
                pGroups[i] = PGroup.unmarshal(byteTree.value[i]);
            }
            return pGroups;
        };
        PPGroup.fromStructure = function (byteTree, atomicPGroups) {
            if (byteTree.isLeaf()) {
                if (byteTree.value.length !== 4) {
                    throw Error("Leaf does not contain an index!");
                }
                var index = verificatum.util.readUint32FromByteArray(byteTree.value);
                if (index >= 0 && index < byteTree.value.length) {
                    return atomicPGroups[index];
                } else {
                    throw Error("Index out of range!");
                }
            } else {
                var bts = [];
                for (var i = 0; i < byteTree.value.length; i++) {
                    bts[i] = PPGroup.fromStructure(byteTree.value[i], atomicPGroups);
                }
                return new verificatum.arithm.PPGroup(bts);
            }
        };
        function Hom(domain, range) {
            this.domain = domain;
            this.range = range;
        }
        Hom.prototype = Object.create(Object.prototype);
        Hom.prototype.constructor = Hom;
        Hom.prototype.eva = function (value) {
            throw new Error("Abstract method!");
        };
        function ExpHom(domain, basis) {
            Hom.call(this, domain, basis.pGroup);
            this.basis = basis;
        }
        ExpHom.prototype = Object.create(Hom.prototype);
        ExpHom.prototype.constructor = ExpHom;
        ExpHom.prototype.eva = function (value) {
            return this.basis.exp(value);
        };
        return {
            "li": li,
            "sli": sli,
            "LargeInteger": LargeInteger,
            "ModPowProd": ModPowProd,
            "FixModPow": FixModPow,
            "PRing": PRing,
            "PField": PField,
            "PPRing": PPRing,
            "PGroup": PGroup,
            "ModPGroup": ModPGroup,
            "ec": ec,
            "ECqPGroup": ECqPGroup,
            "PPGroup": PPGroup,
            "Hom": Hom,
            "ExpHom": ExpHom
        };
    })();
    var crypto = (function () {
        var getStatDist = function (statDist) {
            if (typeof statDist === "undefined") {
                return 50;
            } else {
                return statDist;
            }
        };
        var sha256 = (function () {
            var hash = (function () {
                var k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                         0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                         0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                         0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
                         0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                         0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                         0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                         0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                         0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                         0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
                var w = [];
                var rotr = function (w, r) {
                    return w >>> r | w << 32 - r;
                };
                var H;
                var s0;
                var s1;
                var a;
                var b;
                var c;
                var d;
                var e;
                var f;
                var g;
                var h;
                var S0;
                var S1;
                var ch;
                var maj;
                var temp1;
                var temp2;
                var fillw = function (bytes, offset) {
                    var i;
                    var l;
                    for (i = 0; i < 16; i++) {
                        w[i] = 0;
                    }
                    l = offset;
                    i = 0;
                    while (i < 16 && l < bytes.length) {
                        w[i] = w[i] << 8 | bytes[l];
                        if (l % 4 === 3) {
                            i++;
                        }
                        l++;
                    }
                    if (i < 16) {
                        w[i] = w[i] << 8 | 0x80;
                        var b = 4 - l % 4 - 1;
                        w[i] <<= 8 * b;
                        i++;
                    }
                };
                var process = function () {
                    var i;
                    for (i = 16; i < 64; i++) {
                        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
                        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
                        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                    }
                    a = H[0];
                    b = H[1];
                    c = H[2];
                    d = H[3];
                    e = H[4];
                    f = H[5];
                    g = H[6];
                    h = H[7];
                    for (i = 0; i < 64; i++) {
                        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                        ch = e & f ^ ~e & g;
                        temp1 = h + S1 + ch + k[i] + w[i] | 0;
                        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                        maj = a & b ^ a & c ^ b & c;
                        temp2 = S0 + maj | 0;
                        h = g;
                        g = f;
                        f = e;
                        e = d + temp1 | 0;
                        d = c;
                        c = b;
                        b = a;
                        a = temp1 + temp2 | 0;
                    }
                    H[0] = H[0] + a | 0;
                    H[1] = H[1] + b | 0;
                    H[2] = H[2] + c | 0;
                    H[3] = H[3] + d | 0;
                    H[4] = H[4] + e | 0;
                    H[5] = H[5] + f | 0;
                    H[6] = H[6] + g | 0;
                    H[7] = H[7] + h | 0;
                };
                return function (bytes) {
                    var i;
                    var j;
                    H = [0x6a09e667,
                         0xbb67ae85,
                         0x3c6ef372,
                         0xa54ff53a,
                         0x510e527f,
                         0x9b05688c,
                         0x1f83d9ab,
                         0x5be0cd19];
                    var bs = 16 * 4;
                    var blocks = Math.floor(bytes.length / bs);
                    var offset = 0;
                    for (j = 0; j < blocks; j++) {
                        fillw(bytes, offset);
                        process();
                        offset += bs;
                    }
                    var extra = bytes.length % bs;
                    fillw(bytes, offset);
                    if (extra + 9 > bs) {
                        process();
                        for (i = 0; i < 16; i++) {
                            w[i] = 0;
                        }
                    }
                    var bits = 8 * bytes.length;
                    w[15] = bits & 0xFFFFFFFF;
                    bits = Math.floor(bits / Math.pow(2, 32));
                    w[14] = bits & 0xFFFFFFFF;
                    process();
                    var D = [];
                    var l = 0;
                    for (i = 0; i < H.length; i++) {
                        for (j = 3; j >= 0; j--) {
                            D[l] = H[i] >>> j * 8 & 0xFF;
                            l++;
                        }
                    }
                    return D;
                };
            })();
            return {
                "hash": hash
            };
        })();
        function RandomSource() {
        };
        RandomSource.prototype.getBytes = function (len) {
            throw new Error("Abstract method!");
        };
        function RandomDevice() {
        };
        RandomDevice.prototype = Object.create(RandomSource.prototype);
        RandomDevice.prototype.constructor = RandomDevice;
        if (typeof window !== "undefined" && typeof window.crypto !== "undefined") {
            RandomDevice.prototype.getBytes = function (len) {
                var byteArray = new Uint8Array(len);
                window.crypto.getRandomValues(byteArray);
                var bytes = [];
                for (var i = 0; i < len; i++) {
                    bytes[i] = byteArray[i];
                }
                return bytes;
            };
        } else if (typeof require !== "undefined") {
            RandomDevice.prototype.getBytes = (function () {
                var crypto = require("crypto");
                return function (len) {
                    var tmp = crypto.randomBytes(len);
                    var res = [];
                    for (var i = 0; i < tmp.length; i++) {
                        res[i] = tmp[i];
                    }
                    return res;
                };
            })();
        } else {
            RandomDevice.prototype.getBytes = (function () {
                return function () {
                    throw Error("Unable to find a suitable random device!");
                };
            })();
        }
        function SHA256PRG() {
            this.input = null;
        };
        SHA256PRG.prototype = Object.create(RandomSource.prototype);
        SHA256PRG.prototype.constructor = SHA256PRG;
        SHA256PRG.seedLength = 32;
        SHA256PRG.prototype.setSeed = function (seed) {
            if (seed.length >= 32) {
                this.input = seed.slice(0, 32);
                this.input.length += 4;
                this.counter = 0;
                this.buffer = [];
                this.index = 0;
            } else {
                throw Error("Too short seed!");
            }
        };
        SHA256PRG.prototype.getBytes = function (len) {
            if (this.input === null) {
                throw Error("Uninitialized PRG!");
            }
            var res = [];
            res.length = len;
            for (var i = 0; i < res.length; i++) {
                if (this.index === this.buffer.length) {
                    verificatum.util.setUint32ToByteArray(this.input, this.counter, 32);
                    this.buffer = sha256.hash(this.input);
                    this.index = 0;
                    this.counter++;
                }
                res[i] = this.buffer[this.index];
                this.index++;
            }
            return res;
        };
        function ZKPoK() {
        };
        ZKPoK.prototype = Object.create(Object.prototype);
        ZKPoK.prototype.constructor = ZKPoK;
        ZKPoK.prototype.randomnessByteLength = function (statDist) {
            throw Error("Abstract method!");
        };
        ZKPoK.prototype.precompute = function (randomSource, statDist) {
            throw Error("Abstract method!");
        };
        ZKPoK.prototype.precomputeRequiresInstance = function() {
            return false;
        };
        ZKPoK.prototype.precomputeWithInstance = function (instance,
                                                           randomSource,
                                                           statDist) {
            throw Error("Abstract method!");
        };
        ZKPoK.prototype.completeProof = function (precomputed,
                                                  label, instance, witness,
                                                  hashfunction,
                                                  randomSource, statDist) {
            throw Error("Abstract method!");
        };
        ZKPoK.prototype.verify = function (label, instance, hashfunction, proof) {
            throw Error("Abstract method!");
        };
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
        function SigmaProof() {
            ZKPoK.call(this);
        }
        SigmaProof.prototype = Object.create(ZKPoK.prototype);
        SigmaProof.prototype.constructor = SigmaProof;
        SigmaProof.prototype.instanceToByteTree = function (instance) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.commit = function (precomputed, instance, witness,
                                                randomSource, statDist) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.commitmentToByteTree = function (commitment) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.byteTreeToCommitment = function (byteTree) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.challenge = function (first, second) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.reply = function (precomputed, witness, challenge) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.replyToByteTree = function (reply) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.byteTreeToReply = function (byteTree) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.check = function (instance, commitment, challenge, reply) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.simulate = function (instance, challenge,
                                                  randomSource, statDist) {
            throw Error("Abstract method!");
        };
        SigmaProof.prototype.completeProof = function (precomputed,
                                                       label, instance, witness,
                                                       hashfunction,
                                                       randomSource, statDist) {
            var pair =
                this.commit(precomputed, instance, witness, randomSource, statDist);
            precomputed = pair[0];
            var commitment = pair[1];
            var lbt = eio.ByteTree.asByteTree(label);
            var ibt = this.instanceToByteTree(instance);
            var cbt = this.commitmentToByteTree(commitment);
            var bt = new eio.ByteTree([lbt, ibt, cbt]);
            var challenge = this.challenge(bt, hashfunction);
            var reply = this.reply(precomputed, witness, challenge);
            var rbt = this.replyToByteTree(reply);
            var pbt = new eio.ByteTree([cbt, rbt]);
            return pbt.toByteArray();
        };
        SigmaProof.prototype.verify = function (label, instance, hashfunction, proof) {
            try {
                var pbt = eio.ByteTree.readByteTreeFromByteArray(proof);
                if (!pbt.isLeaf() && pbt.value.length === 2) {
                    var lbt = eio.ByteTree.asByteTree(label);
                    var ibt = this.instanceToByteTree(instance);
                    var cbt = pbt.value[0];
                    var commitment = this.byteTreeToCommitment(cbt);
                    var bt = new eio.ByteTree([lbt, ibt, cbt]);
                    var challenge = this.challenge(bt, hashfunction);
                    var rbt = pbt.value[1];
                    var reply = this.byteTreeToReply(rbt);
                    return this.check(instance, commitment, challenge, reply);
                } else {
                    return false;
                }
            } catch (err) {
                return false;
            }
        };
        function SigmaProofPara(sigmaProofs) {
            SigmaProof.call(this);
            this.sigmaProofs = sigmaProofs;
        }
        SigmaProofPara.prototype = Object.create(SigmaProof.prototype);
        SigmaProofPara.prototype.constructor = SigmaProofPara;
        SigmaProofPara.prototype.instanceToByteTree = function (instance) {
            var bta = [];
            for (var i = 0; i < instance.length; i++) {
                bta[i] = this.sigmaProofs[i].instanceToByteTree(instance[i]);
            }
            return new eio.ByteTree(bta);
        };
        SigmaProofPara.prototype.commitmentToByteTree = function (commitment) {
            var bta = [];
            for (var i = 0; i < commitment.length; i++) {
                bta[i] = this.sigmaProofs[i].commitmentToByteTree(commitment[i]);
            }
            return new eio.ByteTree(bta);
        };
        SigmaProofPara.prototype.byteTreeToCommitment = function (byteTree) {
            if (byteTree.isLeaf()) {
                throw Error("Byte tree is a leaf!");
            } else if (byteTree.value.length === this.sigmaProofs.length) {
                var commitment = [];
                for (var i = 0; i < this.sigmaProofs.length; i++) {
                    commitment[i] =
                        this.sigmaProofs[i].byteTreeToCommitment(byteTree.value[i]);
                }
                return commitment;
            } else {
                throw Error("Byte tree has wrong number of children! (" +
                            byteTree.value.length + ")");
            }
        };
        SigmaProofPara.prototype.challenge = function (first, second) {
            return this.sigmaProofs[0].challenge(first, second);
        };
        SigmaProofPara.prototype.reply = function (precomputed, witness, challenge) {
            var reply = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                reply[i] =
                    this.sigmaProofs[i].reply(precomputed[i], witness[i], challenge);
            }
            return reply;
        };
        SigmaProofPara.prototype.replyToByteTree = function (reply) {
            var btr = [];
            for (var i = 0; i < reply.length; i++) {
                btr[i] = this.sigmaProofs[i].replyToByteTree(reply[i]);
            }
            return new eio.ByteTree(btr);
        };
        SigmaProofPara.prototype.byteTreeToReply = function (byteTree) {
            if (byteTree.isLeaf()) {
                throw Error("Byte tree is a leaf!");
            } else if (byteTree.value.length === this.sigmaProofs.length) {
                var reply = [];
                for (var i = 0; i < this.sigmaProofs.length; i++) {
                    reply[i] = this.sigmaProofs[i].byteTreeToReply(byteTree.value[i]);
                }
                return reply;
            } else {
                throw Error("Byte tree has wrong number of children! (" +
                            byteTree.value.length + ")");
            }
        };
        SigmaProofPara.prototype.check = function (instance, commitment,
                                                   challenge, reply) {
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                if (!this.sigmaProofs[i].check(instance[i], commitment[i],
                                               challenge[i], reply[i])) {
                    return false;
                }
            }
            return true;
        };
        SigmaProofPara.prototype.simulate = function (instance, challenge,
                                                      randomSource, statDist) {
            var commitment = [];
            var reply = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                var pair = this.sigmaProofs[i].simulate(instance[i], challenge[i],
                                                        randomSource, statDist);
                commitment[i] = pair[0];
                reply[i] = pair[1];
            }
            return [commitment, reply];
        };
        function SigmaProofAnd(sigmaProofs) {
            SigmaProofPara.call(this, sigmaProofs);
        }
        SigmaProofAnd.prototype = Object.create(SigmaProofPara.prototype);
        SigmaProofAnd.prototype.constructor = SigmaProofAnd;
        SigmaProofAnd.prototype.randomnessByteLength = function (statDist) {
            var byteLength = 0;
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                byteLength += this.sigmaProofs[i].randomnessByteLength(statDist);
            }
            return byteLength;
        };
        SigmaProofAnd.prototype.precompute = function (randomSource, statDist) {
            var precomputed = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                precomputed[i] = this.sigmaProofs[i].precompute(randomSource, statDist);
            }
            return precomputed;
        };
        SigmaProofAnd.prototype.commit = function (precomputed, instance, witness,
                                                   randomSource, statDist) {
            var newPrecomputed = [];
            var commitment = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                var pair = this.sigmaProofs[i].commit(precomputed[i],
                                                      instance[i], witness[i],
                                                      randomSource, statDist);
                newPrecomputed[i] = pair[0];
                commitment[i] = pair[1];
            }
            return [newPrecomputed, commitment];
        };
        SigmaProofAnd.prototype.check = function (instance, commitment,
                                                  challenge, reply) {
            var chall = util.fill(challenge, this.sigmaProofs.length);
            return SigmaProofPara.prototype.check.call(this,
                                                       instance, commitment,
                                                       chall, reply);
        };
        SigmaProofAnd.prototype.simulate = function (instance, challenge,
                                                     randomSource, statDist) {
            var chall = util.fill(challenge, this.sigmaProofs.length);
            return SigmaProofPara.prototype.simulate.call(this,
                                                          instance, chall,
                                                          randomSource, statDist);
        };
        function SigmaProofOr(challengeSpace, param, copies) {
            SigmaProofPara.call(this, param);
            this.challengeSpace = challengeSpace;
            this.uniform = typeof copies === "undefined";
        }
        SigmaProofOr.prototype = Object.create(SigmaProofPara.prototype);
        SigmaProofOr.prototype.constructor = SigmaProofOr;
        SigmaProofOr.genSigmaProofs = function (param, copies) {
            if (typeof copies === "undefined") {
                return param;
            } else {
                return util.full(param, copies);
            }
        };
        SigmaProofOr.sum = function (array) {
            var s = array[0];
            for (var j = 1; j < array.length; j++) {
                s = s.add(array[j]);
            }
            return s;
        };
        SigmaProofOr.prototype.precomputeRequiresInstance = function() {
            return true;
        };
        SigmaProofOr.prototype.precomputeWithInstance = function (instances,
                                                                  randomSource,
                                                                  statDist) {
            var challenges = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
            }
            var pre = SigmaProofPara.prototype.simulate.call(this, instances, challenges,
                                                             randomSource, statDist);
            var precomputed = [pre[0], [challenges, pre[1]]];
            if (this.uniform) {
                precomputed[2] = this.sigmaProofs[0].precompute(randomSource, statDist);
            }
            return precomputed;
        };
        SigmaProofOr.prototype.commit = function (precomputed, instance, witness,
                                                  randomSource, statDist) {
            var i = witness[1];
            if (!this.uniform) {
                precomputed[2] = this.sigmaProofs[i].precompute(randomSource, statDist);
            }
            precomputed[0][i] = precomputed[2][1];
            return [precomputed, precomputed[0]];
        };
        SigmaProofOr.prototype.reply = function (precomputed, witness, challenge) {
            var i = witness[1];
            var sum = SigmaProofOr.sum(precomputed[1][0]);
            sum = sum.sub(precomputed[1][0][i]);
            precomputed[1][0][i] = challenge.sub(sum);
            precomputed[1][1][i] = this.sigmaProofs[i].reply(precomputed[2][0],
                                                             witness[0],
                                                             precomputed[1][0][i]);
            return precomputed[1];
        };
        SigmaProofOr.prototype.replyToByteTree = function (reply) {
            var cbts = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                cbts[i] = reply[0][i].toByteTree();
            }
            var cbt = new eio.ByteTree(cbts);
            var rbt = SigmaProofPara.prototype.replyToByteTree.call(this, reply[1]);
            return new eio.ByteTree([cbt, rbt]);
        };
        SigmaProofOr.prototype.byteTreeToReply = function (byteTree) {
            if (!byteTree.isLeaf() && byteTree.value.length === 2) {
                var cbt = byteTree.value[0];
                var rbt = byteTree.value[1];
                var challenge;
                if (!cbt.isLeaf() && cbt.value.length === this.sigmaProofs.length) {
                    challenge = [];
                    for (var i = 0; i < this.sigmaProofs.length; i++) {
                        challenge[i] = this.challengeSpace.toElement(cbt.value[i]);
                    }
                } else {
                    throw Error("Byte tree has wrong number of children!");
                }
                var reply =
                    SigmaProofPara.prototype.byteTreeToReply.call(this, rbt);
                return [challenge, reply];
            } else {
                throw Error("Byte tree has wrong number of children!");
            }
        };
        SigmaProofOr.prototype.check = function (instance, commitment,
                                                 challenge, reply) {
            var s = SigmaProofOr.sum(reply[0]);
            return s.equals(challenge) &&
                SigmaProofPara.prototype.check.call(this,
                                                    instance, commitment,
                                                    reply[0], reply[1]);
        };
        SigmaProofOr.prototype.simulate = function (instance, challenge,
                                                    randomSource, statDist) {
            var challenges = [];
            for (var i = 0; i < this.sigmaProofs.length - 1; i++) {
                challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
            }
            var sum = SigmaProofOr.sum(challenges);
            challenges[this.sigmaProofs.length - 1] = challenge.sub(sum);
            var pre = SigmaProofPara.prototype.simulate.call(this,
                                                             instance, challenges,
                                                             randomSource, statDist);
            return [pre[0], [challenges, pre[1]]];
        };
        function SchnorrProof(homomorphism) {
            SigmaProof.call(this);
            this.homomorphism = homomorphism;
        }
        SchnorrProof.prototype = Object.create(SigmaProof.prototype);
        SchnorrProof.prototype.constructor = SchnorrProof;
        SchnorrProof.prototype.randomnessByteLength = function (statDist) {
            return this.homomorphism.domain.randomElementByteLength(statDist);
        };
        SchnorrProof.prototype.instanceToByteTree = function (instance) {
            return instance.toByteTree();
        };
        SchnorrProof.prototype.precompute = function (randomSource, statDist) {
            var a = this.homomorphism.domain.randomElement(randomSource, statDist);
            var A = this.homomorphism.eva(a);
            return [a, A];
        };
        SchnorrProof.prototype.commit = function (precomputed) {
            return precomputed;
        };
        SchnorrProof.prototype.commitmentToByteTree = function (commitment) {
            return commitment.toByteTree();
        };
        SchnorrProof.prototype.byteTreeToCommitment = function (byteTree) {
            return this.homomorphism.range.toElement(byteTree);
        };
        SchnorrProof.prototype.challenge = function (first, second) {
            if (util.ofType(first, eio.ByteTree)) {
                var digest = second.hash(first.toByteArray());
                return this.homomorphism.domain.getPField().toElement(digest);
            } else {
                return this.homomorphism.domain.randomElement(first, second);
            }
        };
        SchnorrProof.prototype.reply = function (precomputed, witness, challenge) {
            return witness.mul(challenge).add(precomputed);
        };
        SchnorrProof.prototype.replyToByteTree = function (reply) {
            return reply.toByteTree();
        };
        SchnorrProof.prototype.byteTreeToReply = function (byteTree) {
            return this.homomorphism.domain.toElement(byteTree);
        };
        SchnorrProof.prototype.check = function (instance, commitment,
                                                 challenge, reply) {
            var ls = instance.exp(challenge).mul(commitment);
            var rs = this.homomorphism.eva(reply);
            return ls.equals(rs);
        };
        SchnorrProof.prototype.simulate = function (instance, challenge,
                                                    randomSource, statDist) {
            var k = this.homomorphism.domain.randomElement(randomSource, statDist);
            var A = this.homomorphism.eva(k).mul(instance.exp(challenge).inv());
            return [A, k];
        };
        function ElGamal(standard, pGroup, randomSource, statDist) {
            this.standard = standard;
            this.pGroup = pGroup;
            this.randomSource = randomSource;
            this.statDist = statDist;
        };
        ElGamal.prototype = Object.create(Object.prototype);
        ElGamal.prototype.constructor = ElGamal;
        ElGamal.prototype.randomnessByteLength = function (publicKey) {
            publicKey.project(1).pGroup.pRing.randomElementByteLength(this.statDist);
        };
        ElGamal.prototype.gen = function () {
            var pGroup = this.pGroup;
            var sk = pGroup.pRing.randomElement(this.randomSource, this.statDist);
            var ghGroup;
            var gh;
            if (this.standard) {
                ghGroup = pGroup;
                gh = pGroup.getg();
            } else {
                var r = pGroup.pRing.randomElement(this.randomSource, this.statDist);
                var h = pGroup.getg().exp(r);
                ghGroup = new verificatum.arithm.PPGroup([pGroup, pGroup]);
                gh = ghGroup.prod([pGroup.getg(), h]);
            }
            var pkGroup = new verificatum.arithm.PPGroup([ghGroup, pGroup]);
            var pk = pkGroup.prod([gh, pGroup.getg().exp(sk)]);
            return [pk, sk];
        };
        ElGamal.prototype.precomputeEncrypt = function (publicKey, random) {
            var gh = publicKey.project(0);
            var y = publicKey.project(1);
            var r;
            if (typeof random === "undefined") {
                r = y.pGroup.pRing.randomElement(this.randomSource, this.statDist);
            } else {
                r = random;
            }
            return [r, gh.exp(r), y.exp(r)];
        };
        ElGamal.prototype.completeEncrypt = function (publicKey, ruv, message) {
            return publicKey.pGroup.prod([ruv[1], ruv[2].mul(message)]);
        };
        ElGamal.prototype.encrypt = function (publicKey, message, random) {
            var ruv = this.precomputeEncrypt(publicKey, random);
            return this.completeEncrypt(publicKey, ruv, message);
        };
        ElGamal.prototype.decrypt = function (privateKey, ciphertext) {
            var ua = ciphertext.project(0);
            var v = ciphertext.project(1);
            var u;
            if (this.standard) {
                u = ua;
            } else {
                u = ua.project(0);
            }
            return v.mul(u.exp(privateKey.neg()));
        };
        ElGamal.prototype.widePublicKey = function (publicKey, width) {
            if (width > 1) {
                var pkGroup = publicKey.pGroup;
                var yGroup = pkGroup.project(1);
                var y = publicKey.project(1);
                var wyGroup = new verificatum.arithm.PPGroup(yGroup, width);
                var wy = wyGroup.prod(y);
                var ghGroup = pkGroup.project(0);
                var gh = publicKey.project(0);
                var wghGroup;
                var wgh;
                if (ghGroup.equals(yGroup)) {
                    wghGroup = wyGroup;
                    wgh = wghGroup.prod(gh);
                } else {
                    var g = gh.project(0);
                    var h = gh.project(1);
                    var wg = wyGroup.prod(g);
                    var wh = wyGroup.prod(h);
                    wghGroup = new verificatum.arithm.PPGroup(wyGroup, 2);
                    wgh = wghGroup.prod([wg, wh]);
                }
                var wpkGroup = new verificatum.arithm.PPGroup([wghGroup, wyGroup]);
                return wpkGroup.prod([wgh, wy]);
            } else {
                return publicKey;
            }
        };
        ElGamal.prototype.widePrivateKey = function (privateKey, width) {
            if (width > 1) {
                var wskRing = new verificatum.arithm.PPRing(privateKey.pRing, width);
                return wskRing.prod(privateKey);
            } else {
                return privateKey;
            }
        };
        ElGamal.benchEncryptPGroupWidth = function (standard, pGroup, width,
                                                    minSamples, randomSource, statDist) {
            var eg = new ElGamal(standard, pGroup, randomSource, statDist);
            var keys = eg.gen();
            var wpk = eg.widePublicKey(keys[0], width);
            var m = wpk.pGroup.project(1).getg();
            var start = util.time_ms();
            var j = 0;
            while (j < minSamples) {
                eg.encrypt(wpk, m);
                j++;
            }
            return (util.time_ms() - start) / j;
        };
        ElGamal.benchEncryptPGroup = function (standard, pGroup, maxWidth,
                                               minSamples, randomSource, statDist) {
            var results = [];
            for (var i = 1; i <= maxWidth; i++) {
                var t = ElGamal.benchEncryptPGroupWidth(standard, pGroup, i,
                                                        minSamples, randomSource,
                                                        statDist);
                results.push(t);
            }
            return results;
        };
        ElGamal.benchEncrypt = function (standard, pGroups, maxWidth,
                                         minSamples, randomSource, statDist) {
            var results = [];
            for (var i = 0; i < pGroups.length; i++) {
                results[i] = ElGamal.benchEncryptPGroup(standard, pGroups[i], maxWidth,
                                                        minSamples, randomSource,
                                                        statDist);
            }
            return results;
        };
        function ElGamalZKPoKAdapter() {};
        ElGamalZKPoKAdapter.prototype = Object.create(Object.prototype);
        ElGamalZKPoKAdapter.prototype.constructor = ElGamalZKPoKAdapter;
        ElGamalZKPoKAdapter.prototype.getZKPoK = function (publicKey) {
            throw new Error("Abstract method!");
        };
        function ElGamalZKPoK(standard, pGroup, adapter, hashfunction,
                              randomSource, statDist) {
            this.eg = new ElGamal(standard, pGroup, randomSource, statDist);
            this.adapter = adapter;
            this.hashfunction = hashfunction;
        };
        ElGamalZKPoK.prototype = Object.create(Object.prototype);
        ElGamalZKPoK.prototype.constructor = ElGamalZKPoK;
        ElGamalZKPoK.prototype.gen = function () {
            return this.eg.gen();
        };
        ElGamalZKPoK.prototype.precomputeEncrypt = function (publicKey) {
            var ruv = this.eg.precomputeEncrypt(publicKey);
            var zkpok = this.adapter.getZKPoK(publicKey);
            var pre = zkpok.precompute(this.eg.randomSource, this.eg.statDist);
            return [ruv, pre];
        };
        ElGamalZKPoK.prototype.completeEncrypt = function (label,
                                                           publicKey,
                                                           precomputed,
                                                           message) {
            var egc = this.eg.completeEncrypt(publicKey, precomputed[0], message);
            var zkpok = this.adapter.getZKPoK(publicKey);
            var proof = zkpok.completeProof(precomputed[1],
                                            label,
                                            egc, precomputed[0][0],
                                            this.hashfunction,
                                            this.eg.randomSource,
                                            this.eg.statDist);
            return new eio.ByteTree([egc.toByteTree(), new eio.ByteTree(proof)]);
        };
        ElGamalZKPoK.prototype.encrypt = function (label, publicKey, message) {
            var precomputed = this.precomputeEncrypt(publicKey);
            return this.completeEncrypt(label, publicKey, precomputed, message);
        };
        ElGamalZKPoK.prototype.decrypt = function (label, publicKey, privateKey,
                                                   ciphertext) {
            if (ciphertext.isLeaf() ||
                ciphertext.value.length !== 2 ||
                !ciphertext.value[1].isLeaf()) {
                return null;
            }
            var ciphertextElement;
            try {
                ciphertextElement = publicKey.pGroup.toElement(ciphertext.value[0]);
            } catch (err) {
                return null;
            }
            var proof = ciphertext.value[1].value;
            var zkpok = this.adapter.getZKPoK(publicKey);
            var verdict =
                zkpok.verify(label, ciphertextElement, this.hashfunction, proof);
            if (verdict) {
                return this.eg.decrypt(privateKey, ciphertextElement);
            } else {
                return null;
            }
        };
        ElGamalZKPoK.prototype.widePublicKey = function (publicKey, width) {
            return this.eg.widePublicKey(publicKey, width);
        };
        ElGamalZKPoK.prototype.widePrivateKey = function (privateKey, width) {
            return this.eg.widePrivateKey(privateKey, width);
        };
        function ZKPoKWriteIn(publicKey) {
            var domain = publicKey.project(1).pGroup.pRing;
            var basis = publicKey.project(0);
            var expHom = new arithm.ExpHom(domain, basis);
            this.sp = new SchnorrProof(expHom);
        };
        ZKPoKWriteIn.prototype = Object.create(ZKPoK.prototype);
        ZKPoKWriteIn.prototype.constructor = ZKPoKWriteIn;
        ZKPoKWriteIn.prototype.precompute = function (randomSource, statDist) {
            return this.sp.precompute(randomSource, statDist);
        };
        ZKPoKWriteIn.makeLabel = function (label, instance) {
            var lbt = eio.ByteTree.asByteTree(label);
            var ebt = instance.project(1).toByteTree();
            return new eio.ByteTree([lbt, ebt]);
        };
        ZKPoKWriteIn.prototype.completeProof = function (precomputed,
                                                         label, instance, witness,
                                                         hashfunction,
                                                         randomSource, statDist) {
            label = ZKPoKWriteIn.makeLabel(label, instance);
            return this.sp.completeProof(precomputed, label,
                                         instance.project(0), witness,
                                         hashfunction, randomSource, statDist);
        };
        ZKPoKWriteIn.prototype.verify = function (label, instance, hashfunction, proof) {
            label = ZKPoKWriteIn.makeLabel(label, instance);
            return this.sp.verify(label, instance.project(0), hashfunction, proof);
        };
        function ZKPoKWriteInAdapter() {};
        ZKPoKWriteInAdapter.prototype = Object.create(ElGamalZKPoKAdapter.prototype);
        ZKPoKWriteInAdapter.prototype.constructor = ZKPoKWriteInAdapter;
        ZKPoKWriteInAdapter.prototype.getZKPoK = function (publicKey) {
            return new ZKPoKWriteIn(publicKey);
        };
        function ElGamalZKPoKWriteIn(standard, pGroup, hashfunction, randomSource,
                                     statDist) {
            ElGamalZKPoK.call(this, standard, pGroup, new ZKPoKWriteInAdapter(),
                              hashfunction, randomSource, statDist);
        };
        ElGamalZKPoKWriteIn.prototype = Object.create(ElGamalZKPoK.prototype);
        ElGamalZKPoKWriteIn.prototype.constructor = ElGamalZKPoKWriteIn;
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
        return {
            "sha256": sha256,
            "getStatDist": getStatDist,
            "RandomSource": RandomSource,
            "RandomDevice": RandomDevice,
            "SHA256PRG": SHA256PRG,
            "SigmaProof": SigmaProof,
            "SigmaProofPara": SigmaProofPara,
            "SigmaProofAnd": SigmaProofAnd,
            "SigmaProofOr": SigmaProofOr,
            "SchnorrProof": SchnorrProof,
            "ElGamal": ElGamal,
            "ElGamalZKPoKAdapter": ElGamalZKPoKAdapter,
            "ElGamalZKPoK": ElGamalZKPoK,
            "ZKPoKWriteIn": ZKPoKWriteIn,
            "ZKPoKWriteInAdapter": ZKPoKWriteInAdapter,
            "ElGamalZKPoKWriteIn": ElGamalZKPoKWriteIn
        };
    })();
    var benchmark = (function () {
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
    return {
        "version": "1.1.1",
        "util": util,
        "eio": eio,
        "arithm": arithm,
        "crypto": crypto,
        "benchmark": benchmark
    };
})();
