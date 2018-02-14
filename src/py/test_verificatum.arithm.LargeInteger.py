
# Copyright 2008-2018 Douglas Wikstrom
#
# This file is part of Verificatum JavaScript Cryptographic library
# (VJSC).
#
# VJSC is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# VJSC is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
# Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with VJSC. If not, see <http://www.gnu.org/licenses/>.

import sys
from util import evjs, h, now, randomInt


"""Class intended to mirror verificatum.arithm.LargeInteger
implemented in JavaScript. All operations are executed in both our
Javascript code and in plain Python and the results are verified to be
consistent.

This provides a simple way to test the most basic functionality of the
implementation in JavaScript. It is only used for debugging.
"""

class LargeInteger(object):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return hex(self.value)

    def js(self, op, pars):
        """Invocation of a method taking a number of integers as
        parameters.
        """

        ls = "new verificatum.arithm.LargeInteger"

        # Convert Python integers to hexadecimal strings.
        hpars = []
        for p in pars:
            hpars.append("%s(\\\"%s\\\")" % (ls, h(p.value)));

        # Compile expression.
        c = "(%s(\\\"%s\\\")).%s(%s).toHexString()" \
            % (ls, h(self.value), op, ",".join(hpars))

        # Evaluate and convert resulting hexadecimal string into a
        # Python integer.
        hexres = evjs(c)
        return LargeInteger(int(hexres, 16))

    def neg(self):
        """Return the negative of this instance."""
        res = self.js("neg", [])
        pres = -self.value
        if (res.value != pres):
            raise Exception("Negation failed: \n-%d != %d\n-%s != -%s" \
                            % (self.value, res.value,
                               h(self.value), h(res.value)))
        return res

    def add(self, other):
        """Return the sum of this instance and the input."""
        res = self.js("add", [other])
        pres = self.value + other.value
        if (res.value != pres):
            raise Exception("Addition failed: \n%d + %d != %d\n%s + %s != %s" \
                            % (self.value, other.value, res.value,
                               h(self.value), h(other.value), h(res.value)))
        return res

    def sub(self, other):
        """Return the difference of this instance and the input."""
        res = self.js("sub", [other])
        pres = self.value - other.value
        if (res.value != pres):
            raise Exception("Subtraction failed: \n%d - %d != %d\n%s - %s != %s" \
                            % (self.value, other.value, res.value,
                               h(self.value), h(other.value), h(res.value)))
        return res

    def mul(self, other):
        """Return the product of this instance and the input."""
        res = self.js("mul", [other])
        pres = self.value * other.value

        if (res.value != pres):
            raise Exception("Multiplication failed: \n%d * %d != %d\n%s * %s = %s != %s" \
                            % (self.value, other.value, res.value,
                               h(self.value), h(other.value), h(res.value), h(pres)))
        return res

    def square(self):
        """Return the square of this instance."""
        res = self.js("square", [])
        pres = self.value * self.value
        if (res.value != pres):
            raise Exception("Squaring failed: \n%d^2 = %d != %d\n%s^2 = %s != %s" \
                            % (self.value, res.value, pres,
                               h(self.value), h(res.value), h(pres)))
        return res

    def div(self, other):
        """Return the quotient of this instance and the input."""
        res = self.js("div", [other])
        pres = self.value / other.value
        if (res.value != pres):
            raise Exception("Division failed: \n%s / %s = %s != %s\n%s / %s = %s != %s" \
                            % (self.value, other.value,
                               res.value, pres,
                               h(self.value), h(other.value),
                               h(res.value), h(pres)))
        return res

    def mod(self, other):
        """Return the remainder of this instance modulo the input."""
        res = self.js("mod", [other])
        pres = self.value % other.value
        if (res.value != pres):
            raise Exception("Modulo failed: \n%s %% %s = %s != %s\n%s %% %s = %s != %s" \
                            % (self.value, other.value,
                               res.value, pres,
                               h(self.value), h(other.value),
                               h(res.value), h(pres)))
        return res

    def modPow(self, other, secondOther):
        res = self.js("modPow", [other, secondOther])
        pres = pow(self.value, other.value, secondOther.value);
        if (res.value != pres):
            raise Exception("Modular exponentiation failed: \n%s ^ %s mod %s = %s != %s\n%s ^ %s mod %s = %s != %s" \
                            % (self.value, other.value, secondOther.value,
                               res.value, pres,
                               h(self.value), h(other.value), h(secondOther.value),
                               h(res.value), h(pres)))
        return res


def test_add_sub(xbits, ybits, op):
    """Tests addition/subtraction exhaustively for the given bit sizes and
    negation at every possible position, with randomly generated
    integers.
    """
    for i in xbits:
        for j in ybits:
            x = LargeInteger(randomInt(i, i))
            y = LargeInteger(randomInt(j, j))

            if (op == "add"):
                x.add(y)
                x.add(y.neg())
                x.neg().add(y)
                x.neg().add(y.neg())
            else:
                x.sub(y)
                x.sub(y.neg())
                x.neg().sub(y)
                x.neg().sub(y.neg())

def test_square(xbits):
    """Tests squaring exhaustively for the given bit sizes, and with
    negation, with randomly generated integers.
    """
    for i in xbits:
        x = LargeInteger(randomInt(i, i))
        x.square()
        x.neg().square()

def test_mul_div(xbits, ybits, op):
    """Tests multiplication/division exhaustively for the given bit sizes
    and negation at every possible position, with randomly generated
    integers.
    """
    for i in xbits:
        for j in ybits:
            x = LargeInteger(randomInt(i, i))
            y = LargeInteger(randomInt(j, j))
            if (op == "mul"):
                x.mul(y)
                x.mul(y.neg())
                x.neg().mul(y)
                x.neg().mul(y.neg())
            elif (y.value > 0):
                x.div(y)
                x.div(y.neg())
                x.neg().div(y)
                x.neg().div(y.neg())

def test_mod(xbits, ybits, op):
    """Tests modular reduction exhaustively for the given bit sizes and
    negation at every possible position, with randomly generated
    integers.
    """
    for i in xbits:
        for j in ybits:
            x = LargeInteger(randomInt(i, i))
            y = LargeInteger(randomInt(j, j))
            x.mod(y)
            # x.mod(y.neg())
            # x.neg().mod(y)
            # x.neg().mod(y.neg())

def test_modPow(xbits, ybits):
    """Tests modular exponentiation exhaustively for the given bit sizes
    and negation at every possible position, with randomly generated
    integers.
    """
    for i in xbits:
        for j in ybits:
            print("i = %s, j = %s" % (i, j))
            x = LargeInteger(randomInt(i, i))
            y = LargeInteger(randomInt(j, j))
            z = LargeInteger(randomInt(j, j + 1))
            x.modPow(y, z)

def test_op(op, seconds, bits1, bits2 = None):
    """Wrapper function for testing a given operation for the given bit
    sizes and negation at every possible position, with randomly
    generated integers.
    """

    if (bits2 == None):
        bits1 = bits2

    sys.stdout.write("Testing %s for %d seconds... " % (op, seconds))
    sys.stdout.flush()
    start = now()
    n = 0

    i = 1;
    while (n <= start + seconds):

        if op == "add":
            test_add_sub(bits1, bits2, "add")

        if op == "sub":
            test_add_sub(bits1, bits2, "sub")

        if op == "square":
            test_square(bits1)

        if op == "mul":
            test_mul_div(bits1, bits2, "mul")

        if op == "div":
            test_mul_div(bits1, bits2, "div")

        if op == "mod":
            test_mod(bits1, bits2, "mod")

        if op == "modPow":
            test_modPow(bits1, bits2)

        i = i + 1
        n = now()

    print "done."

# secs = 20
# bits = range(20, 20)

# test_op("add", secs, bits, bits)
# test_op("sub", secs, bits, bits)
# test_op("square", secs, bits, bits)
# test_op("mul", secs, bits, bits)
# test_op("div", secs, bits, bits)
# test_op("mod", secs, bits, bits)
# test_op("modPow", secs, bits, bits)
