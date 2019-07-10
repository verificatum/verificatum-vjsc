
# Copyright 2008-2019 Douglas Wikstrom
#
# This file is part of Verificatum JavaScript Cryptographic library
# (VJSC).
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Provides simple utility functions (syntactic sugar).

import time
import subprocess
import random

def evjs(command):
    """Wrapper for the script that allows evaluating our Javascript code
    from Python in a simple way.
    """
    return subprocess.Popen("nodejs js/evjs.js \"%s\"" % command,
                            shell=True,
                            stdout=subprocess.PIPE).stdout.read();

def h(x):
    """Convert an integer into a raw hexadecimal representation."""
    return hex(x).replace("0x", "").replace("L", "").upper()

def now():
    """Returns the epoch."""
    return int(time.time())

def randomHexString(byte_length, seed):
    """Returns a random string of hexadecimal characters of the given
    length.
    """
    random.seed(seed)

    s = ""
    for j in range(0, byte_length):
        s += h(random.randrange(0, 16))
    return s

def randomInt(bit_length, seed):
    """Returns a random integer."""
    s = randomHexString((bit_length + 3) / 4, seed)
    return int(s, 16) % (1 << bit_length)
