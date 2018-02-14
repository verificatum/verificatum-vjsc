
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
