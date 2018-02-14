
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

#############################################################################
############### Configuration ###############################################
#############################################################################

# OMITTING FUNCTIONALITY
#
# You can generate code for a subset of the functionality by editing
# the Makefile.conf file. This generates a script that enables
# the inclusion of individual modules in a way that makes best effort
# to guarantee that dependencies are respected. There is a build
# target for generating the default Makefile.conf file if you
# delete it by mistake.
#
# For example, if you implement your own cryptographic routines on top
# of the groups, you can omit the ones provided by default. You may
# wish to omit the benchmark module. Make sure that you test the
# resulting modified library thoroughly, since we can not anticipate
# every possible way you may omit modules.
#
# NOTE. You must edit the dependencies separately for the tests. For
# natural subsets, this should be easy and should suffice. For some
# subsets of functionalities you may have to edit the tests
# themselves. This has the advantage that you can easily disable tests.
#
# OMITTING GROUP PARAMETERS
#
# Only a subset of the available group parameters are thought to be
# secure, so we strongly suggest that you omit the group descriptions
# that you do not use. These are included solely for historical and
# testing purposes.
#
# Some tests use groups of minimal size to give time to run as
# thorough tests as possible. Omitting groups can make these tests
# take substantially more time, and omitting all groups will make the
# tests fail.
#
# We do not recommend any particular parameters, but we strongly
# discourage the use of any parameter not listed below. Please consult
# us or another cryptographer understand what is suitable in your
# application.
#
# Elliptic curves
# NIST:                         prime256v1 prime239v1 prime239v3
# SEC:                          secp256k1 secp256r1 secp384r1 secp521r1
# TeleTrusT/Brainpool:          brainpoolp256r1 brainpoolp320r1
#                               brainpoolp384r1 brainpoolp512r1
# X9.62:                        P-256 P-384 P-521
#
# Multiplicative groups
# RFC 2409, RFC 2412, RFC 3526: modp3072 modp4096 modp6144 modp8192

#############################################################################
############### Normal Targets ##############################################
#############################################################################

# Version of this library.
VJSC_VERSION=1.1.1

# Underlying floating point type. If a platform has a non-standard
# floating point implementation, e.g., JavaScript "number", then this
# can be decreased. Pass MANTISSA=<yours> to make to change this.
ifndef $(MANTISSA)
    MANTISSA=53
endif

# Wordsize in bits. This can be any positive even number between 8 and
# 30. The complexity scales as expected for large wordsizes except
# that in some places slightly more work is needed for 30-bit words to
# work within a 32-bit limb bound. Thus, 28-bit words is a good
# default except when parameters are huge.
# Use "make vjsc WORDSIZE=<yours>" to change this.
ifndef $(WORDSIZE)
    WORDSIZE=28
endif

# Let us be paranoid and verify the wordsize to avoid that something
# somewhat works.
VALID=$(shell echo $(WORDSIZE) | sed "s/\(8\)\|\(1[0,2,4,6,8]\)\|\(2[0,2,4,6,8]\)\|\(30\)/VALID/")
ifneq ($(VALID),VALID)
    $(error Given wordsize ($(WORDSIZE)) is not an even integer in [8,30]!)
endif


VJSC=vjsc-$(VJSC_VERSION)

INSTALLDIR=/usr/local/bin

M4SRC=src/m4
BINSRC=src/bin
JSSRC=src/js
HTMLSRC=src/html
JSONSRC=src/json

TOOLS=tools
M4=m4
BIN=bin
JS=js
BENCH=bench-vjsc
API=api-vjsc
STATANA=$(TOOLS)/staticanalysis
TMP_DIR=tmp

JSHEADER=$(JSSRC)/AGPL_3.0_HEADER.js

all: vjsc min-vjsc bench-vjsc api-vjsc

# Configure what is included by editing this file. The default that
# includes everything can be recovered by "make Makefile.conf". There
# is a target to rebuild the default below.
sinclude Makefile.conf

# Compile all files into a single file. Single inclusion is handled
# with M4 macros.
VERIFICATUM_FILES=$(shell find $(JSSRC) | grep verificatum)
vjsc: $(JS)/$(VJSC).js
$(JS)/$(VJSC).js: $(M4)/filter.m4 $(VERIFICATUM_FILES)
	@mkdir -p $(JS)
	$(TOOLS)/compilejs $(TMP_DIR) $(M4)/filter.m4 $(JSHEADER) $(JSSRC) $(JSSRC)/verificatum/verificatum.js $(JS)/$(VJSC).js

# Generate somewhat minimized library by removing comments and
# redundant newlines.
min-vjsc: $(JS)/min-$(VJSC).js
$(JS)/min-$(VJSC).js: $(JS)/$(VJSC).js
	$(TOOLS)/stripdeco $(JSHEADER) $(JS)/$(VJSC).js $(JS)/min-$(VJSC).js

benchworker: $(JS)/benchworker-$(VJSC_VERSION).js
$(JS)/benchworker-$(VJSC_VERSION).js: $(JSSRC)/benchworker.js
	cat $(M4)/filter.m4 $(JSSRC)/benchworker.js | m4 > $(JS)/benchworker-$(VJSC_VERSION).js


# Generate HTML directory that runs benchmarks. This assumes that no
# functionality of the library has been omitted when building and that
# all groups used are present.
bench-vjsc: $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/version.m4 $(JS)/min-$(VJSC).js $(JS)/benchworker-$(VJSC_VERSION).js $(HTMLSRC)/bench-vjsc.html $(HTMLSRC)/bench-vjsc.css
	@mkdir -p $(BENCH)/
	cp $(JS)/min-$(VJSC).js $(JS)/benchworker-$(VJSC_VERSION).js $(BENCH)/
	cat $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/version.m4 $(HTMLSRC)/bench-vjsc.html | m4 > $(BENCH)/bench-vjsc.html
	cp $(HTMLSRC)/bench-vjsc.css $(BENCH)/
	@rm -f $(BENCH)-*.tar.gz
	tar cvf $(BENCH)-$(VJSC_VERSION).tar $(BENCH)
	gzip $(BENCH)-$(VJSC_VERSION).tar


#############################################################################
############### Development Targets Below ###################################
#############################################################################

# Make sure that our M4 macros are aware of the path to the source
# directory. This allows using relative paths in inclusions.
$(M4)/jssrc.m4: Makefile
	@mkdir -p $(M4)
	@printf "define([[[[[M4_JSSRC]]]]],[[[[[$(JSSRC)]]]]])dnl\n" > $(M4)/jssrc.m4

# Version as an M4 macro.
$(M4)/version.m4: Makefile
	@mkdir -p $(M4)
	@printf "define([[[[[M4_VJSC_VERSION]]]]],[[[[[$(VJSC_VERSION)]]]]])dnl\n" > $(M4)/version.m4
	@echo "Generate version M4 macro in $(M4)/version.m4. ($(VJSC_VERSION))"

# Generate M4 macros for a number of constants that are derived from
# WORDSIZE.
$(M4)/wordsize.m4: $(TOOLS)/gen_wordsize_m4 Makefile
	@mkdir -p $(M4)
	@$(TOOLS)/gen_wordsize_m4 $(MANTISSA) $(WORDSIZE) > $(M4)/wordsize.m4
	@echo "Generate wordsize M4 macros in $(M4)/wordsize.m4. (wordsize = $(WORDSIZE))."

# See Makefile.conf for the targets: $(M4)/enabled.m4.tmp and
# $(M4)/test_enabled.m4.tmp.
$(M4)/enabled.m4: Makefile.conf $(M4)/enabled.m4.tmp
	@cp $(M4)/enabled.m4.tmp $(M4)/enabled.m4
$(M4)/test_enabled.m4: Makefile.conf $(M4)/test_enabled.m4.tmp
	@cp $(M4)/test_enabled.m4.tmp $(M4)/test_enabled.m4

# Combined M4 filters.
$(M4)/filter.m4: $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/jssrc.m4 $(M4)/wordsize.m4 $(M4)/enabled.m4 $(M4)/version.m4
	@echo "dnl" > $(M4)/filter.m4
	@echo "dnl GENERATED CODE BELOW! DO NOT EDIT! See Makefile." >> $(M4)/filter.m4
	@echo "dnl" >> $(M4)/filter.m4
	cat $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/jssrc.m4 $(M4)/version.m4 $(M4)/wordsize.m4 $(M4)/enabled.m4 >> $(M4)/filter.m4

# Combined M4 filters for testing.
$(M4)/test_filter.m4: $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/jssrc.m4 $(M4)/wordsize.m4 $(M4)/test_enabled.m4 $(M4)/version.m4
	@echo "dnl" > $(M4)/test_filter.m4
	@echo "dnl GENERATED CODE BELOW! DO NOT EDIT! See Makefile." >> $(M4)/test_filter.m4
	@echo "dnl" >> $(M4)/test_filter.m4
	cat $(M4SRC)/macros.m4 $(M4SRC)/arithm.m4 $(M4)/jssrc.m4 $(M4)/version.m4 $(M4)/wordsize.m4 $(M4)/test_enabled.m4 >> $(M4)/test_filter.m4

# Generates the default dependencies, that simply enables inclusion of
# all components.
Makefile.conf: $(TOOLS)/getrule $(TOOLS)/getrules $(TOOLS)/getneeds $(VERIFICATUM_FILES)
	@mkdir -p $(TMP_DIR)
	$(TOOLS)/getrules $(TMP_DIR) $(JSSRC) $(M4)/raw_enabled.m4 $(M4)/enabled.m4.tmp $(M4)/test_enabled.m4.tmp Makefile.conf
	@rm -rf $(TMP_DIR)

# Execute all static analyzers.
analysis: jshint eslint $(STATANA)/generate_analysis.sh
	cd $(STATANA); ./generate_analysis.sh
	cat $(STATANA)/analysis_report.txt

# Run static analysis with JSHint
jshint: $(STATANA)/jshint/jshint_report.txt
$(STATANA)/jshint/jshint_report.txt: $(JS)/$(VJSC).js $(STATANA)/jshint/jshint_conf.json
	-@jshint --config $(STATANA)/jshint/jshint_conf.json $(JS)/$(VJSC).js > $(STATANA)/jshint/jshint_report.txt
	cat $(STATANA)/jshint/jshint_report.txt

# Run static analysis with ESLint
eslint: $(STATANA)/eslint/eslint_report.txt
$(STATANA)/eslint/eslint_report.txt: $(JS)/$(VJSC).js
	-@eslint --config $(STATANA)/eslint/eslintrc.js $(JS)/$(VJSC).js > $(STATANA)/eslint/eslint_report.txt
	cat $(STATANA)/eslint/eslint_report.txt

# Library including test code.
test_vjsc: $(JS)/test-$(VJSC).js
$(JS)/test-$(VJSC).js: $(JS)/$(VJSC).js $(M4)/test_filter.m4 $(VERIFICATUM_FILES)
	@mkdir -p $(JS)
	$(TOOLS)/compilejs $(TMP_DIR) $(M4)/test_filter.m4 $(JSHEADER) $(JSSRC) $(JSSRC)/verificatum/test_verificatum.js $(JS)/test-$(VJSC).js

# Run all tests.
check: $(JS)/test-$(VJSC).js
	@nodejs $(JS)/test-$(VJSC).js 5

coverage: $(JS)/test-$(VJSC).js
	istanbul cover $(JS)/test-$(VJSC).js 10

# Minimize test library to test the minimized code.
$(JS)/min-test-$(VJSC).js: $(JS)/test-$(VJSC).js
	$(TOOLS)/stripdeco $(JSHEADER) $(JS)/test-$(VJSC).js $(JS)/min-test-$(VJSC).js

# Run all tests with minimized library.
checkminimized: $(JS)/min-test-$(VJSC).js
	@nodejs $(JS)/min-test-$(VJSC).js 10

# Demo tools that can be used to generate ciphertexts to be used in
# the Verificatum Mix-Net.
jsvmnd: $(BIN)/jsvmnd
$(BIN)/jsvmnd: $(JS)/jsvmnd.js $(BINSRC)/jsvmnd
	@mkdir -p $(BIN)
	cp $(BINSRC)/jsvmnd $(BIN)/
$(JS)/jsvmnd.js: $(JSSRC)/jsvmnd.js $(JS)/$(VJSC).js
	$(TOOLS)/compilejs $(TMP_DIR) $(M4)/filter.m4 $(JSHEADER) $(JSSRC) $(JSSRC)/jsvmnd.js $(JS)/jsvmnd.js

# Complete library wrapped in a script that allows evaluating
# expressions using the command line utility evjs found in this
# package. This is only used for basic debugging of arithmetic, i.e.,
# to ground it for further self-contained testing.
evjs: $(BIN)/evjs
$(BIN)/evjs: $(JS)/evjs.js $(BINSRC)/evjs
	@mkdir -p $(BIN)
	cp $(BINSRC)/evjs $(BIN)/
$(JS)/evjs.js: $(JSSRC)/evjs.js $(JS)/$(VJSC).js
	$(TOOLS)/compilejs $(TMP_DIR) $(M4)/filter.m4 $(JSHEADER) $(JSSRC) $(JSSRC)/evjs.js $(JS)/evjs.js

# Update README file from html source. DO NOT EDIT THE README FILE
# DIRECTLY! (Yes, this is a hack, but a safe one that helps avoiding
# inconsistent documentation.) Edit $(JSSRC)/verificatum/README.js
# instead.
README: $(JSSRC)/verificatum/README.js
	printf "\n\n%10s%s\n\n" "" "VERIFICATUM JAVASCRIPT CRYPTOGRAPHY LIBRARY (VJSC)" > README
	printf "%14s%s\n\n\n" "" "(DO NOT EDIT! Generated file, see Makefile.)" >> README
	cat $(JSSRC)/verificatum/README.js | tr "\n" "\f" | sed "s/{@link \?//g" | sed "s/}//g" | sed "s/ \*      /   /g" | sed "s/ \* //g" | sed "s/ \*\f/\f/g" | sed "s/\(\f<p>\f\)\|\(\f<\/*\(\(ol\)\|\(ul\)\|\(pre\)\)>\f\)//g" | sed "s/<li>/ \*/g" | sed "s/<br>//g" | sed "s/<\/*\(\(em\)\|b\|\(code\)\)>//g" | tr "\f" "\n" >> README

# Generate documentation of API.
api-vjsc: $(JS)/$(VJSC).js
	@mkdir -p $(API)
	$(HOME)/node_modules/jsdoc/jsdoc.js --destination $(API) --verbose $(JS)/$(VJSC).js
	cp $(API)/verificatum.html $(API)/index.html
	@rm -f $(API)-$(VJSC_VERSION).tar.gz
	@rm -f $(API)-$(VJSC_VERSION).tar
	tar cvf $(API)-$(VJSC_VERSION).tar $(API)
	gzip $(API)-$(VJSC_VERSION).tar

install: $(BIN)/jsvmnd $(BIN)/evjs
	cp $(BIN)/jsvmnd $(INSTALLDIR)/
	cp $(JS)/jsvmnd.js $(INSTALLDIR)/
	cp $(BIN)/evjs $(INSTALLDIR)/
	cp $(JS)/evjs.js $(INSTALLDIR)/

uninstall:
	rm $(INSTALLDIR)/jsvmnd
	rm $(INSTALLDIR)/jsvmnd.js
	rm $(INSTALLDIR)/evjs
	rm $(INSTALLDIR)/evjs.js

cleanjshint:
	@rm -rf $(STATANA)/jshint/jshint_report.txt

cleaneslint:
	@rm -rf $(STATANA)/eslint/eslint_report.txt

cleananalysis: cleanjshint cleaneslint
	@rm -rf $(STATANA)/analysis_report.txt

clean: cleananalysis
	@rm -rf $(M4) $(BIN) $(JS) $(API)* $(BENCH)*
	@find . -name "*~" -delete
	@find . -name "*.pyc" -delete

# We show that we remove this Makefile.conf, since it is generated.
totalclean: clean
	rm -f Makefile.conf
