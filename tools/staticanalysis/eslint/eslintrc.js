
// To get the most from ESLint, but remain stable, we consider all its
// possible built-in rules. For each rule we either use it or indicate
// it as a more or less bad rule, or argue that it is not suitable for
// this library. We use the following abbreviations:
//
// BAD_RULE:     This rule should be removed from ESLint.
//
// BAD_GEN_RULE: This rule makes sense in some kinds of code, but
//               should not be used in general. This makes it a
//               questionable rule in a linting tool.
//
// TOO_EARLY:    This rule makes sense, but we will wait until the JS
//               community has settled on the issue until we edit our
//               code. We prioritize stability.
//
// In addition to this we argue briefly and specifically about a
// handful of rules.

module.exports = {
    "env": {
        "browser": true,
        "node": true
    },
    "globals": {
        "Uint8Array": true
    },
    "extends": "eslint:recommended",
    "rules": {
        "accessor-pairs": "error",
        "array-bracket-spacing": [
            "error",
            "never"
        ],
        "array-callback-return": "error",
        "arrow-body-style": "error",
        "arrow-parens": "error",
        "arrow-spacing": "error",
        "block-scoped-var": "error",
        "block-spacing": "error",
        "brace-style": [
            "error",
            "1tbs"
        ],
        "callback-return": "error",
        "camelcase": "off",                  // We use camel case for
                                             // higher level routines
                                             // and underscore style
                                             // for lower-level
                                             // routines.
        "comma-dangle": "error",
        "comma-spacing": [
            "error",
            {
                "after": true,
                "before": false
            }
        ],
        "comma-style": [
            "error",
            "last"
        ],
        "complexity": "error",
        "computed-property-spacing": [
            "error",
            "never"
        ],
        "consistent-return": "error",
        "consistent-this": "error",
        "curly": "error",
        "default-case": "error",
        "dot-location": "error",
        "dot-notation": "error",
        "eol-last": "error",
        "eqeqeq": "error",
        "func-names": [
            "error",
            "never"
        ],
        "func-style": "off",                  // We use function style
                                              // to signal that it is
                                              // used as a class and
                                              // expression style
                                              // otherwise.
        "generator-star-spacing": "error",
        "global-require": "off",
        "guard-for-in": "error",
        "handle-callback-err": "error",
        "id-blacklist": "error",
        "id-length": "off",                   // We use short
                                              // identifiers when
                                              // proper, e.g., in
                                              // arithmetic routines
                                              // where we want to use
                                              // consistent notation
                                              // to the literature.
        "id-match": "error",
        "indent": [
            "off",
            4
        ],
        "init-declarations": "off",
        "jsx-quotes": "error",
        "key-spacing": [
            "error",
            {
                "beforeColon": false,
                "afterColon": true
            }
        ],
        "keyword-spacing": "error",
        "linebreak-style": [
            "error",
            "unix"
        ],
        "lines-around-comment": "off",
        "max-depth": "error",
        "max-len": "off",                     // Our computable script
                                              // is compiled from
                                              // multiple files to get
                                              // a single file with
                                              // proper
                                              // encapsulation. Our
                                              // source files use 80
                                              // character line
                                              // length, but some
                                              // hexadecimal constants
                                              // do not.
        "max-lines": "off",                   // We intentionally
                                              // generate one single
                                              // library file.
        "max-nested-callbacks": "error",
        "max-params": "off",                  // We need to have many
                                              // parameters in some
                                              // low-level code.
        "max-statements": "off",              // Setting this strictly
                                              // makes no sense in
                                              // algorithmic code.
        "max-statements-per-line": [
            "error",
            {
                "max": 1
            }
        ],
        "multiline-ternary": "off",
        "new-parens": "error",
        "newline-after-var": "off",           // BAD_GEN_RULE
        "newline-before-return": "off",       // BAD_GEN_RULE
        "newline-per-chained-call": "off",    // BAD_GEN_RULE
        "no-alert": "error",
        "no-array-constructor": "error",
        "no-bitwise": "off",                  // We use bit-wise
                                              // operators in
                                              // arithmetic code.
        "no-caller": "error",
        "no-catch-shadow": "error",
        "no-confusing-arrow": "error",
        "no-continue": "error",
        "no-div-regex": "error",
        "no-duplicate-imports": "error",
        "no-else-return": "off",              // This is a bad general
                                              // rule.
        "no-empty-function": "off",           // This makes no sense
                                              // for object oriented
                                              // programming where
                                              // base classes may have
                                              // empty "constructors".
        "no-eq-null": "error",
        "no-eval": "error",
        "no-extend-native": "error",
        "no-extra-bind": "error",
        "no-extra-label": "error",
        "no-extra-parens": "error",
        "no-floating-decimal": "error",
        "no-implicit-globals": "error",
        "no-implied-eval": "error",
        "no-inline-comments": "off",          // BAD_GEN_RULE
        "no-inner-declarations": [
            "error",
            "functions"
        ],
        "no-invalid-this": "error",
        "no-iterator": "error",
        "no-label-var": "error",
        "no-labels": "error",
        "no-lone-blocks": "error",
        "no-lonely-if": "off",                // BAD_GEN_RULE
        "no-loop-func": "error",
        "no-magic-numbers": "off",            // Arithmetic code
                                              // contains magic
                                              // numbers.
        "no-mixed-operators": "off",          // Operators have precedence
        "no-mixed-requires": "error",         // for a reason.

        "no-multi-spaces": "off",             // This handles comments
	                                      // incorrectly.
        "no-multi-str": "error",
        "no-multiple-empty-lines": "error",
        "no-negated-condition": "error",
        "no-nested-ternary": "error",
        "no-new": "error",
        "no-new-func": "error",
        "no-new-object": "error",
        "no-new-require": "error",
        "no-new-wrappers": "error",
        "no-octal-escape": "error",
        "no-param-reassign": "off",           // BAD_GEN_RULE
        "no-path-concat": "error",
        "no-plusplus": "off",                 // Using this rule would
                                              // make low-level
                                              // routines harder to
                                              // read.
        "no-process-env": "error",
        "no-process-exit": "error",
        "no-proto": "error",
        "no-prototype-builtins": "error",
        "no-restricted-globals": "error",
        "no-restricted-imports": "error",
        "no-restricted-modules": "error",
        "no-restricted-syntax": "error",
        "no-return-assign": "error",
        "no-script-url": "error",
        "no-self-compare": "error",
        "no-sequences": "error",
        "no-shadow": "off",                   // BAD_GEN_RULE
        "no-shadow-restricted-names": "error",
        "no-spaced-func": "error",
        "no-sync": "error",
        "no-ternary": "off",                  // BAD_GEN_RULE
        "no-throw-literal": "error",
        "no-trailing-spaces": "error",
        "no-undef-init": "error",
        "no-undefined": "error",
        "no-underscore-dangle": "error",
        "no-unmodified-loop-condition": "error",
        "no-unneeded-ternary": "error",
        "no-unused-expressions": "error",
        "no-use-before-define": "error",
        "no-useless-call": "error",
        "no-useless-computed-key": "error",
        "no-useless-concat": "error",
        "no-useless-constructor": "error",
        "no-useless-escape": "error",
        "no-useless-rename": "error",
        "no-var": "off",                      // TOO_EARLY(to only use
                                              // let and const)
        "no-void": "error",
        "no-warning-comments": "error",
        "no-whitespace-before-property": "error",
        "no-with": "error",
        "object-curly-newline": "off",        // BAD_GEN_RULE
        "object-curly-spacing": [
            "error",
            "always"
        ],
        "object-property-newline": [
            "error",
            {
                "allowMultiplePropertiesPerLine": false
            }
        ],
        "object-shorthand": "off",            // BAD_GEN_RULE
        "one-var": "off",                     // BAD_RULE
        "one-var-declaration-per-line": "error",
        "operator-assignment": "off",         // BAD_GEN_RULE
        "operator-linebreak": "error",
        "padded-blocks": "off",               // BAD_RULE
        "prefer-arrow-callback": "off",       // TOO_EARLY(to use
                                              // arrow notation)
        "prefer-const": "error",
        "prefer-reflect": "off",              // TOO_EARLY(to switch
                                              // approach)
        "prefer-rest-params": "error",
        "prefer-spread": "error",
        "prefer-template": "off",             // TOO_EARLY(to use
                                              // formatting)
        "quote-props": "error",
        "quotes": [
            "error",
            "double"
        ],
        "radix": "error",
        "require-jsdoc": "error",
        "rest-spread-spacing": "error",
        "semi": [
            "error",
            "always"
        ],
        "semi-spacing": "error",
        "no-extra-semi": "off",                // This rule can not be
                                               // disabled for extra
                                               // semi-colons after
                                               // functions. This is
                                               // wrong for
                                               // readability and
                                               // consistency, so we
                                               // can not use this
                                               // rule.
        "sort-imports": "error",
        "sort-vars": "error",
        "space-before-blocks": "error",
        "space-before-function-paren": [
            "off",
            {
                "anonymous": "always",
                "named": "never"
            }
        ],
        "space-in-parens": [
            "error",
            "never"
        ],
        "space-infix-ops": "error",
        "space-unary-ops": "error",
        "spaced-comment": [
            "error", "always"
        ],
        "strict": [
            "error",
            "never"
        ],
        "template-curly-spacing": "error",
        "unicode-bom": [
            "error",
            "never"
        ],
        "valid-jsdoc": "off",                 // We use doxygen.
        "vars-on-top": "off",                 // BAD_RULE
        "wrap-regex": "error",
        "yield-star-spacing": "error",
        "no-case-declarations": "error",
        "no-empty-pattern": "error",
        "no-fallthrough": "error",
        "no-implicit-coercion": "error",
        "no-native-reassign": "error",
        "no-redeclare": "error",
        "no-self-assign": "error",
        "no-unused-labels": "error",
        "wrap-iife": [                        // Arbitrary, but good
                                              // to be consistent.
            "error",
            "inside"
        ],
        "yoda": "error"
    }
};