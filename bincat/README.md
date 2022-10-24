# BinCAT

BinCAT is used in QSig to compute the comparisons terms origin.

Some relaxations were implemented to improve QSig efficiency, however, they **break** BinCAT soudness.

## Relaxations (using BinCAT mechanisms)

* Ignore calls and only taint the return values
* Ignore undecoded instructions
* Do not follow backward edges and immediately widen the state

## List of modifications

* Add the support for some THUMB instructions
* Add `Failed_decoding` exception to resume execution when the decoding failed
* Support for a `[cfg]` section to help BinCAT find the jump target (for switches)
* Add some custom sections for argument taint to allow dereferencing an argument within its own section

## Usage

The patch has been generated from the difference between our local version and BinCAT d1ef5c4e. However, due to some `git` issues, some modification from `BinCAT`'s original authors are included in the `patch.diff` file.


## Installation

* Install BinCAT dependencies
* Checkout to `d1ef5c4e`
* Apply the patch to the source tree
* Build BinCAT.
* Add the resulting binary to `$PATH`