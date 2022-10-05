# BinCAT

BinCAT is used in QSig to compute the comparisons terms origin.

Some relaxations were implemented to improve QSig efficiency, however, they **break** BinCAT soudness.

## Relaxations

* Ignore calls and only taint the return values
* Ignore undecoded instructions
* Do not follow backward edges and immediately widen the state

## Usage

The patch has been generated from the difference between our local version and BinCAT v1.2.
