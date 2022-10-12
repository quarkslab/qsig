# QSig

This repository includes research work done by Alexis Challande at Quarkslab as part of his
*Towards 1-day Vulnerability Detection using Semantic Patch Signatures* Phd thesis.

QSig is the prototype developed to solve the _Firmware Matching Problem_ using
the _Filtering-Selecting-Matching_ strategy.

The code here is **highly** experimental, and will probably work only on the
developer computer. It should not be seen as a working **tool** but merely as a
improved documentation and supplementary material for the paper and the
manuscript.

## Dependencies

QSig uses several dependencies:

* [quokka](https://github.com/quarkslab/quokka) to generate export file and
  manipulate them
* IDA to disassemble the binaries
* BinCAT to perform a tainting algorithm (see the bincat within the repository)
* BinDiff (optional) to find the changed functions between two binaries

## Architecture

QSig is composed of two complementary components.
It is composed of a command line allowing to easily use the tool, but also
usable as a library.

### Generator

The _generator_ generates a signature from the difference between two binaries.
To find the named / addresses of the function changed, it uses the
`functions_by_file` method of the `Vulnerability` class. This is implemented
currently for two backends: artifacts from AOSP CVE dataset
[aosp_dataset](https://github.com/quarkslab/aosp_dataset) and the [Cyber Grand Challenge](https://www.darpa.mil/program/cyber-grand-challenge) vulnerabilities.

The generator's output is a signature, in the protobuf format.
The definition of the signature is found in [signature.proto](qsig/signature.proto).

### Detector

The detector applies signatures onto a file or a filesystem.
To load a device image, a small project (`firmextractor`) is used. This is also
present in the same repostiory and is mainly chaining commands to extract a raw
image into something usable.

## Support

No support is available for QSig
