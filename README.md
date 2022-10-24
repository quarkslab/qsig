# Towards 1-day Vulnerability Detection using Semantic Patch Signatures

_by Alexis Challande_

## Disclamer

This work is highly experimental and guaranteed to **only** work on the developer computer.

It serves mostly as an additional reading material rather than a functional artefact.

## Introduction

This repository contain the code of QSig and its companion projects. The objective of the tool is to detect vulnerability patches in firmware image (e.g. filesystems).

To do so, it implements a three step strategy :

* Filtering: to select appropriate binaries within the firmware
* Selecting: to find appropriate functions with a selected program
* Matching: to guess the function version (or state)

This approach is described in the Thesis and its accompanying paper (to be published).

## Installation

### Prerequisites

The code has only been tested on Debian 11 and with Python 3.8-3.10.
To install BinCAT, you will also need OCaml (version `4.05.0` is known to work).


### Installation

1. Install [BinCAT fork](bincat/README.md) following the instruction in the repository.
2. Install [firmwextractor](firmware_extractor/README.md) 
3. Install [QSig](QSIG/README.md)

Note: Installing everything in a virtualenv is recommended.

## Usage

### As a CLI

Using QSig with its CLI interface is best when performing simple queries on a
supported Android device or on a single binary.

```command
$ python -m qsig --help
Usage: qsig [OPTIONS] COMMAND [ARGS]...

  QSIG CLI - Use to generate signature or match firmwares images

Options:
  -d, --debug           Activate debug output  [default: False]
  -q, --quiet           Silence output  [default: False]
  -b, --bench           Activate benchmark output  [default: False]
  --install-completion  Install completion for the current shell.
  --show-completion     Show completion for the current shell, to copy it or
                        customize the installation.

  --help                Show this message and exit.

Commands:
  detect             Apply a signature onto a file.
  detector           Detect if a patch has been applied to a firmware
                      image...
  generate           Generate a signature based on a CVE directory
  generate-multiple  Generate signature for every CVE found in a directory.
  info               Dump info on the signatures.
```

Example:
```command
  $ python -m qsig detect libbluetooth.so CVE-2018-9506.sig
  INFO: libbluetooth.so was matched with the signature 
        (using ['strings', 'constants'])
  INFO: Complete chunk match for libbluetooth.so
  INFO: CVE Match for CVE-2018-9506 on libbluetooth.so
```

### As a Library

QSig interface is insufficient to answer every query, and a user may want to
change some of QSig's behavior more deeply. Thus QSig is also available as a
library. However, its usage is more complex.

Example: The following snippet shows how to implement a custom Detector that checks if a binary contain specified strings.

```python

from firmextractor.fs import ExecutableFile
from qsig.detector import Detector

def get_strings(fw_file: ExecutableFile) -> set[str]:
    """Returns `fw_file' strings"""
    ...

class MyDetector(Detector):
    """Simple File Detector to assess whether a candidate 
        has a specific string.
    """
    def __init__(self, match_string: str):
        """Constructor"""
        self.match_string = match_string
    
    def accept(self, fw_file: ExecutableFile) -> bool:
        """Check whether `fw_file' is accepted"""
        return True
    
    def match(self, fw_file: ExecutableFile) -> bool:
        """Perform the match."""
        return self.match_string in get_strings(fw_file)
```

The detector generated above is usable with the following code:
```python
from pathlib import Path
from firmextractor.fs import FileSystem

def search_string(file_system: Path, string: str):
    file_system = FileSystem(file_system)
    detector = MyDetector(string)

    for exec_file in file_system.elf_files():
        if detector.accept(exec_file):
            print(f"Match Result: {cve_detector.match(exec_file)}")
```