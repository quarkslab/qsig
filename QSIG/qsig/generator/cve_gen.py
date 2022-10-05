import logging
import pathlib
import tempfile
from typing import Union, Optional, Generator, Tuple

import qsig

PathLike = Union[pathlib.Path, str]


logger = logging.getLogger(__name__)


class CveGenerator:
    def __init__(self, cve: "qsig.cve.Vulnerability"):
        self.cve: "qsig.cve.Vulnerability" = cve
        self.signature = qsig.sig.CVESignature()

        self.file_generators = []

    def generate(
        self, arch: "qsig.cve.Architecture" = qsig.cve.Architecture.x64
    ) -> bool:
        self.signature.set_meta(self.cve, arch)
        for fix_file, vuln_file in self.select_files(arch):
            logger.info("Start to generate the signature for file %s", fix_file.name)
            file_generator = qsig.generator.FileGenerator(
                self, self.signature.add_file(), fix_file, vuln_file
            )
            if file_generator.generate():
                self.file_generators.append(file_generator)
            else:
                self.signature.remove_last_file()

        if not any(self.file_generators):
            logger.info(
                "",
                extra={
                    "bench": True,
                    "type": "generator",
                    "cve": self.cve.name,
                    "commit": getattr(self.cve, "cve_commit", ""),
                    "level": "cve",
                    "generated": False,
                    "reason": "unknown",
                },
            )
        else:
            logger.info(
                "",
                extra={
                    "bench": True,
                    "type": "generator",
                    "cve": self.cve.name,
                    "commit": getattr(self.cve, "cve_commit", ""),
                    "level": "cve",
                    "generated": True,
                    "files": len(self.file_generators),
                },
            )

        return any(self.file_generators)

    def save(self, output_file: Optional[PathLike]) -> Optional[pathlib.Path]:
        if output_file is None:
            output_file = tempfile.mktemp(suffix=".sig")

        if self.file_generators:
            logger.debug("Wrote signature in %s", output_file)
            self.signature.write(pathlib.Path(output_file))
            return output_file

        logger.error("Failed to save the signature")
        return None

    def select_files(self, arch) -> Generator[Tuple[PathLike, PathLike], None, bool]:

        for stripped in [False, True]:
            binaries = self.cve.get_tuples(arch, stripped=stripped)
            if binaries:
                break

            logger.info("No files found for vulnerability (%s)", stripped)
        else:
            return False

        for fix_binary, vuln_binary in binaries:
            yield fix_binary, vuln_binary

        return True
