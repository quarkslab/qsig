import logging
import pathlib
import re
from typing import Union, Optional, Set, List, Generator

import qsig.generator
import quokka
import quokka.function


PathLike = Union[pathlib.Path, str]
"""Type for Path-Like object."""

logger = logging.getLogger(__name__)


def get_func_by_name(
    program: quokka.Program,
    name: str,
) -> quokka.function.Function:
    try:
        return program.get_function(name, approximative=True, normal=True)
    except ValueError:
        pass

    if "(" in name:
        name = name[: name.index("(")]

    return program.get_function(name, approximative=True, normal=True)


class FileGenerator:
    def __init__(
        self,
        parent: "qsig.generator.CveGenerator",
        signature,
        fix_file: PathLike,
        vuln_file: PathLike,
    ):
        self.parent = parent
        self.signature = signature

        self.fix_file: quokka.Program = self.load_program(fix_file)
        self.vuln_file: quokka.Program = self.load_program(vuln_file)

        if self.fix_file is None or self.vuln_file is None:
            raise qsig.exc.GeneratorException("Unable to load one of the exports")

        self.chunk_generators = []

    @staticmethod
    def load_program(path: pathlib.Path) -> Optional[quokka.Program]:
        debug = logger.getEffectiveLevel() == logging.DEBUG
        program = quokka.Program.from_binary(
            path, debug=debug, timeout=qsig.Settings.EXPORT_TIMEOUT
        )
        return program

    def get_functions(self) -> Generator[str, None, None]:
        """Get the functions for the file to generate the signature.

        Yields:
            Functions name
        """

        # First solution: get the BinDiff results
        file_name: str = self.fix_file.executable.exec_file.stem
        file_hash: str = qsig.sig.sha256_file(self.fix_file.executable.exec_file)
        if file_name.startswith(file_hash):
            file_name = file_name[len(file_hash) + 1 :]

        functions: Optional[List[str]] = None
        try:
            functions = self.parent.cve.functions_by_file(file_name)
        except (ValueError, NotImplementedError):
            pass

        try:
            for function_name in functions:
                yield function_name

            return
        except TypeError:
            pass

        # Second solution: get the listed functions in the functions.json file
        # Note that we also iterate to find functions with different strings "just in
        # case"
        function_list: Set[str] = set(self.parent.cve.functions())
        for fun_name in set(self.fix_file.fun_names).intersection(
            self.vuln_file.fun_names
        ):
            if fun_name.startswith("sub_"):
                continue

            strings_diff = set(self.fix_file.fun_names[fun_name].strings).difference(
                self.vuln_file.fun_names[fun_name].strings
            )
            if any(re.match(r"^(b/)?[0-9]+$", string) for string in strings_diff):
                function_list.add(fun_name)

        for function_name in function_list:
            yield function_name

        if not function_list:
            raise qsig.exc.NoFuncException(
                "Unable to find different function target in file"
            )

    def generate(self) -> bool:
        """Generate a signature for a file

        Returns:
            Boolean for success
        """
        self.signature.set_file_meta(self.fix_file.executable.exec_file)

        functions: Optional[Generator[str]] = None
        try:
            functions = self.get_functions()
        except qsig.exc.NoFuncException:
            pass

        if functions is not None:
            for function_name in sorted(functions):
                logger.debug("Try to generate signature for function %s", function_name)

                if self.generate_for_func(function_name):
                    logger.info("Generated for function %s with success", function_name)
                else:
                    logger.error("Failed to generate for function %s", function_name)
                    logger.info(
                        "",
                        extra={
                            "bench": True,
                            "type": "generator",
                            "cve": self.parent.cve.name,
                            "commit": getattr(self.parent.cve, "cve_commit", ""),
                            "file": self.fix_file.executable.exec_file.name,
                            "func_name": function_name,
                            "generated": False,
                            "level": "func",
                            "reason": "unknown",
                        },
                    )

        else:
            logger.info(
                "Failed to generate for file %s (missing function)",
                self.fix_file.executable.exec_file.name,
            )
            logger.info(
                "",
                extra={
                    "bench": True,
                    "type": "generator",
                    "cve": self.parent.cve.name,
                    "commit": getattr(self.parent.cve, "cve_commit", ""),
                    "file": self.fix_file.executable.exec_file.name,
                    "generated": False,
                    "level": "file",
                    "reason": "no func",
                },
            )

        return any(self.chunk_generators)

    def generate_for_func(self, function_name: str) -> bool:
        try:
            fix_function = get_func_by_name(self.fix_file, function_name)
        except ValueError:
            logger.error("Unable to find fix function")
            return False

        try:
            # TODO(dm) check if the vuln function is the same as the fix one
            vuln_function = get_func_by_name(self.vuln_file, function_name)
        except ValueError:
            logger.info("Unable to find vuln function")
            vuln_function = None

        try:
            vuln_chunks = iter(vuln_function.values())
        except AttributeError:
            vuln_chunks = iter({})

        results: List[bool] = []

        for fix_chunk in fix_function.values():
            # Check that we have not already generated a signature for this chunk
            if fix_chunk in [
                generator.fix_chunk for generator in self.chunk_generators
            ]:
                logger.debug(
                    "Skip chunk 0x%x because already generated", fix_chunk.start
                )
                continue

            vuln_chunk: Optional[quokka.function.Chunk] = next(vuln_chunks, None)

            chunk_generator = qsig.generator.ChunkGenerator(
                self, self.signature.add_chunk_signature(), fix_chunk, vuln_chunk
            )
            result: bool = False
            if chunk_generator.has_differences:
                logger.info(
                    "Found %s differences for chunk",
                    [diff.name for diff in chunk_generator.differences],
                )
                result = chunk_generator.generate()
            else:
                logger.info("Did not found differences for chunk.")
                logger.info(
                    "",
                    extra={
                        "bench": True,
                        "type": "generator",
                        "cve": self.parent.cve.name,
                        "commit": getattr(self.parent.cve, "cve_commit", ""),
                        "file": self.fix_file.executable.exec_file.name,
                        "generated": False,
                        "level": "chunk",
                        "reason": "no diff",
                    },
                )

            if result:
                self.chunk_generators.append(chunk_generator)
                results.append(result)
            else:
                self.signature.remove_last_chunk()

        return any(results)
