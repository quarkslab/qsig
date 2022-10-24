from __future__ import annotations

import itertools
import pathlib
from typing import List, Optional, Dict, Any


import firmextractor
import networkx
import quokka

import bgraph.viewer
import bgraph.types
from bgraph.viewer.viewer import get_graph_srcs

import qsig
from qsig.detector import Detector


def find_final_targets(graph: bgraph.types.BGraph, target: str) -> List[str]:
    """Find the "final" targets of a node

    Args:
        graph: A BGraph to search
        target: A target in the graph

    Returns:
        A list of ("cc_library", "cc_library_shared", "cc_binary") target
    """

    try:
        worklist: List[str] = [target]
    except networkx.NetworkXError:
        raise qsig.exc.DetectorException("Static target not found in graph")

    results: List[str] = []
    while worklist:
        node = worklist.pop()
        node_type = bgraph.viewer.get_node_type(graph.nodes[node], all_types=False)
        if node_type in (
            "cc_library",
            "cc_library_static",
        ):
            try:
                successors = list(graph.successors(node))
            except networkx.NetworkXError:
                # Node does not exist
                continue

            if not successors and node_type == "cc_library":
                results.append(node)
            elif successors:
                worklist.extend(successors)

        elif node_type in (
            "cc_library_shared",
            "cc_binary",
        ):
            results.append(node)

    return results


class FileDetector(Detector):
    """Detector at a file level

    Args:
        signature: A path towards the file signature
        program_holder: A program loader
        parent: The CVEDetector associated
    """

    def __init__(
        self,
        signature: qsig.sig.FileSignature,
        program_holder: qsig.program.ProgramLoader,
        parent: qsig.detector.CVEDetector,
        **kwargs: Any,
    ):
        """Initialization"""
        self.signature: qsig.sig.FileSignature = signature
        self.parent: qsig.detector.CVEDetector = parent

        self.bgraph: Optional[bgraph.types.BGraph] = kwargs.get("bgraph", None)
        self._valid_targets: Optional[List[str]] = None

        self.chunk_matchers: List[qsig.detector.ChunkDetector] = []
        for chunk_signature in self.signature.chunk_signatures:
            self.chunk_matchers.append(
                qsig.detector.ChunkDetector(chunk_signature, self, **kwargs)
            )

        self._binary_file: Optional[firmextractor.fs.ExecutableFile] = None
        self.loader: qsig.program.ProgramLoader = program_holder

    def __str__(self) -> str:
        """String representation"""
        result = f"<FileDetector for file {self.signature.file_name} with :"
        for chunk_matcher in self.chunk_matchers:
            result += f"\n\t {chunk_matcher}"
        result += "\n>"
        return result

    @property
    def binary_file(self) -> firmextractor.fs.ExecutableFile:
        """Returns the binary file."""
        if self._binary_file is None:
            raise qsig.exc.DetectorException("Binary file not loaded yet")

        return self._binary_file

    @binary_file.setter
    def binary_file(self, value: firmextractor.fs.ExecutableFile) -> None:
        """Set a binary file and reset the program"""
        if self._binary_file != value:
            self._binary_file = value

    @property
    def program(self) -> quokka.Program:
        """Returns a quokkaed file from the binary file.

        To not pollute the image directory, a shadow filesystem is used.

        Raises:
            DetectorException when no file has been loaded

        Returns:
            The program representation

        """
        export_file = self.binary_file.firmware.file_in_shadow(
            self.binary_file.path, extension=".quokka"
        )

        database_file = self.binary_file.firmware.file_in_shadow(
            self.binary_file.path, extension=".i64"
        )
        program = None
        try:
            program = self.loader.from_binary(
                self.binary_file.path, export_file, database_file=database_file
            )
        except FileNotFoundError:
            self.logger.error("Unable to export or load %s", self.binary_file.path)
            pass

        if program is None:
            raise qsig.exc.DetectorException("Unable to export")
        else:
            return program

    @property
    def valid_targets(self) -> List[str]:
        """For the prematch, precompute valid targets for the binary.

        This methods need a BGraph to work.

        Returns:
            A list of node inside the BGraph that should be matched
        """
        if self._valid_targets is not None:
            return self._valid_targets

        self._valid_targets = []

        if self.bgraph is None:
            return self._valid_targets

        signature_type = self.signature.file_type
        # Case 1: candidate is an object file (e.g. foo.o)
        if signature_type == firmextractor.fs.FileType.OBJECT:

            # Get the sources
            graph_sources = get_graph_srcs(self.bgraph)

            # Find the static libraries that could be impacted
            # TODO(dm) test if the object file could be part of a shared lib
            potential_targets: List[List[str]] = []
            for node in filter(
                lambda name: f"{self.signature.file_name}." in name, graph_sources
            ):

                if any(node.endswith(suffix) for suffix in (".h", ".hpp")):
                    continue

                _, targets = bgraph.viewer.find_target(
                    self.bgraph,
                    node,
                    radius=1,
                )
                if targets:
                    potential_targets.append(targets)

            if not potential_targets:
                self.logger.warning(f"Prematch failed.")
            else:
                targets = {
                    target
                    for target in itertools.chain.from_iterable(potential_targets)
                }

                # Final target is finally a list of either shared lib or executable
                final_targets = set()
                for target in targets:
                    final_targets.update(find_final_targets(self.bgraph, target))

                self._valid_targets = list(final_targets)

        # Case 2: candidate is a library so we need to match the same library
        #      3: candidate is an executable so we need to match the same one
        elif signature_type in (
            firmextractor.fs.FileType.LIBRARY,
            firmextractor.fs.FileType.EXECUTABLE,
        ):

            potential_target = next(
                (
                    node
                    for node in self.bgraph
                    if pathlib.Path(node).stem == self.signature.file_name
                ),
                None,
            )

            if potential_target:
                self._valid_targets = [potential_target]

        elif signature_type in (
            firmextractor.fs.FileType.STATIC,
            firmextractor.fs.FileType.BLOB,
        ):
            raise NotImplementedError("PreMatch on STATIC/BLOB no implemented.")

        return self._valid_targets

    def accept(self, binary_file: firmextractor.fs.ExecutableFile) -> bool:
        """Accepts a binary file.

        The prematch uses BGraphes to perform his duty.
        This will only work for vulnerabilities affecting AOSP for which the dependency
        chain is known.

        Args:
            binary_file: The candidate binary

        Returns:
            Boolean for success
        """
        prematch_result: bool = False

        # Case 1: we have a bgraph to do the prematch
        if self.bgraph is not None:
            if qsig.sig.utils.norm_name(binary_file.path) in self.valid_targets:
                prematch_result = True

        # Case 2: we don't. In this case the prematch is *best* effort, we just check
        # the type of the candidate and the name.
        # Note: This will not work for object files for instance
        else:
            candidate_type = firmextractor.fs.get_filetype(
                binary_file.path, binary_file.mime_type
            )
            signature_type = self.signature.file_type

            # First, check binary type
            if candidate_type == signature_type:
                # Second, check names (or alternatives names)
                signature_name = self.signature.file_name
                if signature_name in binary_file.path.stem or any(
                    signature_name in alternatives
                    for alternatives in binary_file.alternative_names
                ):
                    prematch_result = True

        if self.logger.isEnabledFor(qsig.Verbosity.BENCHMARK):
            self.logger.info(
                "",
                extra={
                    "bench": True,
                    "type": "prematch",
                    "cve": self.signature.cve_signature.cve_id,
                    "commit": self.signature.cve_signature.commit,
                    "file": binary_file.path.as_posix(),
                    "targets": self.valid_targets if self.bgraph is not None else [],
                    "prematch_result": prematch_result,
                },
            )

        return prematch_result

    def match(self, binary_file: firmextractor.fs.ExecutableFile) -> bool:
        """Try to match a binary file for this detector

        The file matcher does not do anything yet, it just pass the results to the
        underlying chunk detectors.

        Args:
            binary_file: A binary file

        Returns:
            Boolean for success
        """

        self.binary_file = binary_file

        chunk_results: Dict[qsig.detector.ChunkDetector, bool] = {}
        for chunk_matcher in self.chunk_matchers:
            chunk_result = chunk_matcher.match(binary_file)
            if chunk_result:
                chunk_results[chunk_matcher] = chunk_result

        if len(chunk_results) == len(self.chunk_matchers):
            self.logger.info("Complete chunk match for %s", binary_file.path)
            return True
        elif len(chunk_results) > 0:
            self.logger.info("Partial chunk match for %s", binary_file.path)
            return True
        else:
            return False
