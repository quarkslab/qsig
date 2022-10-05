from __future__ import annotations
import collections
import io
import logging

import firmextractor
import yara
from typing import Any, Optional, List, Dict, Tuple, Union, Generator, Set
import pathlib
import quokka
import quokka.exc
import quokka.types
from quokka.function import Chunk, Function

import qsig
from qsig.detector.detector import Detector
import qsig.signature_pb2


logger = logging.getLogger(__name__)


class ChunkDetector(Detector):
    """Detector at a chunk level"""

    def __init__(
        self,
        signature: qsig.sig.ChunkSignature,
        parent: "qsig.detector.FileDetector",
        **kwargs: Any,
    ):

        self.signature: qsig.sig.ChunkSignature = signature
        self.parent: "qsig.detector.FileDetector" = parent

        self._candidate_chunks: Optional[List[Chunk]] = None

        self._signature_conditions: Optional[Dict[qsig.sig.Condition, int]] = None
        self._labels_collection: Optional[qsig.sig.LabelsCollection] = None

    def __str__(self) -> str:
        return f"<ChunkDetector using {[x.name for x in self.signature.artifact_type]}>"

    @property
    def program(self) -> quokka.Program:
        """Wrapper to the program attribute"""
        return self.parent.program

    def match_string_signature(self) -> bool:
        """Matcher for the string signature.

        This matcher use a YARA rule to detect the strings in a binary and does *not*
        need to decompile the binary (way faster).

         Returns:
             Boolean for success
        """

        if qsig.sig.Artefact.STRINGS not in self.signature.artifact_type:
            return False

        buffer = io.BytesIO(self.signature.string_signature)
        rules = yara.load(file=buffer)

        if rules.match(pathlib.Path(self.parent.binary_file.path).as_posix()):
            return True

        return False

    def match_local_string_signature(
        self, already_matched: bool = False
    ) -> Tuple[List[quokka.types.AddressT], List[quokka.types.AddressT]]:

        if qsig.sig.Artefact.STRINGS not in self.signature.artifact_type:
            return [], []

        local_strings: Set[str] = self.signature.string_signature_local

        match_strings: List[quokka.types.AddressT] = []
        wrong_match: List[quokka.types.AddressT] = []
        for target_chunk in self.candidate_chunks:
            if any(x in target_chunk.strings for x in local_strings):
                match_strings.append(target_chunk.start)

            # FIX: YARA has a problem and cannot detect substring efficiently
            #      The fix here check if any of the signature strings is a substring of
            #      a candidate string. If this is the case, we cannot rely on the YARA
            #      matching.
            if already_matched:
                for string in target_chunk.strings:
                    if any(sig_string in string for sig_string in local_strings):
                        wrong_match.append(target_chunk.start)
                        break

        return match_strings, wrong_match

    @property
    def candidate_chunks(self) -> List[Chunk]:
        """Returns a list of potential chunks to test the condition.

        The signature has been established on chunk, so we need to match it against
        chunks. However, we do not know which one to pick. This methods selects
        SIMILAR_CHUNK (usually 5) from the binary as candidates

        An un-optimized and probably not so good scoring system is used :
            - best case: we have common strings so we use them (weight = 10)
            - if the chunk belongs to a named function, use this name similarity
                (weight = 8)
            - if the chunk index in the program is close, use that (weight = 6)
            - if the function index is close, use it (weight = 4)
            - finally, if the size are similar weight it (weight = 2)

        TODO:
            Use constants as well but it will be a huge perf hit

        Returns:
            A list of chunks

        """
        if not self._candidate_chunks:
            self._candidate_chunks = []
            target_chunk = qsig.sig.ChunkIdentifier.from_proto(
                self.signature.chunk_identifier
            )

            target_strings = set(target_chunk.strings)
            target_constants = set(target_chunk.constants)

            potential_chunks = collections.Counter()
            chunk_features = dict()
            for chunk_index, chunk in enumerate(self.program.iter_chunk()):
                if chunk.chunk_type != quokka.types.FunctionType.NORMAL:
                    continue

                scores = dict()
                scores["STRINGS"] = qsig.sig.utils.inclusion_index(
                    target_strings, chunk.strings
                )

                scores["FUNC_NAME"] = 0
                try:
                    function = self.program.get_first_function_by_chunk(chunk)

                    if (
                        not target_chunk.func_name.startswith("sub_")
                        and not function.name.startswith("sub_")
                        and target_chunk.func_name != ""
                    ):
                        scores["FUNC_NAME"] = 1 - qsig.sig.utils.levenstein(
                            target_chunk.func_name, function.name
                        )

                except quokka.exc.FunctionMissingError:
                    function = None

                extern_calls = qsig.sig.utils.get_extern_calls(chunk)
                scores["CALLS"] = qsig.sig.utils.jaccard_index(
                    extern_calls, target_chunk.calls
                )

                # scores["CHUNK_INDEX"] = qsig.sig.utils.small_difference(target_chunk.index, chunk_index)

                chunk_constants = [
                    cst
                    for cst in set(qsig.sig.utils.norm_constants(set(chunk.constants)))
                    if qsig.Settings.MIN_CONSTANT <= cst <= qsig.Settings.MAX_CONSTANT
                ]
                scores["CONSTANTS"] = qsig.sig.utils.inclusion_index(
                    target_constants, chunk_constants
                )

                scores["FUNC_INDEX"] = 0
                if function is not None and target_chunk.func_index >= 0:
                    # TODO(dm) should quokka maintain an OrderedDict of functions ?
                    function_index = sorted(self.program).index(function.start)
                    scores["FUNC_INDEX"] = qsig.sig.utils.small_difference(
                        target_chunk.func_index, function_index
                    )

                scores["SIZE"] = qsig.sig.utils.small_difference(
                    chunk.size, target_chunk.size
                )

                potential_chunks[chunk] = (
                    0
                    + 1 * scores["STRINGS"]
                    + 1 * scores["FUNC_NAME"]
                    + 1 * scores["CALLS"]
                    + 1 * scores["CONSTANTS"]
                    + 1 * scores["FUNC_INDEX"]
                    + 1 * scores["SIZE"]
                )

                chunk_features[chunk.start] = scores

            for chunk, score in potential_chunks.most_common(
                qsig.Settings.SIMILAR_CHUNK
            ):
                self.logger.debug(
                    "Selected chunk at 0x%x with score %f", chunk.start, score
                )
                self._candidate_chunks.append(chunk)

            self.logger.info(
                "",
                extra={
                    "bench": True,
                    "type": "selection",
                    "cve": self.parent.signature.cve_signature.cve_id,
                    "commit": self.parent.signature.cve_signature.commit,
                    "chunk_matcher": self.parent.parent.chunk_index(self),
                    "features": target_chunk.features,
                    "file": self.parent.binary_file.path.as_posix(),
                    "scores": chunk_features,
                },
            )

        return self._candidate_chunks

    def match_constant_signature(self) -> List[quokka.types.AddressT]:
        """Match the constants part of the signature

        Constants matching is harder than first expected.
        See explanations in the signature part.

        Returns:
            Boolean for success
        """
        if qsig.sig.Artefact.CONSTANTS not in self.signature.artifact_type:
            return []

        sig_constants: Dict[int, Tuple[int, int, bool]] = {}
        for proto_constant in self.signature.constant_signature.constants:
            sig_constants[proto_constant.value] = (
                proto_constant.vuln_count,
                proto_constant.fix_count,
                proto_constant.new,
            )

        match_chunks: List[quokka.types.AddressT] = []
        for target_chunk in self.candidate_chunks:
            target = collections.Counter(
                qsig.sig.utils.norm_constants(target_chunk.constants)
            )

            results: List[bool] = []
            for constant, counts in sig_constants.items():
                vuln_count, fix_count, only_in_fix = counts
                # If it's a new constant, just check if its present
                if only_in_fix:
                    results.append(target[constant] > 0)
                else:
                    results.append(vuln_count < target[constant] <= fix_count)

            if results.count(True) >= results.count(False):
                match_chunks.append(target_chunk.start)

        return match_chunks

    def match_call_signature(self) -> List[quokka.types.AddressT]:
        """
        Matches the call part of the signature.

        TODO Improve this, it does not work well at all.

        Returns:
            Boolean for success
        """

        def match_calls(
            candidate: Union[Chunk, Function],
            call_proto,
        ) -> bool:
            candidate_degrees = quokka.function.get_degrees(candidate)
            return (
                candidate_degrees[0] == call_proto.in_degree
                and candidate_degrees[1] == call_proto.out_degree
            )

        if qsig.sig.Artefact.CALLS not in self.signature.artifact_type:
            return []

        call_signature = self.signature.calls_signature
        calls_match: List[quokka.types.AddressT] = []
        for chunk in self.candidate_chunks:
            # First, we try to match the caller
            if not match_calls(chunk, call_signature.caller):
                continue

            results: List[bool] = []
            all_degrees = {
                candidate.start: quokka.function.get_degrees(candidate)
                for candidate in set(chunk.calls)
            }

            callers_count = collections.Counter(target.start for target in chunk.calls)

            for callee in call_signature.callees:
                if (callee.in_degree, callee.out_degree) in all_degrees.values():
                    results.append(True)

                # We found a function called exactly the same number of time
                elif (
                    callee.caller_count > 1
                    and callee.caller_count in callers_count.values()
                ):
                    results.append(True)

                else:
                    results.append(False)

            if results.count(True) > results.count(False):
                calls_match.append(chunk.start)

        return calls_match

    def _create_conditions(self) -> None:
        """Build the conditions list from the signature

        Acts as a proxy because both labels and conditions property need this.

        Returns:
            None
        """

        def create_condition(
            proto_condition: qsig.signature_pb2.ChunkSignature.ConditionSignature.Condition,
            labels: qsig.sig.LabelsCollection,
        ) -> qsig.sig.Condition:
            """Build a condition from a protobuf and a labels collection"""
            compared_elements = [
                labels.add_from_condition(
                    qsig.sig.ConditionElementConverter.to_code(element.type),
                    element.value,
                )
                for element in proto_condition.elements
            ]
            return qsig.sig.Condition.from_proto(compared_elements)

        self._signature_conditions: Dict[qsig.sig.Condition, int] = {}
        self._labels_collection = qsig.sig.LabelsCollection()
        for proto_condition in self.signature.condition_signature.conditions:
            self._signature_conditions[
                create_condition(proto_condition, self._labels_collection)
            ] = proto_condition.count

    @property
    def labels(self) -> qsig.sig.LabelsCollection:
        """Returns the label collection for the conditions in the signature"""
        if self._labels_collection is None:
            self._create_conditions()

        return self._labels_collection

    @property
    def conditions(self) -> Dict[qsig.sig.Condition, int]:
        """Return the conditions from the signature"""
        if self._signature_conditions is None:
            self._create_conditions()

        return self._signature_conditions

    def get_candidate_conditions(
        self,
    ) -> Generator[
        None,
        Tuple[
            quokka.types.AddressT,
            qsig.sig.LabelsCollection,
            List[qsig.sig.Condition],
        ],
        None,
    ]:
        """Yields a candidate conditions and labels for each candidate chunk"""
        bincat = qsig.sig.Bincat()

        condition_file = self.parent.binary_file.firmware.file_in_shadow(
            self.parent.binary_file.path, ".bincat"
        )
        bincat.set_binary(self.program, condition_file)

        for candidate_chunk in self.candidate_chunks:
            try:
                yield qsig.sig.get_condition_for_function(
                    function=candidate_chunk, bincat_interface=bincat
                )
            except qsig.sig.BincatException:
                continue

    def match_condition_signature(self) -> List[quokka.types.AddressT]:
        """Match a condition signature.

        The condition matcher looks for at least the same number of conditions with the
        same type in the candidate and in the signature.

        Note that this methods has an exponential complexity due to the fuzzy matching
        performed for labels (see yield_mapping for more details).

        Returns:
            Boolean for success

        """
        if qsig.sig.Artefact.CONDITIONS not in self.signature.artifact_type:
            return []

        count_signature_conditions = sum(self.conditions.values())
        # Generate the counter for the condition from the signature
        signature_counter = collections.Counter(self.conditions)

        condition_match: List[quokka.types.AddressT] = []
        for (
            candidate_address,
            candidate_labels,
            candidate_conditions,
        ) in self.get_candidate_conditions():

            # FIX: Do not try to do a matching if we have *less* condition in the
            # candidate
            if len(candidate_conditions) < count_signature_conditions:
                continue

            # FIX : Do not try to do a matching if we have less labels in the
            # candidate
            if len(candidate_labels.arg_labels) < len(self.labels.arg_labels) or len(
                candidate_labels.calls_labels
            ) < len(self.labels.calls_labels):
                continue

            for mapping in qsig.sig.yield_mapping(
                self.labels,
                candidate_labels,
            ):
                tmp_counter = collections.Counter(
                    {cond: 0 for cond in signature_counter}
                )
                for condition in signature_counter:
                    for candidate_condition in candidate_conditions:
                        if condition.is_equivalent(candidate_condition, mapping):
                            tmp_counter[condition] += 1

                # We found a correct mapping and the conditions
                if qsig.sig.utils.is_included(tmp_counter, signature_counter):
                    condition_match.append(candidate_address)
                    break

        return condition_match

    def match(self, binary_file: firmextractor.fs.ExecutableFile) -> bool:
        """Matches a chunk.

        A chunk is matched if:
            1/ the string signature is found
            2/ the constants are found
            3/ the conditions are found
            (4/ the calls are found)

        If a method is successful none of the following are tried.

        Args:
            binary_file: A candidate file

        Returns:
            Boolean for success
        """
        if binary_file is not None:
            self._candidate_chunks = None

        results = []
        if self.match_string_signature():
            results.append("strings")

        strings_match, wrong_match = self.match_local_string_signature(
            already_matched="strings" in results
        )
        if strings_match and "strings" not in results:
            results.append("strings")
        # Fix: case when YARA has matched a substring but the string is not found
        elif not strings_match and wrong_match:
            results.remove("strings")

        constants_match = self.match_constant_signature()
        if constants_match:
            results.append("constants")

        call_match = self.match_call_signature()
        if call_match:
            results.append("calls")

        condition_match = self.match_condition_signature()
        if condition_match:
            results.append("conditions")

        if results:
            self.logger.info(
                f"%s was matched with the signature (using %s)",
                self.parent.binary_file.name,
                results,
            )

        logger.info(
            "",
            extra={
                "bench": True,
                "type": "match",
                "cve": self.parent.signature.cve_signature.cve_id,
                "file": self.parent.binary_file.path.as_posix(),
                "commit": self.parent.signature.cve_signature.commit,
                "chunk_matcher": self.parent.parent.chunk_index(self),
                "candidates": [
                    x.start
                    for x in self.candidate_chunks
                    if len(self.candidate_chunks) < 10
                ],
                "match_results": {
                    "constants": constants_match,
                    "calls": call_match,
                    "conditions": condition_match,
                    "strings": strings_match,
                },
                "results": results,
                "artifacts": [x.name for x in self.signature.artifact_type],
            },
        )

        return results != []

    def accept(self, binary_file: firmextractor.fs.ExecutableFile) -> bool:
        """Accepts a chunk: returns always true"""
        return True
