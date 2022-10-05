import collections
import enum
import logging
from typing import Union, Optional, List, Set, Any, Tuple

import qsig
import quokka
import quokka.exc
from quokka.function import Chunk, Function


logger = logging.getLogger(__name__)


class Difference(enum.Enum):
    """Differences for a signature"""

    STRINGS = enum.auto()
    CONSTANTS = enum.auto()
    CALLS = enum.auto()
    CONDITIONS = enum.auto()


def generate_identity(
    first: Union[Chunk, Function], second: Optional[Union[Chunk, Function]] = None
) -> qsig.sig.Identity:

    common_strings: List[str] = []
    common_constants: List[int] = []
    common_calls: List[str] = []
    if second is not None and not (
        isinstance(first, Function)
        and first.type != quokka.function.FunctionType.NORMAL
    ):
        try:
            common_strings = list(set(first.strings).intersection(second.strings))
        except (ValueError, IndexError):
            pass

        vuln_constants = set(qsig.sig.norm_constants(set(second.constants)))
        fix_constants = set(qsig.sig.norm_constants(set(first.constants)))
        common_constants = [
            cst
            for cst in vuln_constants.intersection(fix_constants)
            if qsig.Settings.MIN_CONSTANT <= cst <= qsig.Settings.MAX_CONSTANT
        ]

        for extern_call in set(qsig.sig.get_extern_calls(first)).intersection(
            qsig.sig.get_extern_calls(second)
        ):
            common_calls.append(extern_call)

    return qsig.sig.Identity(
        index=-1,
        size=first.end - first.start,
        strings=common_strings,
        constants=common_constants,
        calls=common_calls,
    )


def generate_chunk_identifier(
    chunk: Chunk, other_chunk: Optional[Chunk]
) -> qsig.sig.ChunkIdentifier:

    identity = generate_identity(chunk, other_chunk)

    # Chunk index in program
    for chunk_index, start in enumerate(
        sorted(x.start for x in chunk.program.iter_chunk())
    ):
        if start == chunk.start:
            break
    else:
        raise qsig.GeneratorException("Failed to find chunk in program")

    try:
        function = chunk.program.get_first_function_by_chunk(chunk)
        func_index = sorted(chunk.program).index(function.start)
        function_name = function.name
    except quokka.exc.FunctionMissingError:
        func_index = -1
        function_name = ""

    return qsig.sig.ChunkIdentifier(
        index=chunk_index,
        size=identity.size,
        strings=identity.strings,
        constants=identity.constants,
        calls=identity.calls,
        func_name=function_name,
        func_index=func_index,
        chunk=chunk,
    )


def generate_function_identifier(
    function: Function,
    other_func: Optional[Function] = None,
) -> qsig.sig.FunctionIdentifier:

    identity = generate_identity(function, other_func)

    for function_index, start in enumerate(sorted(x for x in function.program)):
        if function.start == start:
            break
    else:
        function_index = -1

    return qsig.sig.FunctionIdentifier(
        name=function.name,
        index=function_index,
        size=identity.size,
        strings=identity.strings,
        constants=identity.constants,
        calls=identity.calls,
        function=function,
    )


def find_call_difference(
    fix_chunk: "Chunk",
    vuln_chunk: Optional[Chunk],
) -> List[Function]:

    if vuln_chunk is not None:
        vuln_binary: quokka.Program = vuln_chunk.program

        vuln_calls = collections.Counter()
        for called_chunk in vuln_chunk.calls:
            try:
                called_function = vuln_binary.get_function_by_chunk(called_chunk)[0]
            except IndexError:
                # FIX: may call a "chunk" outside of a function in case of bad
                # disassembly
                continue

            vuln_calls[called_function.name] += 1

    else:
        vuln_calls = collections.Counter()

    fix_binary = fix_chunk.program

    fix_calls = collections.Counter()
    for chunk in fix_chunk.calls:
        try:
            fix_calls[fix_binary.get_first_function_by_chunk(chunk).name] += 1
        except quokka.exc.FunctionMissingError:
            continue

    diff_names = fix_calls - vuln_calls
    if diff_names:
        return_list = []
        for function_name in diff_names:
            try:
                function = quokka.function.dereference_thunk(
                    fix_binary.get_function(function_name)
                )
            except quokka.exc.FunctionMissingError:
                logger.error("Unable to find the dereference of the thunk function")
                continue

            return_list.append(function)

        return return_list

    # TODO(dm) do some diff magic here
    raise NotImplementedError


def diff_conditions(
    fix_labels: qsig.sig.LabelsCollection,
    fix_conditions: List[qsig.sig.Condition],
    vuln_labels: Optional[qsig.sig.LabelsCollection],
    vuln_conditions: List[qsig.sig.Condition],
) -> Set[qsig.sig.Condition]:

    # Do not diff if there is no added conditions
    if len(vuln_conditions) >= len(fix_conditions):
        return set()

    # Clean the condition list to reduce complexity
    unique_vuln_conditions = set(vuln_conditions)
    unique_fix_conditions = set(fix_conditions)

    for mapping in qsig.sig.yield_mapping(vuln_labels, fix_labels):
        if qsig.sig.test_mapping(
            mapping, unique_vuln_conditions, unique_fix_conditions
        ):
            break
    else:
        logger.debug("No valid mapping found")
        return set()

    new_conditions: Set["qsig.sig.Condition"] = set()
    for fix_condition in unique_fix_conditions:
        if not any(
            vuln_condition.is_equivalent(fix_condition, mapping)
            for vuln_condition in unique_vuln_conditions
        ):
            new_conditions.add(fix_condition)

    if not new_conditions:
        logger.warning("No new conditions found")
        return set()

    return new_conditions


class ChunkGenerator:
    def __init__(
        self,
        parent: "qsig.generator.FileGenerator",
        signature,
        fix_function: quokka.function.Chunk,
        vuln_function: Optional[quokka.function.Chunk],
    ):
        self.parent = parent
        self.signature = signature
        self.fix_chunk = fix_function
        self.vuln_chunk = vuln_function

        self.differences: Set[Difference] = self.get_differences()

    @staticmethod
    def chunk_proxy(chunk: Chunk, attr: str, return_type: type) -> Any:
        try:
            return getattr(chunk, attr)
        except AttributeError:
            if return_type is dict:
                return {}
            elif return_type is set:
                return set()
            elif return_type is list:
                return []
            return None

    def generate(self) -> bool:
        results: List[Difference] = []

        self.signature.chunk_identifier = generate_chunk_identifier(
            self.fix_chunk, self.vuln_chunk
        )

        if Difference.STRINGS in self.differences and self.generate_string_signature():
            results.append(Difference.STRINGS)

        if (
            Difference.CONSTANTS in self.differences
            and self.generate_constant_signature()
        ):
            results.append(Difference.CONSTANTS)

        if Difference.CALLS in self.differences and self.generate_call_signature():
            results.append(Difference.CALLS)

        if (
            Difference.CONDITIONS in self.differences
            and self.generate_condition_signature()
        ):
            results.append(Difference.CONDITIONS)

        logger.info(
            "Chunk generated",
            extra={
                "bench": True,
                "type": "generator",
                "cve": self.parent.parent.cve.name,
                "commit": getattr(self.parent.parent.cve, "cve_commit", ""),
                "file": self.parent.fix_file.executable.exec_file.name,
                "chunk": self.fix_chunk.name,
                "level": "chunk",
                "differences": [x.name for x in self.differences],
                "generated": [x.name for x in results],
            },
        )

        return any(results)

    def generate_string_signature(self) -> bool:
        def add_strings_to_rule(
            rule_object: qsig.sig.yara_rule.Rule,
            strings_container: Set[str],
            all_of_them: bool = True,
        ) -> None:

            for string_index, string in enumerate(strings_container):
                rule_object.add_strings(
                    string,
                    identifier=f"s{string_index}",
                    modifiers=["nocase", "ascii"],
                )

            if all_of_them:
                rule_object.add_condition("all of them")
            else:
                # Relax the condition and only requires 60% of them
                min_strings = max(1, int(0.6 * len(strings_container)))
                rule_object.add_condition(f"{min_strings} of them")

        logger.debug("Generate full string signature (YARA Rule)")

        cve_id = self.parent.parent.cve.name
        rule_file = qsig.sig.yara_rule.RuleFile(
            default_meta={"author": qsig.Settings.AUTHOR}, prefix=cve_id
        )
        rule_file.add_description(f"Rule file written to detect {cve_id}.")

        vuln_strings: List[str] = self.chunk_proxy(self.vuln_chunk, "strings", list)

        common_strings = {
            string
            for string in set(self.fix_chunk.strings).intersection(vuln_strings)
            if string
        }

        common_signature: Optional[qsig.sig.yara_rule.Rule] = None
        if common_strings:
            common_signature: qsig.sig.yara_rule.Rule = rule_file.create_rule(
                name=f"chunk_{self.fix_chunk.start}", suffix="_common", private=True
            )
            logger.debug("Found %d common strings to use", len(common_strings))
            add_strings_to_rule(common_signature, common_strings, all_of_them=False)

        new_strings = set(self.fix_chunk.strings) - set(vuln_strings)
        logger.debug("Found %d different strings to use", len(new_strings))
        if new_strings:
            logger.debug("New strings are %s", new_strings)
            rule: qsig.sig.yara_rule.Rule = rule_file.create_rule(
                name=f"chunk_{self.fix_chunk.start}", suffix="_fix"
            )
            if common_strings:
                rule.add_condition(common_signature)
            add_strings_to_rule(rule, new_strings)

        logger.debug("String signature generated")

        try:
            self.signature.string_signature = rule_file, new_strings
        except qsig.sig.SignatureException as e:
            logger.exception(e)
            return False

        return True

    def generate_constant_signature(self) -> bool:
        """Generates a "constant" signature.

        The signature is generated based on the difference of constant in the vuln and
        fix part. We keep the value of the constant and its occurrence both in vuln and
        fix.

        Returns:
            A boolean for success
        """
        logger.debug("Generate constant signature based on fix chunk constants")
        vuln_constants = collections.Counter(
            self.chunk_proxy(self.vuln_chunk, "constants", list)
        )
        fix_constants = collections.Counter(self.fix_chunk.constants)

        constant_signature: List[Tuple[int, int, int, bool]] = []
        for constant in fix_constants - vuln_constants:
            constant_signature.append(
                (
                    constant,
                    vuln_constants[constant],
                    fix_constants[constant],
                    constant not in vuln_constants,
                )
            )

        self.signature.constant_signature = constant_signature

        return True

    def generate_call_signature(self) -> bool:
        # TODO(dm) This need to be upgrade once we'll have a diffing with both the
        #  mapping betwen vuln and fix chunks. Until we use this band aid solution to
        #  match calls between (fix_chunk, other_funcs in fix binary). This won't play
        #  nice when the reconstruction of the functions fails
        callees_identifier: List["qsig.sig.FunctionIdentifier"] = []

        callee: Function

        try:
            call_differences: List[Function] = find_call_difference(
                self.fix_chunk, self.vuln_chunk
            )
        except NotImplementedError:
            logger.info("Unable to find the call difference")
            return False

        for callee in call_differences:
            try:
                vuln_callee_func = self.parent.vuln_file.get_function(
                    name=callee.name, approximative=False, normal=False
                )
            except ValueError:
                vuln_callee_func = None

            callees_identifier.append(
                generate_function_identifier(callee, vuln_callee_func)
            )

        self.signature.add_call_signature(self.fix_chunk, callees_identifier)

        return True

    def generate_condition_signature(self) -> bool:
        logger.debug("Generate a condition signature")

        try:
            _, fix_labels, fix_conditions = qsig.sig.get_condition_for_function(
                self.fix_chunk
            )
        except qsig.sig.BincatException:
            return False

        vuln_labels, vuln_conditions = None, []
        if self.vuln_chunk is not None:
            try:
                (
                    _,
                    vuln_labels,
                    vuln_conditions,
                ) = qsig.sig.get_condition_for_function(self.vuln_chunk)
            except qsig.sig.BincatException:
                logger.error("BinCAT error for %s", self.vuln_chunk.name)
                return False

        fix_counter = collections.Counter(fix_conditions)
        new_conditions: List[Tuple[qsig.sig.Condition, int]] = [
            (condition, fix_counter[condition])
            for condition in diff_conditions(
                fix_labels, fix_conditions, vuln_labels, vuln_conditions
            )
        ]

        logger.debug("We found %d new conditions to match", len(new_conditions))

        if new_conditions:
            self.signature.condition_signature = new_conditions
            return True

        return False

    def get_differences(self) -> Set[Difference]:
        differences = set()

        # Strings difference
        vuln_strings = self.chunk_proxy(self.vuln_chunk, "strings", set)
        diff_strings = set(self.fix_chunk.strings).symmetric_difference(vuln_strings)

        # Check also that the new strings are not found in the "old" binary
        # This check is needed because we won't have the localization of strings in
        # the new binary
        if diff_strings and any(
            string not in self.parent.vuln_file.strings for string in diff_strings
        ):
            differences.add(Difference.STRINGS)

        # Constants differences
        vuln_constants = self.chunk_proxy(self.vuln_chunk, "constants", list)
        diff_constants = collections.Counter(
            self.fix_chunk.constants
        ) - collections.Counter(vuln_constants)
        if any(
            qsig.Settings.MIN_CONSTANT <= constant <= qsig.Settings.MAX_CONSTANT
            for constant in qsig.sig.norm_constants(diff_constants.elements())
        ):
            differences.add(Difference.CONSTANTS)

        # Calls difference
        vuln_calls = self.chunk_proxy(self.vuln_chunk, "calls", list)
        # TODO(dm) Get a better way if the call target change
        if len(self.fix_chunk.calls) != len(vuln_calls):
            differences.add(Difference.CALLS)

        # Conditions difference
        # On the same architecture, a change in the CFG is probably responsible for new
        # conditions. We'll double check that when computing the actual differences
        vuln_graph = self.chunk_proxy(self.vuln_chunk, "graph", list)
        if len(self.fix_chunk.graph) != len(vuln_graph):
            differences.add(Difference.CONDITIONS)

        return differences

    @property
    def has_differences(self) -> bool:
        return any(self.differences)
