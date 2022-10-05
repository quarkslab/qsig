from __future__ import annotations

import math
import itertools
import logging
from typing import (
    Dict,
    List,
    Union,
    Tuple,
    Generator,
    Optional,
    Set,
    Type,
    Any,
    Sequence,
)

import qsig.sig
import quokka.instruction

logger = logging.getLogger(__name__)
"""Logger instance"""


class Label:
    """Label

    A label represent an origin inside the function.

    Args:
        identifier: Id of the label

    Attributes:
        id: Id of the label
    """

    id: int
    """Label's id"""

    def __init__(self, identifier: int):
        """Constructor"""
        self.id = identifier

    def equivalent(self, other: "Label", mapping: Dict[Label, Label]) -> bool:
        """Is the other Label equivalent to me using this mapping"""
        # TODO(dm)
        ...

    def __str__(self) -> str:
        """String representation of the label"""
        ...

    def __eq__(self, other: Any) -> bool:
        """Is the other label IS me?"""
        return isinstance(other, self.__class__) and self.id == other.id

    def __hash__(self) -> int:
        """Hash value"""
        return hash(frozenset({self.id, self.__class__}))


class ArgLabel(Label):
    """ArgLabel: represents the label for an argument"""

    def equivalent(self, other: "Label", mapping: Dict[Label, Label]) -> bool:
        """Is the other Label equivalent to me using this mapping"""
        return isinstance(other, ArgLabel) and mapping[self] == other

    def __str__(self) -> str:
        """String representation of the label"""
        return f"arg{self.id}"


class CallLabel(Label):
    """CallLabel: represents the label for a call return value"""

    def equivalent(self, other: "Label", mapping: Dict[Label, Label]) -> bool:
        """Is the other Label equivalent to me using this mapping"""
        return isinstance(other, CallLabel) and mapping[self] == other

    def __str__(self) -> str:
        """String representation of the label"""
        return f"call_{hex(self.id)}"


class ConstantLabel(Label):
    """ConstantLabel: represent a constant value"""

    def equivalent(self, other: "Label", mapping: Dict[Label, Label]) -> bool:
        """Is the other Label equivalent to me using this mapping"""
        return isinstance(other, ConstantLabel) and self.id == other.id

    def __str__(self) -> str:
        """String representation of the label"""
        return f"{self.id}"


class Condition:
    """Condition

    A condition represent two compared elements with their associated labels.

    Args:
        compared_elements: A list of labels
        instruction: Optional. An instruction

    Attributes:
        compared_elements: A list of labels
        instruction: An instruction for the condition represented

    """

    def __init__(
        self,
        compared_elements: List[Label],
        instruction: Optional[quokka.instruction.Instruction] = None,
    ):
        """Constructor"""
        self.compared_elements: List[Label] = compared_elements
        self.instruction: Optional[quokka.instruction.Instruction] = instruction

    def __hash__(self) -> int:
        """Hash value"""
        return hash(frozenset(self.compared_elements))

    def __eq__(self, other) -> bool:
        """Equivalence"""
        return self.__hash__() == hash(other)

    def __str__(self) -> str:
        """String representation"""
        sides = "-".join([str(x) for x in self.compared_elements])
        address = f"0x{self.instruction.address:x}" if self.instruction else "UNKNOWN"
        return f"<Condition with {sides} at {address}>"

    def is_equivalent(self, other: "Condition", mapping: Dict[Label, Label]) -> bool:
        """Check if this condition is equivalent to the other."""
        if len(other.compared_elements) != len(self.compared_elements):
            return False

        for element in self.compared_elements:
            if not any(
                element.equivalent(other_element, mapping)
                for other_element in other.compared_elements
            ):
                return False

        return True

    def __getstate__(self) -> Dict[Any, Any]:
        """Pickling method"""
        state = self.__dict__.copy()
        del state["instruction"]
        return state

    def __setstate__(self, state: Dict[Any, Any]):
        """Unpickling method"""
        self.__dict__.update(state)
        self.__dict__.setdefault("instruction", None)

    @classmethod
    def from_bincat(
        cls,
        taint_sources: List[Label],
        instruction: "quokka.instruction.Instruction",
        labels_collection: "LabelsCollection",
    ) -> Condition:
        """Create a Condition from BinCAT

        Args:
            taint_sources: Taint sources in the instruction
            instruction: Instruction itself
            labels_collection: Function label collections

        Returns:
            A condition
        """
        for operand in instruction.operands:
            if operand.type == 5:  # IDA immediate value
                taint_sources.append(
                    labels_collection.get_constant_label(operand.value)
                )

        return cls(list(set(taint_sources)), instruction)

    @classmethod
    def from_proto(cls, compared_elements: List[Label]) -> Condition:
        """Create a Condition from a proto serialization

        Args:
            compared_elements: List of compared elements

        Returns:
            A condition
        """
        return cls(compared_elements)


class LabelsCollection:
    """Labels Collection: store all labels for a function

    This bag holds every label used in a function.

    Attributes:
        skipped_func: List of addresses of skipped functions
        args_labels: Mapping for argument labels
        calls_labels: Mapping for calls labels
        csts_labels: Mapping for constants labels

    Args:
        skipped_func: List of addresses of skipped fucntions

    """

    def __init__(self, skipped_func: Optional[List[int]] = None) -> None:
        """Constructor"""
        if skipped_func is None:
            skipped_func = []

        self.skipped_func: List[int] = skipped_func
        self.arg_labels: Dict[int, ArgLabel] = {}
        self.calls_labels: Dict[int, CallLabel] = {}
        self.cst_labels: Dict[int, ConstantLabel] = {}

    @property
    def calls_args_labels(self) -> Sequence[Union[CallLabel, ArgLabel]]:
        """Returns all calls and args labels"""
        return [value for value in {**self.arg_labels, **self.calls_labels}.values()]

    def format_taint_id(self, taint_id: int) -> Tuple[str, int]:
        """Format a taint id"""
        if taint_id > len(self.skipped_func):
            return "arg", taint_id - len(self.skipped_func)
        else:
            assert taint_id > 0
            address = self.skipped_func[taint_id - 1]
            return "call", address

    def __getitem__(self, label_id: int) -> Label:
        """Return the appropriate label based on the label_id"""
        label_type, identifier = self.format_taint_id(label_id)

        if label_type == "arg":
            if not self.arg_labels.get(identifier):
                self.arg_labels[identifier] = ArgLabel(identifier)
            return self.arg_labels[identifier]

        elif label_type == "call":
            if not self.calls_labels.get(identifier):
                self.calls_labels[identifier] = CallLabel(identifier)
            return self.calls_labels[identifier]

        raise qsig.sig.ConditionException("Wrong label type")

    def get_constant_label(self, cst_value: int) -> ConstantLabel:
        """Get a constant label for a constant value"""
        cst_label = self.cst_labels.get(cst_value, ConstantLabel(cst_value))
        self.cst_labels[cst_value] = cst_label
        return cst_label

    def add_from_condition(self, label_type: Type[Label], value: int) -> Label:
        """Add labels from a condition

        Args:
            label_type: Type of label
            value: Value of label's id

        Returns:
            A Label freshly added inside the collection
        """
        mapping = {
            ArgLabel: self.arg_labels,
            CallLabel: self.calls_labels,
            ConstantLabel: self.cst_labels,
        }

        collection = mapping[label_type]
        collection[value] = label_type(value)

        return collection[value]


def yield_mapping(
    collection_1: Optional[LabelsCollection], collection_2: LabelsCollection
) -> Generator[Dict[Label, Label], None, None]:
    """Yields an acceptable valid mapping between `collection_1` and `collection_2`
    labels.

    A mapping is a map of labels from the collection 1 towards a label of the collection
    2. All acceptable mapping are iterated and exhausted before returning.

    A mapping is deemed acceptable if the type of the labels in both side of the mapping
    matches (e.g. a arg label is mapped to an arg label).

    Note: This function is *not* symmetric. Indeed, since the number of labels may
    differ in both sides, we only consider *injections* from collection 1 to collection
    2.

    In the case if collection_1 is empty or not defined then the empty mapping is
    returned.

    Args:
        collection_1: Labels from the function 1
        collection_2: Labels to the function 2

    Yields:
        A map between labels of collection 1 to collection 2

    Returns:
        None
    """

    # Shortcut: if there is no labels for collection_1, every mapping is acceptable
    if collection_1 is None:
        return None

    collection_1_l: Sequence[Label] = collection_1.calls_args_labels
    collection_2_l: Sequence[Label] = collection_2.calls_args_labels

    n = len(collection_2_l)
    k = len(collection_1_l)

    if len(collection_1.arg_labels) > len(collection_2.arg_labels) or len(
        collection_1.calls_labels
    ) > len(collection_2.calls_labels):
        return None

    assert n - k >= 0, "Error"
    if math.factorial(n) / math.factorial(n - k) > 1_000_000:
        logger.info("Too much mapping to try, abort.")
        return None

    for permutation in itertools.permutations(collection_2_l, r=len(collection_1_l)):
        mapping = {}
        valid = True
        for dst, src in enumerate(permutation):
            label_1, label_2 = collection_1_l[dst], src
            if type(label_1) == type(label_2):
                mapping[label_1] = label_2
            else:
                valid = False
                break

        if valid:
            yield mapping

    logger.debug("No more mapping to try.")


def test_mapping(
    mapping: Dict[Label, Label],
    vuln_conditions: Set[Condition],
    fix_conditions: Set[Condition],
) -> bool:
    """Test if a mapping is valid

    To be valid a mapping must, for each condition in the vuln set, find at least one
    condition in the fixed set that match for this mapping.

    This methods tries to fail fast.

    Args:
        mapping: Association between Vuln and Fixed Labels Collections
        vuln_conditions: Set of conditions from vuln func
        fix_conditions: Set of conditions from fixed func

    Returns:
        boolean for success
    """
    for vuln_condition in vuln_conditions:
        if not any(
            vuln_condition.is_equivalent(fix_condition, mapping)
            for fix_condition in fix_conditions
        ):
            return False

    return True
