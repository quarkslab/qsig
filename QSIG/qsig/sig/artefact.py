import enum


class Artefact(enum.Enum):
    """Artefact used in the signatures

    UNKNOWN:
        default value
    STRINGS:
        signs the strings added during the patch
    CALLS:
        signs the change to the call graph
    CONSTANTS:
        signs the changes to the constant pool used by the function
    CONDITIONS:
        signs the origin of new comparisons
    """

    UNKNOWN = enum.auto()
    STRINGS = enum.auto()
    CALLS = enum.auto()
    CONSTANTS = enum.auto()
    CONDITIONS = enum.auto()
