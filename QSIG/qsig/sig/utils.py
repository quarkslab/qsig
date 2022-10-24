import collections
import editdistance  # type: ignore
import hashlib
import logging
import pathlib

import lief
from typing import List, Iterable, Any, Dict, Optional, Union

import quokka.exc
from quokka.function import Function, Chunk
import qsig


logger: logging.Logger = logging.getLogger(__name__)
"""Logger instance"""


def norm_constant(constant: int) -> List[int]:
    """Normalize `constant` (up to 64b integer) to 4*2bytes constants.

    This splits the each constant in the list into 16 bits constants (0-0xFFFF).
    This is done to deal with architectures that cannot represent wider constants (e.g 64b)

    Args:
        constant: Constant to normalize

    Returns:
        A list of 2 bytes constants
    """
    normed_constant: List[int] = []
    if constant != 0:
        for shift in [0, 0x10, 0x20, 0x30]:
            shifted = (constant >> shift) & 0xFFFF
            if shifted != 0:
                normed_constant.append(shifted)
    else:
        normed_constant.append(0)

    return normed_constant


def norm_constants(constants: Iterable[int]) -> List[int]:
    """Normalize the constants list by appling `norm_constant` to each of them.

    Args:
        constants: The list of constant to split

    Returns:
        A normalized list where every constant is less than 0xffff
    """
    normed_constants: List[int] = []
    for constant in constants:
        normed_constants.extend(norm_constant(constant))

    return normed_constants


def sha256_file(file_path: pathlib.Path) -> str:
    """Compute the SHA-256 of a file

    Args:
        file_path: Path towards the file

    Returns:
        SHA256 hexdigest of the file
    """
    sha = hashlib.sha256()
    with open(file_path.as_posix(), "rb") as f:
        for byte in iter(lambda: f.read(65535), b""):
            sha.update(byte)

    return sha.hexdigest()


def jaccard_index(left: Iterable[Any], right: Iterable[Any]) -> float:
    """Jaccard Index

    Args:
        left: First set
        right: Second set

    Returns:
        A floating value between 0 and 1
    """
    if not left and not right:
        return 0.0

    left = collections.Counter(left)
    right = collections.Counter(right)

    return len(list((right & left).elements())) / len(list((right | left).elements()))


def inclusion_index(small: Iterable[Any], large: Iterable[Any]) -> float:
    """Compute the "jaccard-like" index of two sets by looking at the inclusion score

    Args:
        small: Small set
        large: Large set

    Returns:
        A floating result between 0 and 1
    """
    if not small or not large:
        return 0.0

    small = collections.Counter(small)
    large = collections.Counter(large)

    return len(list((small & large).elements())) / len(list(small.elements()))


def levenstein(x: str, y: str) -> float:
    """Return a percent based on levenstein distance of two strings"""
    return editdistance.eval(x, y) / max(len(x), len(y))


def small_difference(x: int, y: int) -> float:
    """Returns a number between [0, 1].
    Use min(x,y) / max(x,y) as a metric.  Note: If x == y return 1.
    """
    if x == y:
        return 1.0
    else:
        return min(abs(x), abs(y)) / max(abs(x), abs(y))


def norm_name(path: pathlib.Path, sha256: Optional[str] = None) -> str:
    """Norm a name by removing the prefix if there is any"""
    name = path.stem
    if len(name) > 65:
        sha256 = sha256 or sha256_file(path)
        if name.startswith(f"{sha256}_"):
            name = name[65:]

    return name


def is_included(counter_1: collections.Counter, counter_2: collections.Counter) -> bool:
    """Check if counter_1 is included in counter_2"""

    for key, val in counter_1.items():
        if counter_2.get(key, 0) > val:
            return False
    return True


def get_extern_calls(target: Union[Chunk, Function]) -> List[str]:
    """List external calls from target

    Args:
        target: A Function or Chunk to consider

    Returns:
        A list of functions names which are called by target
    """
    extern_calls: List[str] = []
    callee: Function
    for callee in set(target.calls):
        try:
            callee = quokka.function.dereference_thunk(callee)
        except quokka.exc.FunctionMissingError:
            continue

        if callee.type == quokka.function.FunctionType.EXTERN:
            extern_calls.append(callee.name)

    return extern_calls
