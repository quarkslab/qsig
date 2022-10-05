from __future__ import annotations

import dataclasses
from typing import List, Optional

import quokka.function
import qsig.signature_pb2


@dataclasses.dataclass
class Identity:
    """Base identity information"""

    index: int
    """Index inside the binary"""

    size: int
    """Element size (end-start)"""

    strings: List[str]
    """List of strings"""

    constants: List[int]
    """List of constants"""

    calls: List[str]
    """List of called functions names"""

    @property
    def features(self) -> List[str]:
        """Returns the list of features set for this identity"""
        features: List[str] = [
            feature for feature, value in dataclasses.asdict(self).items() if value
        ]
        return features


@dataclasses.dataclass
class ChunkIdentifier(Identity):
    """Identifier for a Chunk"""

    func_name: str
    """Name of the associated function"""

    func_index: int
    """Index of the function"""

    chunk: Optional["quokka.function.Chunk"]
    """Direct link to the Chunk itself"""

    @staticmethod
    def from_proto(
        proto_chunk_identifier: qsig.signature_pb2.ChunkSignature.ChunkIdentifier,
    ) -> ChunkIdentifier:
        """Load a Chunk Identifier from a proto

        Args:
            proto_chunk_identifier: Serialized data

        Returns:
            ChunkIdentifier
        """
        return ChunkIdentifier(
            index=proto_chunk_identifier.identity.index,
            size=proto_chunk_identifier.identity.size,
            strings=list(proto_chunk_identifier.identity.strings),
            constants=list(proto_chunk_identifier.identity.constants),
            calls=list(proto_chunk_identifier.identity.calls),
            func_name=proto_chunk_identifier.func_name,
            func_index=proto_chunk_identifier.func_index,
            chunk=None,
        )


@dataclasses.dataclass
class FunctionIdentifier(Identity):
    """Identifier for a function"""

    name: str
    """Function name"""

    function: Optional[quokka.function.Function]
    """Direct link to the function itself"""

    @staticmethod
    def from_proto(
        proto_fun_identifier: qsig.signature_pb2.ChunkSignature.FunctionIdentifier,
    ) -> FunctionIdentifier:
        """Load a function identifier from a protobuf

        Args:
            proto_fun_identifier: Serialized data

        Returns:
            FunctionIdentifier
        """
        return FunctionIdentifier(
            name=proto_fun_identifier.name,
            index=proto_fun_identifier.identity.index,
            size=proto_fun_identifier.identity.size,
            strings=list(proto_fun_identifier.identity.strings),
            constants=list(proto_fun_identifier.identity.constants),
            calls=list(proto_fun_identifier.identity.calls),
            function=None,
        )
