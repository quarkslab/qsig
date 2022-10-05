from __future__ import annotations
import collections
import pathlib
from typing import Optional, List, Tuple, Union, MutableMapping, Set, Dict

import google
import quokka
import quokka.function

import firmextractor.firmware

import qsig.cve
from qsig import signature_pb2 as sig_pb
import qsig.sig


class Signature:
    """Signature abstract class"""

    pass


class CVESignature(Signature):
    """CVESignature: signature for a patch

    A Signature is like a matryoshka doll, it contains a list of FileSignatures, one for
    each affected file by a patch

    Attributes:
        signature: Protobuf serialization
        file_path: Path towards the signature on the disk
        file_signatures: Signatures for the files affected by the CVE

    Args:
        signature_path: Path towards the signature on the disk

    """

    def __init__(self, signature_path: Optional[pathlib.Path] = None) -> None:
        """Constructor"""
        self.signature: "sig_pb.CVESignature" = sig_pb.CVESignature()
        self.file_path: Optional[pathlib.Path] = signature_path

        self.file_signatures: List["FileSignature"] = []

        if self.file_path is not None:
            self.load(self.file_path)

    @property
    def cve_id(self) -> str:
        """Return the CVE id"""
        return self.signature.meta.cve_id

    @cve_id.setter
    def cve_id(self, cve_id: str):
        """Set the CVE id"""
        self.signature.meta.cve_id = cve_id

    @property
    def commit(self) -> str:
        """Return the commit-id"""
        return self.signature.meta.fix_commit

    @commit.setter
    def commit(self, commit: str):
        """Set the commit-id"""
        self.signature.meta.fix_commit = commit

    @property
    def author(self) -> str:
        """Return the author name"""
        return self.signature.meta.author

    @author.setter
    def author(self, author: str):
        """Set the author name"""
        self.signature.meta.author = author

    @property
    def timestamp(self):
        """Returns the creation date for the signature"""
        return self.signature.meta.creation

    @timestamp.setter
    def timestamp(self, value: str):
        """Sets the creation date of the signature"""
        if value == "now":
            self.signature.meta.creation.GetCurrentTime()

    @property
    def architecture(self) -> "qsig.cve.Architecture":
        """Returns the architecture from the signature"""
        return qsig.sig.ArchitectureConverter.to_code(
            self.signature.meta.generated_from
        )

    @architecture.setter
    def architecture(self, value: "qsig.cve.Architecture") -> None:
        """Set the architecture from the signature"""
        self.signature.meta.generated_from = qsig.sig.ArchitectureConverter.to_proto(
            value
        )

    def set_meta(
        self,
        vulnerability: "qsig.cve.Vulnerability",
        architecture: "qsig.cve.Architecture",
    ) -> None:
        """Set meta information for a CVE Signature

        Meta information at a signature level are valid for all sub-signatures and
        consist manly on the author and the creation date/

        Args:
            vulnerability: Signed vulnerability
            architecture: Architecture signed
        """
        self.author: str = qsig.Settings.AUTHOR
        self.cve_id: str = vulnerability.name
        self.commit: str = getattr(vulnerability, "cve_commit", "")
        self.timestamp: str = "now"
        self.architecture = architecture

    def add_file(self) -> "FileSignature":
        """Add a FileSignature and return it"""
        file_signature = self.signature.file_signatures.add()
        self.file_signatures.append(FileSignature(file_signature, self))
        return self.file_signatures[-1]

    def remove_last_file(self) -> bool:
        """Remove the last file signature if there is one"""
        if self.file_signatures:
            del self.signature.file_signatures[-1]
            return True

        return False

    def write(self, file_path: pathlib.Path) -> None:
        """Write a signature on the disk

        Args:
            file_path: Path to write the signature to

        Raises:
            SignatureException when it cannot write
        """
        try:
            with open(file_path, "wb") as file:
                file.write(self.signature.SerializeToString())
        except PermissionError:
            raise qsig.sig.exc.SignatureException("Unable to write the signature")

    def load(self, file_path: pathlib.Path) -> None:
        """Load a signature from the disk

        Args:
            file_path: Path towards the signature
        """
        try:
            with open(str(file_path), "rb") as file:
                self.signature.ParseFromString(file.read())
        except (
            FileNotFoundError,
            IsADirectoryError,
            google.protobuf.message.DecodeError,
        ):
            raise qsig.sig.exc.SignatureException("Unable to load the signature")

        self.file_signatures = []
        for file_signature in self.signature.file_signatures:
            self.file_signatures.append(FileSignature(file_signature, self))

    def __str__(self) -> str:
        """String representation"""
        return_files = []
        for file_signature in self.file_signatures:
            return_files.extend(str(file_signature).split("\n"))

        final_str = f"Signature {self.cve_id} ({self.commit:.6}) :"
        for chunk in return_files:
            final_str += "\n    " + chunk

        return final_str


class FileSignature(Signature):
    """File Signature

    A File Signature represents the signature for a file in a patch.

    Args:
        signature: Protobuf object
        parent: Link towards the CVESignature

    Attributes:
        signature: Protobuf object
        cve_signature: Link towards the CVESignature
        chunk_signatures: List of Chunk Signatures
    """

    def __init__(self, signature: "sig_pb.FileSignature", parent: CVESignature) -> None:
        """Constructor"""
        self.signature: "sig_pb.FileSignature" = signature
        self.cve_signature: "CVESignature" = parent

        self.chunk_signatures: List["ChunkSignature"] = []
        for chunk_signature in self.signature.chunk_signatures:
            self.chunk_signatures.append(ChunkSignature(chunk_signature, self))

    @property
    def file_name(self) -> str:
        """Return the file name"""
        return self.signature.file_meta.name

    @file_name.setter
    def file_name(self, name: str) -> None:
        """Set the file name"""
        self.signature.file_meta.name = name

    @property
    def size(self) -> int:
        """Get the file size"""
        return self.signature.file_meta.size

    @size.setter
    def size(self, size: int) -> None:
        """Set the file size"""
        self.signature.file_meta.size = size

    @property
    def file_type(self) -> firmextractor.fs.FileType:
        """Return the file type"""
        return qsig.sig.FileTypeConverter.to_code(self.signature.file_meta.type)

    @file_type.setter
    def file_type(self, file_type: firmextractor.fs.FileType) -> None:
        """Get the file type"""
        self.signature.file_meta.type = qsig.sig.FileTypeConverter.to_proto(file_type)

    @property
    def file_hash(self) -> str:
        """Get the SHA256 of the file"""
        return self.signature.file_meta.sha256

    @file_hash.setter
    def file_hash(self, value: str) -> None:
        """Set the SHA256 hash value"""
        self.signature.file_meta.sha256 = value

    def set_file_meta(self, file_path: Union[str, pathlib.Path]) -> None:
        """Prepare the metadata for the signature at a file level

        Note: The file meta only consider the *fixed* file.

        Args:
            file_path: Path towards the binary where the signature will be generated
        """
        path = pathlib.Path(file_path)
        self.file_hash = qsig.sig.utils.sha256_file(path)

        self.file_name = qsig.sig.utils.norm_name(path, sha256=self.file_hash)
        self.size = path.stat().st_size
        self.file_type = firmextractor.fs.get_filetype(file_path)

    def add_chunk_signature(self) -> "ChunkSignature":
        """Add a ChunkSignature to the list of chunk signatures"""
        chunk_signature = self.signature.chunk_signatures.add()
        return ChunkSignature(chunk_signature, self)

    def remove_last_chunk(self) -> bool:
        """Remove the last chunk signature"""
        if self.signature.chunk_signatures:
            del self.signature.chunk_signatures[-1]
            return True

        return False

    def __str__(self):
        """String representation"""
        return_chunk = []
        for chunk in self.chunk_signatures:
            return_chunk.extend(str(chunk).split("\n"))

        final_str = f"File {self.file_name} ({self.file_type.name}):"
        for chunk in return_chunk:
            final_str += "\n    " + chunk
        return final_str


class ChunkSignature(Signature):
    """ChunkSignature

    A Chunk signature signs a function

    Args:
        signature: Protobuf object
        parent: Direct link towards the FileSignature

    Attributes:
        signature: Protobuf object
        parent: Direct link towards the FileSignature

    """

    def __init__(self, signature: "sig_pb.ChunkSignature", parent: "FileSignature"):
        self.signature: "sig_pb.ChunkSignature" = signature
        self.file_signature = parent

    @property
    def artifact_type(self) -> List[qsig.sig.artefact.Artefact]:
        """Get the list of artifacts set in this signature"""
        return [
            qsig.sig.ArtefactTypeConverter.to_code(artefact)
            for artefact in self.signature.type
        ]

    @artifact_type.setter
    def artifact_type(self, _) -> None:
        raise NotImplemented

    def add_artifact_type(self, type_: qsig.sig.artefact.Artefact) -> None:
        """Add an artifact tot he list of artifacts"""
        proto_type = qsig.sig.ArtefactTypeConverter.to_proto(type_)
        if proto_type not in self.artifact_type:
            self.signature.type.append(proto_type)

    @staticmethod
    def create_identifier(
        proto, identifier: "qsig.sig.function_identifer.Identity"
    ) -> None:
        """Create an identifier from an Identity

        Args:
            proto: Protobuf object
            identifier: Identity to serialize
        """
        proto.index = identifier.index
        proto.size = identifier.size
        proto.strings[:] = identifier.strings
        proto.constants[:] = identifier.constants
        proto.calls[:] = identifier.calls

    def create_chunk_identifier(
        self, chunk_identifier: "qsig.sig.function_identifer.ChunkIdentifier"
    ) -> "sig_pb.ChunkSignature.ChunkIdentifier":
        """Create a chunk identifier

        Args:
            chunk_identifier: Chunk to serialize

        Returns:
            A serialized version of the chunk identifier
        """
        proto_identifier: sig_pb.ChunkSignature.ChunkIdentifier = (
            self.signature.ChunkIdentifier()
        )

        self.create_identifier(proto_identifier.identity, chunk_identifier)

        proto_identifier.func_name = chunk_identifier.func_name
        proto_identifier.func_index = chunk_identifier.func_index

        return proto_identifier

    @property
    def chunk_identifier(self):
        """Return the chunk identifier for this signature (the main one)"""
        return self.signature.chunk

    @chunk_identifier.setter
    def chunk_identifier(
        self, chunk_identifier: "qsig.sig.function_identifer.ChunkIdentifier"
    ):
        """Create the chunk identifier for this signature"""
        chunk_sig = self.create_chunk_identifier(chunk_identifier)
        self.signature.chunk.CopyFrom(chunk_sig)

    @property
    def string_signature(self) -> Optional[bytes]:
        """Retrieve the string signature (YARA form)"""
        if qsig.sig.artefact.Artefact.STRINGS in self.artifact_type:
            return self.signature.string_sig.yara

        return None

    @property
    def string_signature_local(self) -> Optional[Set[str]]:
        """Retrieve the string signature (local form)"""
        if qsig.sig.artefact.Artefact.STRINGS in self.artifact_type:
            return set(self.signature.string_sig.strings)

        return None

    @string_signature.setter
    def string_signature(
        self, string_sig: Tuple[qsig.sig.yara_rule.RuleFile, Set[str]]
    ) -> None:
        """Store the string signature (both form)"""
        yara_rule: qsig.sig.yara_rule.RuleFile
        new_strings: Set[str]
        yara_rule, new_strings = string_sig

        try:
            self.signature.string_sig.yara = yara_rule.compile()
            self.signature.string_sig.strings[:] = new_strings
        except qsig.sig.exc.YaraToolException:
            raise qsig.sig.exc.SignatureException("Unable to generate YARA rule")

        self.add_artifact_type(qsig.sig.artefact.Artefact.STRINGS)

    @property
    def constant_signature(self):
        """Retrieve the constant signature"""
        if qsig.sig.artefact.Artefact.CONSTANTS in self.artifact_type:
            return self.signature.constant_sig

    @constant_signature.setter
    def constant_signature(
        self, new_constants: List[Tuple[int, int, int, bool]]
    ) -> None:
        """Store the constant signature"""
        normed_constants: MutableMapping = {}
        for constant, vuln_count, fix_count, only_in_fix in new_constants:
            for normed_constant in qsig.sig.utils.norm_constant(constant):
                if not (
                    qsig.Settings.MIN_CONSTANT
                    <= normed_constant
                    <= qsig.Settings.MAX_CONSTANT
                ):
                    continue
                previous_count = normed_constants.get(normed_constant, (0, 0, False))
                normed_constants[normed_constant] = (
                    vuln_count + previous_count[0],
                    fix_count + previous_count[1],
                    only_in_fix,
                )

        for constant, counts in normed_constants.items():
            constant_sig = self.signature.constant_sig.constants.add()
            constant_sig.value = constant
            constant_sig.vuln_count = counts[0]
            constant_sig.fix_count = counts[1]
            constant_sig.new = counts[2]

        self.add_artifact_type(qsig.sig.artefact.Artefact.CONSTANTS)

    @property
    def calls_signature(self):
        """Retrieve the call signature"""
        if qsig.sig.artefact.Artefact.CALLS in self.artifact_type:
            return self.signature.call_sig

        return None

    @calls_signature.setter
    def calls_signature(self, _):
        raise NotImplemented

    def add_call_signature(
        self,
        chunk: quokka.function.Chunk,
        callees: List["qsig.sig.function_identifer.FunctionIdentifier"],
    ) -> None:
        """Add a call signature: (chunk, list of callees by chunk).

        Args:
            chunk: Caller chunk
            callees: Functions called by `chunk`
        """
        calls_sig = self.signature.CallsSignature()
        # The caller does not need to repeat the chunk identifier
        chunk_degrees = quokka.function.get_degrees(chunk)
        calls_sig.caller.in_degree = chunk_degrees[0]
        calls_sig.caller.out_degree = chunk_degrees[1]

        caller_counts = collections.Counter(target.start for target in chunk.calls)

        callee: qsig.sig.function_identifer.FunctionIdentifier
        for callee in callees:
            proto_callee = calls_sig.callees.add()

            proto_callee.function.name = callee.name
            self.create_identifier(proto_callee.function.identity, callee)

            assert callee.function is not None

            func_degrees = quokka.function.get_degrees(callee.function)
            proto_callee.in_degree = func_degrees[0]
            proto_callee.out_degree = func_degrees[1]

            # FIX: un-dereference thunk when needed
            if callee.function.start not in caller_counts:
                dereferenced = quokka.function.dereference_thunk(
                    callee.function, caller=True
                )
                proto_callee.caller_count = caller_counts[dereferenced.start]
            else:
                proto_callee.caller_count = caller_counts[callee.function.start]

        self.signature.call_sig.CopyFrom(calls_sig)
        self.add_artifact_type(qsig.sig.artefact.Artefact.CALLS)

    @property
    def condition_signature(self):
        """Retrieve the condition signature"""
        if qsig.sig.artefact.Artefact.CONDITIONS in self.artifact_type:
            return self.signature.condition_sig

    @condition_signature.setter
    def condition_signature(
        self, new_conditions: List[Tuple["qsig.sig.conditions.Condition", int]]
    ) -> None:
        """Store the condition signature"""
        condition_sig = self.signature.ConditionSignature()

        for condition, count in new_conditions:
            condition_proto = condition_sig.conditions.add()

            for element in condition.compared_elements:
                element_proto = condition_proto.elements.add()
                element_proto.type = qsig.sig.ConditionElementConverter.to_proto(
                    type(element)
                )
                element_proto.value = element.id

            condition_proto.count = count

        self.signature.condition_sig.CopyFrom(condition_sig)
        self.add_artifact_type(qsig.sig.artefact.Artefact.CONDITIONS)

    def __str__(self) -> str:
        """String representation"""
        return f'Chunk : {" ".join(x.name for x in self.artifact_type)}'
