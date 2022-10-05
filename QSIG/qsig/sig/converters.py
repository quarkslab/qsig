from typing import Any, Dict

import firmextractor.fs as fs_m

import qsig.signature_pb2 as sig_pb2
import qsig.cve as cve_m
import qsig.sig.artefact as artefact_m
import qsig.sig.conditions as cond_m


class Converter:
    """Converter

    A converter transforms types from Protobuf to Python enums.
    """

    translation: Dict[Any, Any] = {}
    """Translations between the two types: first one is the enum, second is the proto.
    """

    default_type: Dict[str, Any] = {}
    """Defaults types for both sides"""

    @classmethod
    def to_proto(cls, code_type: Any) -> Any:
        """Convert an enum value to a proto type"""
        return cls.translation.get(code_type, cls.default_type["proto"])

    @classmethod
    def to_code(cls, proto_type: Any) -> Any:
        """Convert a proto type to an enum value"""
        return next(
            (
                code_type
                for code_type, proto in cls.translation.items()
                if proto_type == proto
            ),
            cls.default_type["code"],
        )


class FileTypeConverter(Converter):
    """File Type Converter"""

    translation = {
        fs_m.FileType.OBJECT: sig_pb2.FileSignature.FILE_TYPE_OBJECT,
        fs_m.FileType.STATIC: sig_pb2.FileSignature.FILE_TYPE_STATIC,
        fs_m.FileType.LIBRARY: sig_pb2.FileSignature.FILE_TYPE_SHARED,
        fs_m.FileType.EXECUTABLE: sig_pb2.FileSignature.FILE_TYPE_EXEC,
        fs_m.FileType.BLOB: sig_pb2.FileSignature.FILE_TYPE_BLOB,
    }

    default_type = {
        "code": fs_m.FileType.UNKNOWN,
        "proto": sig_pb2.FileSignature.FILE_TYPE_UNKNOWN,
    }


class ArtefactTypeConverter(Converter):
    """Artefact Type Converter"""

    translation = {
        artefact_m.Artefact.STRINGS: sig_pb2.ChunkSignature.ARTEFACT_TYPE_STRINGS,
        artefact_m.Artefact.CONSTANTS: sig_pb2.ChunkSignature.ARTEFACT_TYPE_CONSTANTS,
        artefact_m.Artefact.CALLS: sig_pb2.ChunkSignature.ARTEFACT_TYPE_CALLS,
        artefact_m.Artefact.CONDITIONS: sig_pb2.ChunkSignature.ARTEFACT_TYPE_CONDITIONS,
    }

    default_type = {
        "code": artefact_m.Artefact.UNKNOWN,
        "proto": sig_pb2.ChunkSignature.ARTEFACT_TYPE_UNKNOWN,
    }


class ConditionElementConverter(Converter):
    """Conditions elements Converter"""

    translation = {
        cond_m.ArgLabel: sig_pb2.ChunkSignature.ConditionSignature.Condition.LABEL_TYPE_ARGUMENT,
        cond_m.CallLabel: sig_pb2.ChunkSignature.ConditionSignature.Condition.LABEL_TYPE_CALL,
        cond_m.ConstantLabel: sig_pb2.ChunkSignature.ConditionSignature.Condition.LABEL_TYPE_CONSTANT,
    }

    default_type = {
        "proto": sig_pb2.ChunkSignature.ConditionSignature.Condition.LABEL_TYPE_UNKNOWN,
        "code": cond_m.Label,
    }


class ArchitectureConverter(Converter):
    """Architecture converter"""

    translation = {
        cve_m.Architecture.x64: sig_pb2.CVESignature.ARCHITECTURE_X64,
        cve_m.Architecture.x86: sig_pb2.CVESignature.ARCHITECTURE_X86,
        cve_m.Architecture.arm: sig_pb2.CVESignature.ARCHITECTURE_ARM,
        cve_m.Architecture.arm64: sig_pb2.CVESignature.ARCHITECTURE_ARM64,
    }

    default_type = {
        "proto": sig_pb2.CVESignature.ARCHITECTURE_UNKNOWN,
        "code": cve_m.Architecture.x64,
    }
