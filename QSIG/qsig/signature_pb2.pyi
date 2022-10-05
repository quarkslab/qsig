"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import google.protobuf.timestamp_pb2
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor = ...

class ChunkSignature(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
    class ArtefactType(metaclass=_ArtefactType):
        V = typing.NewType("V", builtins.int)
    ARTEFACT_TYPE_UNKNOWN = ChunkSignature.ArtefactType.V(0)
    ARTEFACT_TYPE_STRINGS = ChunkSignature.ArtefactType.V(1)
    ARTEFACT_TYPE_CONSTANTS = ChunkSignature.ArtefactType.V(2)
    ARTEFACT_TYPE_CALLS = ChunkSignature.ArtefactType.V(3)
    ARTEFACT_TYPE_CONDITIONS = ChunkSignature.ArtefactType.V(4)
    class _ArtefactType(
        google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[ArtefactType.V],
        builtins.type,
    ):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor = ...
        ARTEFACT_TYPE_UNKNOWN = ChunkSignature.ArtefactType.V(0)
        ARTEFACT_TYPE_STRINGS = ChunkSignature.ArtefactType.V(1)
        ARTEFACT_TYPE_CONSTANTS = ChunkSignature.ArtefactType.V(2)
        ARTEFACT_TYPE_CALLS = ChunkSignature.ArtefactType.V(3)
        ARTEFACT_TYPE_CONDITIONS = ChunkSignature.ArtefactType.V(4)
    class StringsSignature(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        YARA_FIELD_NUMBER: builtins.int
        STRINGS_FIELD_NUMBER: builtins.int
        yara: builtins.bytes = ...
        @property
        def strings(
            self,
        ) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[
            typing.Text
        ]: ...
        def __init__(
            self,
            *,
            yara: builtins.bytes = ...,
            strings: typing.Optional[typing.Iterable[typing.Text]] = ...,
        ) -> None: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "strings", b"strings", "yara", b"yara"
            ],
        ) -> None: ...
    class Identifier(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        INDEX_FIELD_NUMBER: builtins.int
        SIZE_FIELD_NUMBER: builtins.int
        STRINGS_FIELD_NUMBER: builtins.int
        CONSTANTS_FIELD_NUMBER: builtins.int
        CALLS_FIELD_NUMBER: builtins.int
        index: builtins.int = ...
        size: builtins.int = ...
        @property
        def strings(
            self,
        ) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[
            typing.Text
        ]: ...
        @property
        def constants(
            self,
        ) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[
            builtins.int
        ]: ...
        @property
        def calls(
            self,
        ) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[
            typing.Text
        ]: ...
        def __init__(
            self,
            *,
            index: builtins.int = ...,
            size: builtins.int = ...,
            strings: typing.Optional[typing.Iterable[typing.Text]] = ...,
            constants: typing.Optional[typing.Iterable[builtins.int]] = ...,
            calls: typing.Optional[typing.Iterable[typing.Text]] = ...,
        ) -> None: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "calls",
                b"calls",
                "constants",
                b"constants",
                "index",
                b"index",
                "size",
                b"size",
                "strings",
                b"strings",
            ],
        ) -> None: ...
    class ChunkIdentifier(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        IDENTITY_FIELD_NUMBER: builtins.int
        FUNC_NAME_FIELD_NUMBER: builtins.int
        FUNC_INDEX_FIELD_NUMBER: builtins.int
        func_name: typing.Text = ...
        func_index: builtins.int = ...
        @property
        def identity(self) -> global___ChunkSignature.Identifier: ...
        def __init__(
            self,
            *,
            identity: typing.Optional[global___ChunkSignature.Identifier] = ...,
            func_name: typing.Text = ...,
            func_index: builtins.int = ...,
        ) -> None: ...
        def HasField(
            self, field_name: typing_extensions.Literal["identity", b"identity"]
        ) -> builtins.bool: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "func_index",
                b"func_index",
                "func_name",
                b"func_name",
                "identity",
                b"identity",
            ],
        ) -> None: ...
    class FunctionIdentifier(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        IDENTITY_FIELD_NUMBER: builtins.int
        NAME_FIELD_NUMBER: builtins.int
        name: typing.Text = ...
        @property
        def identity(self) -> global___ChunkSignature.Identifier: ...
        def __init__(
            self,
            *,
            identity: typing.Optional[global___ChunkSignature.Identifier] = ...,
            name: typing.Text = ...,
        ) -> None: ...
        def HasField(
            self, field_name: typing_extensions.Literal["identity", b"identity"]
        ) -> builtins.bool: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "identity", b"identity", "name", b"name"
            ],
        ) -> None: ...
    class ConstantsSignature(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        class Constant(google.protobuf.message.Message):
            DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
            VALUE_FIELD_NUMBER: builtins.int
            VULN_COUNT_FIELD_NUMBER: builtins.int
            FIX_COUNT_FIELD_NUMBER: builtins.int
            NEW_FIELD_NUMBER: builtins.int
            value: builtins.int = ...
            vuln_count: builtins.int = ...
            fix_count: builtins.int = ...
            new: builtins.bool = ...
            def __init__(
                self,
                *,
                value: builtins.int = ...,
                vuln_count: builtins.int = ...,
                fix_count: builtins.int = ...,
                new: builtins.bool = ...,
            ) -> None: ...
            def ClearField(
                self,
                field_name: typing_extensions.Literal[
                    "fix_count",
                    b"fix_count",
                    "new",
                    b"new",
                    "value",
                    b"value",
                    "vuln_count",
                    b"vuln_count",
                ],
            ) -> None: ...
        CONSTANTS_FIELD_NUMBER: builtins.int
        @property
        def constants(
            self,
        ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
            global___ChunkSignature.ConstantsSignature.Constant
        ]: ...
        def __init__(
            self,
            *,
            constants: typing.Optional[
                typing.Iterable[global___ChunkSignature.ConstantsSignature.Constant]
            ] = ...,
        ) -> None: ...
        def ClearField(
            self, field_name: typing_extensions.Literal["constants", b"constants"]
        ) -> None: ...
    class CallsSignature(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        class Call(google.protobuf.message.Message):
            DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
            FUNCTION_FIELD_NUMBER: builtins.int
            IN_DEGREE_FIELD_NUMBER: builtins.int
            OUT_DEGREE_FIELD_NUMBER: builtins.int
            CALLER_COUNT_FIELD_NUMBER: builtins.int
            in_degree: builtins.int = ...
            out_degree: builtins.int = ...
            caller_count: builtins.int = ...
            @property
            def function(self) -> global___ChunkSignature.FunctionIdentifier: ...
            def __init__(
                self,
                *,
                function: typing.Optional[
                    global___ChunkSignature.FunctionIdentifier
                ] = ...,
                in_degree: builtins.int = ...,
                out_degree: builtins.int = ...,
                caller_count: builtins.int = ...,
            ) -> None: ...
            def HasField(
                self, field_name: typing_extensions.Literal["function", b"function"]
            ) -> builtins.bool: ...
            def ClearField(
                self,
                field_name: typing_extensions.Literal[
                    "caller_count",
                    b"caller_count",
                    "function",
                    b"function",
                    "in_degree",
                    b"in_degree",
                    "out_degree",
                    b"out_degree",
                ],
            ) -> None: ...
        CALLER_FIELD_NUMBER: builtins.int
        CALLEES_FIELD_NUMBER: builtins.int
        @property
        def caller(self) -> global___ChunkSignature.CallsSignature.Call: ...
        @property
        def callees(
            self,
        ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
            global___ChunkSignature.CallsSignature.Call
        ]: ...
        def __init__(
            self,
            *,
            caller: typing.Optional[global___ChunkSignature.CallsSignature.Call] = ...,
            callees: typing.Optional[
                typing.Iterable[global___ChunkSignature.CallsSignature.Call]
            ] = ...,
        ) -> None: ...
        def HasField(
            self, field_name: typing_extensions.Literal["caller", b"caller"]
        ) -> builtins.bool: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "callees", b"callees", "caller", b"caller"
            ],
        ) -> None: ...
    class ConditionSignature(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        class Condition(google.protobuf.message.Message):
            DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
            class LabelType(metaclass=_LabelType):
                V = typing.NewType("V", builtins.int)
            LABEL_TYPE_UNKNOWN = (
                ChunkSignature.ConditionSignature.Condition.LabelType.V(0)
            )
            LABEL_TYPE_CONSTANT = (
                ChunkSignature.ConditionSignature.Condition.LabelType.V(1)
            )
            LABEL_TYPE_ARGUMENT = (
                ChunkSignature.ConditionSignature.Condition.LabelType.V(2)
            )
            LABEL_TYPE_CALL = ChunkSignature.ConditionSignature.Condition.LabelType.V(3)
            class _LabelType(
                google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[
                    LabelType.V
                ],
                builtins.type,
            ):
                DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor = ...
                LABEL_TYPE_UNKNOWN = (
                    ChunkSignature.ConditionSignature.Condition.LabelType.V(0)
                )
                LABEL_TYPE_CONSTANT = (
                    ChunkSignature.ConditionSignature.Condition.LabelType.V(1)
                )
                LABEL_TYPE_ARGUMENT = (
                    ChunkSignature.ConditionSignature.Condition.LabelType.V(2)
                )
                LABEL_TYPE_CALL = (
                    ChunkSignature.ConditionSignature.Condition.LabelType.V(3)
                )
            class Element(google.protobuf.message.Message):
                DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
                TYPE_FIELD_NUMBER: builtins.int
                VALUE_FIELD_NUMBER: builtins.int
                type: global___ChunkSignature.ConditionSignature.Condition.LabelType.V = (
                    ...
                )
                value: builtins.int = ...
                def __init__(
                    self,
                    *,
                    type: global___ChunkSignature.ConditionSignature.Condition.LabelType.V = ...,
                    value: builtins.int = ...,
                ) -> None: ...
                def ClearField(
                    self,
                    field_name: typing_extensions.Literal[
                        "type", b"type", "value", b"value"
                    ],
                ) -> None: ...
            ELEMENTS_FIELD_NUMBER: builtins.int
            COUNT_FIELD_NUMBER: builtins.int
            count: builtins.int = ...
            @property
            def elements(
                self,
            ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
                global___ChunkSignature.ConditionSignature.Condition.Element
            ]: ...
            def __init__(
                self,
                *,
                elements: typing.Optional[
                    typing.Iterable[
                        global___ChunkSignature.ConditionSignature.Condition.Element
                    ]
                ] = ...,
                count: builtins.int = ...,
            ) -> None: ...
            def ClearField(
                self,
                field_name: typing_extensions.Literal[
                    "count", b"count", "elements", b"elements"
                ],
            ) -> None: ...
        CONDITIONS_FIELD_NUMBER: builtins.int
        @property
        def conditions(
            self,
        ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
            global___ChunkSignature.ConditionSignature.Condition
        ]: ...
        def __init__(
            self,
            *,
            conditions: typing.Optional[
                typing.Iterable[global___ChunkSignature.ConditionSignature.Condition]
            ] = ...,
        ) -> None: ...
        def ClearField(
            self, field_name: typing_extensions.Literal["conditions", b"conditions"]
        ) -> None: ...
    CHUNK_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    STRING_SIG_FIELD_NUMBER: builtins.int
    CONSTANT_SIG_FIELD_NUMBER: builtins.int
    CALL_SIG_FIELD_NUMBER: builtins.int
    CONDITION_SIG_FIELD_NUMBER: builtins.int
    @property
    def type(
        self,
    ) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[
        global___ChunkSignature.ArtefactType.V
    ]: ...
    @property
    def chunk(self) -> global___ChunkSignature.ChunkIdentifier: ...
    @property
    def string_sig(self) -> global___ChunkSignature.StringsSignature: ...
    @property
    def constant_sig(self) -> global___ChunkSignature.ConstantsSignature: ...
    @property
    def call_sig(self) -> global___ChunkSignature.CallsSignature: ...
    @property
    def condition_sig(self) -> global___ChunkSignature.ConditionSignature: ...
    def __init__(
        self,
        *,
        chunk: typing.Optional[global___ChunkSignature.ChunkIdentifier] = ...,
        type: typing.Optional[
            typing.Iterable[global___ChunkSignature.ArtefactType.V]
        ] = ...,
        string_sig: typing.Optional[global___ChunkSignature.StringsSignature] = ...,
        constant_sig: typing.Optional[global___ChunkSignature.ConstantsSignature] = ...,
        call_sig: typing.Optional[global___ChunkSignature.CallsSignature] = ...,
        condition_sig: typing.Optional[
            global___ChunkSignature.ConditionSignature
        ] = ...,
    ) -> None: ...
    def HasField(
        self,
        field_name: typing_extensions.Literal[
            "call_sig",
            b"call_sig",
            "chunk",
            b"chunk",
            "condition_sig",
            b"condition_sig",
            "constant_sig",
            b"constant_sig",
            "string_sig",
            b"string_sig",
        ],
    ) -> builtins.bool: ...
    def ClearField(
        self,
        field_name: typing_extensions.Literal[
            "call_sig",
            b"call_sig",
            "chunk",
            b"chunk",
            "condition_sig",
            b"condition_sig",
            "constant_sig",
            b"constant_sig",
            "string_sig",
            b"string_sig",
            "type",
            b"type",
        ],
    ) -> None: ...

global___ChunkSignature = ChunkSignature

class FileSignature(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
    class FileType(metaclass=_FileType):
        V = typing.NewType("V", builtins.int)
    FILE_TYPE_UNKNOWN = FileSignature.FileType.V(0)
    FILE_TYPE_OBJECT = FileSignature.FileType.V(1)
    FILE_TYPE_STATIC = FileSignature.FileType.V(2)
    FILE_TYPE_SHARED = FileSignature.FileType.V(3)
    FILE_TYPE_EXEC = FileSignature.FileType.V(4)
    FILE_TYPE_BLOB = FileSignature.FileType.V(5)
    class _FileType(
        google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[FileType.V],
        builtins.type,
    ):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor = ...
        FILE_TYPE_UNKNOWN = FileSignature.FileType.V(0)
        FILE_TYPE_OBJECT = FileSignature.FileType.V(1)
        FILE_TYPE_STATIC = FileSignature.FileType.V(2)
        FILE_TYPE_SHARED = FileSignature.FileType.V(3)
        FILE_TYPE_EXEC = FileSignature.FileType.V(4)
        FILE_TYPE_BLOB = FileSignature.FileType.V(5)
    class FileMeta(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        NAME_FIELD_NUMBER: builtins.int
        TYPE_FIELD_NUMBER: builtins.int
        SIZE_FIELD_NUMBER: builtins.int
        SHA256_FIELD_NUMBER: builtins.int
        name: typing.Text = ...
        type: global___FileSignature.FileType.V = ...
        size: builtins.int = ...
        sha256: typing.Text = ...
        def __init__(
            self,
            *,
            name: typing.Text = ...,
            type: global___FileSignature.FileType.V = ...,
            size: builtins.int = ...,
            sha256: typing.Text = ...,
        ) -> None: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "name", b"name", "sha256", b"sha256", "size", b"size", "type", b"type"
            ],
        ) -> None: ...
    FILE_META_FIELD_NUMBER: builtins.int
    CHUNK_SIGNATURES_FIELD_NUMBER: builtins.int
    @property
    def file_meta(self) -> global___FileSignature.FileMeta: ...
    @property
    def chunk_signatures(
        self,
    ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
        global___ChunkSignature
    ]: ...
    def __init__(
        self,
        *,
        file_meta: typing.Optional[global___FileSignature.FileMeta] = ...,
        chunk_signatures: typing.Optional[
            typing.Iterable[global___ChunkSignature]
        ] = ...,
    ) -> None: ...
    def HasField(
        self, field_name: typing_extensions.Literal["file_meta", b"file_meta"]
    ) -> builtins.bool: ...
    def ClearField(
        self,
        field_name: typing_extensions.Literal[
            "chunk_signatures", b"chunk_signatures", "file_meta", b"file_meta"
        ],
    ) -> None: ...

global___FileSignature = FileSignature

class CVESignature(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
    class Architecture(metaclass=_Architecture):
        V = typing.NewType("V", builtins.int)
    ARCHITECTURE_UNKNOWN = CVESignature.Architecture.V(0)
    ARCHITECTURE_X86 = CVESignature.Architecture.V(1)
    ARCHITECTURE_X64 = CVESignature.Architecture.V(2)
    ARCHITECTURE_ARM = CVESignature.Architecture.V(3)
    ARCHITECTURE_ARM64 = CVESignature.Architecture.V(4)
    class _Architecture(
        google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Architecture.V],
        builtins.type,
    ):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor = ...
        ARCHITECTURE_UNKNOWN = CVESignature.Architecture.V(0)
        ARCHITECTURE_X86 = CVESignature.Architecture.V(1)
        ARCHITECTURE_X64 = CVESignature.Architecture.V(2)
        ARCHITECTURE_ARM = CVESignature.Architecture.V(3)
        ARCHITECTURE_ARM64 = CVESignature.Architecture.V(4)
    class Meta(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor = ...
        AUTHOR_FIELD_NUMBER: builtins.int
        CVE_ID_FIELD_NUMBER: builtins.int
        FIX_COMMIT_FIELD_NUMBER: builtins.int
        CREATION_FIELD_NUMBER: builtins.int
        GENERATED_FROM_FIELD_NUMBER: builtins.int
        author: typing.Text = ...
        cve_id: typing.Text = ...
        fix_commit: typing.Text = ...
        generated_from: global___CVESignature.Architecture.V = ...
        @property
        def creation(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
        def __init__(
            self,
            *,
            author: typing.Text = ...,
            cve_id: typing.Text = ...,
            fix_commit: typing.Text = ...,
            creation: typing.Optional[google.protobuf.timestamp_pb2.Timestamp] = ...,
            generated_from: global___CVESignature.Architecture.V = ...,
        ) -> None: ...
        def HasField(
            self, field_name: typing_extensions.Literal["creation", b"creation"]
        ) -> builtins.bool: ...
        def ClearField(
            self,
            field_name: typing_extensions.Literal[
                "author",
                b"author",
                "creation",
                b"creation",
                "cve_id",
                b"cve_id",
                "fix_commit",
                b"fix_commit",
                "generated_from",
                b"generated_from",
            ],
        ) -> None: ...
    META_FIELD_NUMBER: builtins.int
    FILE_SIGNATURES_FIELD_NUMBER: builtins.int
    @property
    def meta(self) -> global___CVESignature.Meta: ...
    @property
    def file_signatures(
        self,
    ) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[
        global___FileSignature
    ]: ...
    def __init__(
        self,
        *,
        meta: typing.Optional[global___CVESignature.Meta] = ...,
        file_signatures: typing.Optional[typing.Iterable[global___FileSignature]] = ...,
    ) -> None: ...
    def HasField(
        self, field_name: typing_extensions.Literal["meta", b"meta"]
    ) -> builtins.bool: ...
    def ClearField(
        self,
        field_name: typing_extensions.Literal[
            "file_signatures", b"file_signatures", "meta", b"meta"
        ],
    ) -> None: ...

global___CVESignature = CVESignature
