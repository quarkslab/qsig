"""File system wrapper"""

import collections
import dataclasses
import enum
import fnmatch
import functools
import itertools
import multiprocessing
import pathlib
import hashlib
import pickle
from typing import Optional, Generator, List, Dict, Tuple

import magic

from firmextractor.settings import Settings

ELF_TYPES: List[str] = [
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-object",
    "application/x-pie-executable",
]
"""Mime types for elf"""

SHARED_OBJECT: List[str] = [
    "application/x-sharedlib",
]
"""Mime types for shared-objects (SO)"""

EXECUTABLE: List[str] = [
    "application/x-executable",
    "application/x-object",
    "application/x-pie-executable",
]
"""Mimes types for executables"""

BLOB: List[str] = ["application/octet-stream", "application/x-tplink-bin"]
"""Mimes types for Binary large objects (blob)"""

SYMLINKS: str = "inode/symlink"
"""Mime type for symlinks"""

MIME_TYPE_FILES: str = "_MIMES_TYPES.pickle"
"""Name of the file where the mime-types are stored"""

LINK_FILE: str = "_LINK_FILE.pickle"
"""Filename for keeping symlink resolution"""


def magic_wrapper(file_path: pathlib.Path, mime: bool = False) -> Optional[str]:
    """Wrap magic call to recover from errors

    Args:
        file_path: Path towards the file
        mime: Should we get the mime-type or the output of file command

    Returns:
        Mime type
    """
    try:
        return magic.from_file(str(file_path), mime=mime)
    except (FileNotFoundError, PermissionError):
        return None


def magic_wrapper_packed(
    args: Tuple[pathlib.Path, bool]
) -> Tuple[pathlib.Path, Optional[str]]:
    """Packed version of magic_wrapper for multiprocessing

    Args:
        args: A tuple containing the path and the boolean argument

    Returns:
        A tuple (Path, Mime-Type)
    """
    return args[0], magic_wrapper(*args)


class FileType(enum.IntEnum):
    # Exec types
    OBJECT = enum.auto()
    STATIC = enum.auto()
    LIBRARY = enum.auto()
    EXECUTABLE = enum.auto()
    BLOB = enum.auto()

    # Classic types
    TEXT = enum.auto()
    JSON = enum.auto()
    XML = enum.auto()

    SQLITE = enum.auto()
    JAR = enum.auto()

    APK = enum.auto()
    OAT = enum.auto()
    ODEX = enum.auto()

    ARCHIVE = enum.auto()
    AUDIO = enum.auto()
    IMAGE = enum.auto()
    FONT = enum.auto()

    UNKNOWN_APPLICATION = enum.auto()
    UNKNOWN = enum.auto()


def get_filetype(file_path: pathlib.Path, mime_type: Optional[str] = None) -> FileType:
    """Try to understand the file type from the mime type.

    Args:
        file_path: Path towards the file
        mime_type: Optional result of the mime command

    Returns:
        A FileType for the file
    """
    if mime_type is None:
        mime_type = magic_wrapper(file_path, mime=True)

    if mime_type.startswith("audio/"):
        return FileType.AUDIO
    elif mime_type.startswith("image/"):
        return FileType.IMAGE
    elif mime_type.startswith("text/"):
        if mime_type == "text/xml":
            return FileType.XML
        else:
            return FileType.TEXT

    elif mime_type.startswith("application/"):
        mime = magic_wrapper(file_path, mime=False)

        if mime_type == "application/json":
            return FileType.JSON
        elif mime_type in [
            "application/gzip",
            "application/zip",
        ]:
            return FileType.ARCHIVE
        elif mime_type == "application/x-sqlite3":
            return FileType.SQLITE
        elif mime_type == "application/java-archive":
            if file_path.suffix == ".apk":
                return FileType.APK
            return FileType.JAR
        elif mime_type == "application/x-archive":
            return FileType.STATIC
        elif "shared object" in mime:
            if file_path.suffix == ".odex":
                return FileType.ODEX
            elif file_path.suffix == ".oat":
                return FileType.OAT
            return FileType.LIBRARY
        elif "relocatable" in mime:
            return FileType.OBJECT
        elif "ELF" in mime:
            return FileType.EXECUTABLE
        elif mime_type in ["application/octet-stream", "application/x-tplink-bin"]:
            return FileType.BLOB

        return FileType.UNKNOWN_APPLICATION

    return FileType.UNKNOWN


def sha_1(file_path: pathlib.Path) -> str:
    """Get the SHA-1 of a file *path*."""
    digest = hashlib.sha1()
    digest.update(bytes(file_path.expanduser().resolve()))
    return digest.hexdigest()


class Endianess(enum.IntEnum):
    """Endianess"""

    LSB = enum.auto()
    MSB = enum.auto()


@dataclasses.dataclass
class File:
    """File abstraction"""

    name: str
    alternative_names: List[str]
    path: pathlib.Path
    extension: str
    mime_type: str

    symlink: bool
    size: int

    type: FileType
    firmware: "FileSystem"

    def __init__(
        self,
        file_path: pathlib.Path,
        alternative_names: List[str],
        mime_type: Optional[str] = None,
        firmware: Optional["FileSystem"] = None,
    ):
        if mime_type is None:
            mime_type = magic_wrapper(file_path, mime=True)

        self.mime_type = mime_type
        self.name = file_path.name
        self.extension = file_path.suffix
        self.alternative_names = alternative_names

        self.path = file_path
        self.type = get_filetype(file_path, mime_type)

        if not file_path.is_symlink():
            self.size = file_path.stat().st_size
            self.symlink = False
        else:
            self.size = 0
            self.symlink = True

        self.firmware = firmware


@dataclasses.dataclass
class ExecutableFile(File):
    """Executable file

    Note:
        Only works for ELF
    """

    endianess: Endianess
    address_size: int

    stripped: bool = True
    elf: bool = True

    def __init__(
        self,
        file_path: pathlib.Path,
        alternative_names: List[str],
        mime_type: Optional[str],
        firmware: Optional["FileSystem"],
    ):
        super(ExecutableFile, self).__init__(
            file_path, alternative_names, mime_type, firmware
        )

        self.file_info = magic_wrapper(file_path, mime=False)
        if not self.file_info:
            raise ValueError

        assert "ELF" in self.file_info

        if "ELF 32-bit" in self.file_info:
            self.address_size = 32
        elif "ELF 64-bit" in self.file_info:
            self.address_size = 64
        else:
            raise ValueError

        if "LSB" in self.file_info:
            self.endianess = Endianess.LSB
        else:
            self.endianess = Endianess.MSB

        self.stripped = "not stripped" not in self.file_info


class FileSystem:
    """FileSystem abstraction

    A FileSystem object is an abstraction of the underlying file system.
    Its shadow part mimic the filesystem hierarchy and allow to have a "read-only" FS.

    Args:
        base_path: Path towards the file system
        shadow: Optional. Path towards the shadow-directory. If not set, it will use a
                sha-1 derivative frpm the base path
        name: Optional. Name of the file-system

    Attributes:
        base_path: Path towards the file system
        name: Name of the FS
    """

    def __init__(
        self,
        base_path: pathlib.Path,
        shadow: Optional[pathlib.Path] = None,
        name: Optional[str] = None,
    ):
        """Constructor"""
        self.base_path: pathlib.Path = base_path
        self._mimes: collections.defaultdict = collections.defaultdict(list)
        self._links: collections.defaultdict = collections.defaultdict(list)

        self._shadow: Optional[pathlib.Path] = None
        if shadow is not None:
            shadow.mkdir(exist_ok=True)
            self._shadow = shadow

        if name is not None:
            self.name = name
        else:
            self.name = self.base_path.stem

    @property
    def shadow(self) -> pathlib.Path:
        """Shadow FS"""
        if self._shadow is None:
            self._shadow = Settings.SHADOW / sha_1(self.base_path)
            self._shadow.mkdir(exist_ok=True)

        return self._shadow

    @property
    def mimes_types(self) -> Dict[str, List[pathlib.Path]]:
        """Mimes types found in the FS

        This result is cached using a pickle-file stored in the shadow-fs.
        To increase performances, the file command is run in multiple processes.
        """
        if not self._mimes:

            try:
                with open(self.shadow / MIME_TYPE_FILES, "rb") as file:
                    self._mimes = pickle.load(file)

                with open(self.shadow / LINK_FILE, "rb") as file:
                    self._links = pickle.load(file)

                    return self._mimes
            except (FileNotFoundError, pickle.PickleError):
                pass

            with multiprocessing.Pool(processes=Settings.PROCESSES) as pool:
                mimes = pool.map(
                    magic_wrapper_packed,
                    (
                        (path, True)
                        for path in self.base_path.rglob("*")
                        if path.is_file()
                    ),
                )

            for path, mime_type in mimes:
                self._mimes[mime_type].append(path)

            # Resolve symlinks?
            for link in self._mimes.get(SYMLINKS, []):
                self._links[link.resolve()].append(link)

            try:
                with open(self.shadow / MIME_TYPE_FILES, "wb") as file:
                    pickle.dump(self._mimes, file)

                with open(self.shadow / LINK_FILE, "wb") as file:
                    pickle.dump(self._links, file)

            except pickle.PickleError:
                pass

        return self._mimes

    def elf_files(
        self, with_special: bool = True
    ) -> Generator[ExecutableFile, None, None]:
        """Accessor for all elf-files found in the FS

        Args:
            with_special: Also get weird elf files such OAT and ODEX

        Yields:
            ExecutableFile
        """
        types = ELF_TYPES
        if with_special is True:
            types.extend([FileType.OAT.value, FileType.ODEX.value])

        for mime_type in types:
            for file in self.mimes_types[mime_type]:
                alternative_names = [link.name for link in self._links.get(file, [])]
                executable_file = ExecutableFile(
                    file_path=file,
                    alternative_names=alternative_names,
                    mime_type=mime_type,
                    firmware=self,
                )

                yield executable_file

    def translate_path(self, real_path: pathlib.Path) -> pathlib.Path:
        """Translate a path from the real one into the shadow fs.

        The transformation keeps the arborescence of the initial FS only replacing the
        root tree. It is also pure (x will always yield to the same y).

        Args:
            real_path: Path to be transformed

        Returns:
            A path which is a child of the shadow root.
        """
        relative = real_path.relative_to(self.base_path)
        shadow_path = self.shadow / relative

        if real_path.is_file():
            shadow_path.parent.mkdir(exist_ok=True, parents=True)
        else:
            shadow_path.mkdir(exist_ok=True, parents=True)

        return shadow_path

    @functools.lru_cache(maxsize=128)
    def file_in_shadow(
        self, original_path: pathlib.Path, extension: Optional[str] = None
    ) -> pathlib.Path:
        """Create in the shadow directory a pathname similar to the original one.
        If the extension is set /path/to/libfoo.so is translated to /path/to/libfoo.so.EXT

        Args:
            original_path: Original path (not in the shadow)
            extension: Optional. Will append the new extension to the path.

        Returns:
            A path object inside the shadow FS.
        """
        shadow_path = self.translate_path(original_path)
        if extension:
            shadow_path = shadow_path.parent / f"{shadow_path.name}{extension}"

        return shadow_path

    def find(
        self, name: str, exact: bool = True, with_extension: bool = True
    ) -> List[File]:
        """Find a file in the File System by name

        Args:
            name: Name of the file
            exact: Strict match or may be a substring
            with_extension: Use the extensions

        TODO(dm):
            This method does not work well, it has to be improved and tested

        Returns:
            A `File` if found

        Raises:
            ValueError if not file has been found
        """
        pattern = name
        if not exact:
            pattern = "*" + name
        if not with_extension:
            pattern += "*"

        candidates = fnmatch.filter(
            (
                str(file)
                for file in itertools.chain.from_iterable(self.mimes_types.values())
            ),
            pattern,
        )

        if not candidates:
            raise ValueError(f"File with name {name} not found")

        files: List[File] = []
        for file_path in candidates:
            path = pathlib.Path(file_path)
            files.append(
                File(
                    file_path=path,
                    alternative_names=[link.name for link in self._links.get(path, [])],
                    firmware=self,
                )
            )

        return files
