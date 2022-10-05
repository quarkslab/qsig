import abc
import collections
import enum
import json
import logging
import pathlib
from os import PathLike

import magic
import sh
from typing import List, Union, Dict, Tuple, Optional

import qsig

FilesToFunc = Dict[str, List[str]]
CVEFunctions = Dict[str, FilesToFunc]


class Architecture(enum.Enum):
    """Architectures"""

    arm = "arm"
    arm64 = "arm64"
    x86 = "x86"
    x64 = "x64"


def file_properties(file: PathLike) -> Tuple[bool, bool]:
    """Check if the file is stripped and for 64-bit arch.

    Args:
        file: A path towards the file to check

    Returns:
        A tuple of (is_stripped?, is_64b?)
    """
    output = magic.from_file(str(file))
    return "not stripped" not in output, "64-bit" in output


def get_files(
    files_directory: pathlib.Path,
    arch: str,
    build_type: str,
    stripped: bool,
    forbidden_extensions: List[str],
    forbidden_names: List[str],
) -> List[pathlib.Path]:
    """

    Args:
        files_directory: Directory to consider
        arch: Which architecture (e.g. arm/arm64)
        build_type: Type of build (either fix/vuln)
        stripped: Should we get stripped binaries
        forbidden_extensions: List of extensions to *not* consider
        forbidden_names: List of names *to* remove

    Returns:
        A list of file path matching the criteria
    """
    files: List[pathlib.Path] = []
    for item in files_directory.glob(f"{arch}/{build_type}/*"):
        if (
            item.is_file()
            and item.suffix not in forbidden_extensions
            and not any(name in item.stem for name in forbidden_names)
            and file_properties(item) == (stripped, arch == "*" or "64" in arch)
        ):
            files.append(item)

    return files


class Vulnerability:
    """Base class for vulnerabilities

    A vulnerabilty to be signable by QSig must abide by this class.
    """

    name: str
    """Name of the vulnerability (e.g. a CVE, a binary name)"""

    path: pathlib.Path
    """Path to the vulnerability files"""

    @abc.abstractmethod
    def functions_by_file(self, file_name: str) -> List[str]:
        """Functions affected by the vulnerability for a file
        Args:
            file_name: Name of the file

        Returns:
            A list of functions affected inside a file.
        """
        pass

    @abc.abstractmethod
    def functions(self) -> List[str]:
        """Functions affected by the vulnerability

        Returns:
            A list of functions name
        """
        pass

    @abc.abstractmethod
    def get_tuples(
        self, arch: Union[str, Architecture] = "*", stripped: bool = False
    ) -> List[Tuple[pathlib.Path, pathlib.Path]]:
        """Returns couples of (fix, vuln) binaries

        Args:
            arch: Architecture of those tuples
            stripped: Should the binaries be stripped

        Returns:
            A list of binaries couples
        """
        pass

    @property
    @abc.abstractmethod
    def valid(self) -> bool:
        """Is the current CVE valid?

        Returns:
            Boolean for success
        """
        pass

    def __repr__(self) -> str:
        """Representation of the vulnerability"""
        return f"<Vulnerability {self.name}>"


class CompiledCve(Vulnerability):
    """Compiled CVE class

    Args:
        files_directory (Path): A path object towards the result directory of this CVE

    Attributes:
        cve_id: The id of the CVE (e.g CVE-2019-1234)
        cve_commit: Id of the "fix" commit of the CVE
        name: A tuple (cve_id, cve_commit) : the unique identifier for this CVE
    """

    logger = logging.getLogger(__file__)
    """A logger instance"""

    def __init__(self, files_directory: Union[str, pathlib.Path]):
        """Constructor"""
        files_dir = pathlib.Path(files_directory)
        if files_dir.suffix in (".tgz", ".zst"):
            self.logger.debug("Remove suffix from archive name")
            files_dir = files_dir.with_suffix("")

        self._files_dir: pathlib.Path = files_dir
        self.cve_id: str = self._files_dir.parent.name
        self.cve_commit: str = self._files_dir.name

        self.path = self._files_dir
        self.name: str = f"{self.cve_id}"

        self._valid: Union[None, bool] = None

    def _open_archive(self, directory_path: pathlib.Path) -> None:
        """Open an archive if the directory was not already decompressed

        Args:
            directory_path (Path): The directory where the archive is present

        Raises:
            ArchiveException
        """

        for suffix in [".tgz", ".zst"]:
            tarfile_path = directory_path.with_suffix(suffix)
            if tarfile_path.is_file():
                break
        else:
            raise qsig.exc.CveException("Missing archive")

        # TODO(dm) Use ZSTD to compress archives to reduce disk usage
        try:
            sh.tar(
                "--use-compress-program=pigz",
                "-xf",
                str(tarfile_path),
                _cwd=tarfile_path.parent,
            )
        except sh.ErrorReturnCode:
            raise qsig.exc.CveException("Unable to extract the archive")

    def compress(self) -> None:
        """Compress the current archive.

        This uses tar program with pigz.
        The tarfile module of Python is way too slow to do this...
        """
        tarfile_path = self._files_dir.with_suffix(".tgz")
        if tarfile_path.is_file():
            self.logger.warning("Archive already exists, abort.")
            return

        try:
            sh.tar(
                "--use-compress-program=pigz",
                "-cf",
                str(tarfile_path),
                "--exclude=*i64",
                "--exclude=*.quokka",
                str(self._files_dir.relative_to(self._files_dir.parent)),
                _cwd=self._files_dir.parent,
            )
        except sh.ErrorReturnCode:
            self.logger.error("Unable to create the archive %s", self._files_dir.name)

    @property
    def files_dir(self) -> pathlib.Path:
        """Retrieve the files directory

        Returns:
            Path object towards the directory
        """
        if not self._files_dir.is_dir():
            self._open_archive(self._files_dir)

        return self._files_dir

    @property
    def valid(self) -> bool:
        """Check if a compiled CVE is valid.

        For a CVE to be a valid, it must have:
            - at least 4 arch folders with 2 subfolders each
            - 8 files.json files
            - 1 functions.json file
            - at least 1 binary

        Returns:
            True if valid, False otherwise

        """
        if self._valid is None:
            self._valid = False
            tarfile_path = self._files_dir.with_suffix(".tgz")
            files: List[pathlib.Path]
            if self._files_dir.is_dir():
                files = list(
                    file.relative_to(self._files_dir.parent)
                    for file in self._files_dir.rglob("*")
                )
            elif tarfile_path.is_file():
                try:
                    result = sh.tar("tf", tarfile_path.as_posix())
                    files = [
                        pathlib.Path(file)
                        for file in result.stdout.decode().split("\n")
                    ]
                except sh.ErrorReturnCode:
                    self.logger.error("Unable to list files in archive")
                    raise qsig.exc.CveException()
            else:
                raise qsig.exc.CveException("Missing CVE")

            counters = collections.Counter()

            if len(files) > 10:
                for file in files:
                    parts = file.parts
                    if len(parts) > 3:
                        counters["/".join(parts[1:3])] += 1

            try:
                if min(counters.values()) >= 2:
                    self._valid = True
            except ValueError:  # Counter is empty
                pass

        return self._valid

    def get_tuples(
        self,
        arch: Union[str, Architecture] = "*",
        stripped: bool = False,
        debug_files: bool = False,
    ) -> List[Tuple[pathlib.Path, pathlib.Path]]:
        """Retrieve the list of files couples from the CVE with optional filters options
        Args:
            arch: An arch name
            stripped: Return striped files
            debug_files: Also file ending with '.debug'

        Returns:
            List of couples (fix, vuln) path towards files

        """
        if isinstance(arch, Architecture):
            arch = arch.value

        forbidden_extensions: List[str] = []
        if debug_files is False:
            forbidden_extensions.extend([".debug", ".xz"])

        forbidden_names: List[str] = []
        if debug_files is False:
            forbidden_names.extend(["test"])

        vuln_files = get_files(
            self.files_dir,
            arch,
            "vuln",
            stripped,
            forbidden_extensions,
            forbidden_names,
        )
        fix_files = get_files(
            self.files_dir, arch, "fix", stripped, forbidden_extensions, forbidden_names
        )

        names = set(file.name[65:] for file in set(vuln_files).union(fix_files))
        results: List[Tuple[pathlib.Path, pathlib.Path]] = []
        for name in names:
            fix_candidates = [path for path in fix_files if path.name[65:] == name]
            vuln_candidates = [path for path in vuln_files if path.name[65:] == name]

            if fix_candidates and vuln_candidates:
                results.append((fix_candidates.pop(), vuln_candidates.pop()))

        return results

    def functions_by_file(self, file_name: str) -> Optional[List[str]]:
        """Returns the functions affected by a vulnerability inside `file_name`.

        Note that this methods needs to have "BINDIFF" results

        Args:
            file_name: Name of the binary file

        Raises:
            ValueError if BinDiff results are not available

        Returns:
            A list of modified functions inside the file
        """

        function_file = self.files_dir / "functions.json"
        try:
            functions_data: CVEFunctions = json.load(open(function_file.as_posix()))
        except (json.JSONDecodeError, FileNotFoundError):
            raise qsig.exc.CveException("Unable to load the CVE")

        bindiff_functions: Dict[str, List[str]] = functions_data.get("bindiff", {})
        if not bindiff_functions:
            raise ValueError("BinDiff results not available")

        return bindiff_functions.get(file_name)

    def functions(self) -> List[str]:
        """Retrieve the affected functions for a CVE

        Returns:
            A list of function names flatten
        """

        function_file = self.files_dir / "functions.json"
        try:
            functions_data: CVEFunctions = json.load(open(function_file.as_posix()))
        except (json.JSONDecodeError, FileNotFoundError):
            raise qsig.exc.CveException("Unable to load the CVE")

        functions: List[str] = []

        # Return functions from the bindiff diffing if they are available
        bindiff_functions: Dict[str, List[str]] = functions_data.get("bindiff", {})
        if bindiff_functions:
            for file_name, file_functions in bindiff_functions.items():
                functions.extend(file_functions)

            return list(set(functions))

        # Old way of storing BinDiff results
        old_bindiff: List[str] = functions_data.get("fix", {}).get("bindiff", [])
        if old_bindiff:
            self.logger.warning("Old way of storing functions for cve %s", self.cve_id)
            return old_bindiff

        # Fallback to source computed functions from diff
        for key in ["vuln", "fix"]:
            for k, v in functions_data.get(key, {}).items():
                if k != "bindiff":
                    functions.extend(v)

        return list(set(functions))


class CGCVuln(Vulnerability):
    """A CGC Vulnerability represents binaries used for the CGC."""

    def __init__(self, vuln_path: pathlib.Path):
        """Constructor

        Args:
            vuln_path: Path towards the vulnerabilities
        """
        self.path: pathlib.Path = vuln_path
        self.name: str = vuln_path.name

    @property
    def valid(self) -> bool:
        """Is the CGC vuln valid ?"""
        return (self.path / "functions.json").is_file()

    def functions_by_file(self, file_name: str) -> Optional[List[str]]:
        """Functions with files"""
        with open(self.path / "functions.json", "r") as json_file:
            data = json.load(json_file)

        bindiff_functions: Dict[str, List[str]] = data.get("bindiff", {})
        if not bindiff_functions:
            raise ValueError("BinDiff results not available")

        if file_name.endswith("_patched"):
            file_name = file_name[:file_name.index("_patched")]

        return bindiff_functions.get(file_name)

    def functions(self) -> List[str]:
        """List functions affected by this CGC Vulnerability"""
        with open(self.path / "functions.json", "r") as json_file:
            data = json.load(json_file)

        functions: List[str] = []
        for key in ["vuln", "fix"]:
            for v in data.get(key, {}).values():
                functions.extend(v)

        return functions

    def get_tuples(
        self, arch: Union[str, Architecture] = "*", stripped: bool = False
    ) -> List[Tuple[pathlib.Path, pathlib.Path]]:
        """Get couples of vulnerable and fixed binaries

        Args:
            arch: Architecture
            stripped: Should the binaries be stripped?

        Returns:
             Couple(s) matching the criteria
        """

        def strip(stripped_path: pathlib.Path) -> None:
            """Strip a binary"""
            sh.strip(
                "-o",
                str(stripped_path),
                "-s",
                str(stripped_path.parent.parent / stripped_path.name),
            )

        if isinstance(arch, Architecture):
            arch = arch.value
        elif arch == "*":
            arch = Architecture.x64.value

        if arch not in [Architecture.x64.value, Architecture.x86.value]:
            raise qsig.exc.CveException(f"CGC Vuln support only X86/X64 (not {arch})")

        path = self.path / arch

        tuples: List[Tuple[pathlib.Path, pathlib.Path]] = []
        for i in range(20):
            if i == 0:  # Special case
                vuln_file = path / self.name
            else:
                vuln_file = path / f"{self.name}_{i}"

            fix_file = vuln_file.parent / f"{vuln_file.name}_patched"

            if not vuln_file.is_file():  # We did not find any more files
                break

            tuples.append((fix_file, vuln_file))

        if stripped:
            new_tuples: List[Tuple[pathlib.Path, pathlib.Path]] = []
            path /= "stripped"
            for fix_file, vuln_file in tuples:
                new_fix = path / fix_file.name
                new_vuln = path / vuln_file.name

                if not new_fix.is_file():
                    strip(new_fix)

                if not new_vuln.is_file():
                    strip(new_vuln)

                new_tuples.append((new_fix, new_vuln))
            return new_tuples

        return tuples
