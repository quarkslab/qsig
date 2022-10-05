import os
import pathlib
import subprocess
import time
from abc import abstractmethod
from typing import Optional, Deque, List
import collections
import logging
from os import PathLike

import quokka

import qsig.settings


logger: logging.Logger = logging.getLogger(__name__)


def quokka_timed(
    exec_path: PathLike,
    output_file: Optional[PathLike] = None,
    database_file: Optional[PathLike] = None,
    timeout: Optional[int] = None,
):

    if timeout is None:
        timeout = qsig.settings.Settings.EXPORT_TIMEOUT

    exec_path = pathlib.Path(exec_path)
    if not exec_path.is_file():
        raise FileNotFoundError("Missing exec file")

    if output_file is None:
        output_file = exec_path.parent / f"{exec_path.name}.quokka"
    else:
        output_file = pathlib.Path(output_file)

    if output_file.is_file():
        return quokka.Program(output_file, exec_path)

    exec_file = exec_path
    if database_file is None:
        database_file = exec_file.parent / f"{exec_file.name}.i64"
    else:
        database_file = pathlib.Path(database_file)

    # IDA OPTIONS
    ida_path = os.environ.get("IDA_PATH", "idat64")
    ida_env = {
        "TVHEADLESS": "1",
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
        "TERM": "xterm",  # problem with libcurses
        "IDALOG": "/tmp/ida.log",
    }
    output_level = subprocess.PIPE

    # First generate database
    if not database_file.is_file():

        logger.info(
            "",
            extra={
                "bench": True,
                "type": "timer",
                "action": "disassembly",
                "event": "start",
                "value": time.time(),
                "file": f"{exec_file!s}",
            },
        )
        ida_cmd: List[str] = [
            ida_path,
            "-B",
            f"-o{database_file.with_suffix('')!s}",
            f"{exec_file!s}",
        ]

        try:
            subprocess.run(
                ida_cmd,
                stdout=output_level,
                stderr=output_level,
                env=ida_env,
                timeout=timeout,
            )
        except subprocess.CalledProcessError:
            return None

        logger.info(
            "",
            extra={
                "bench": True,
                "type": "timer",
                "action": "disassembly",
                "event": "end",
                "value": time.time(),
                "file": f"{exec_file!s}",
            },
        )

    if not database_file.is_file():
        return None

    logger.info(
        "",
        extra={
            "bench": True,
            "type": "timer",
            "action": "export",
            "event": "start",
            "value": time.time(),
            "file": f"{exec_file!s}",
        },
    )

    # Now, do the export
    ida_cmd = [
        ida_path,
        "-OquokkaAuto:true",
        f"-OquokkaFile:{output_file}",
        "-A",
        f"{database_file!s}",
    ]
    try:
        subprocess.run(
            ida_cmd,
            stderr=output_level,
            stdout=output_level,
            env=ida_env,
            timeout=timeout,
        )

    except subprocess.CalledProcessError:
        return None

    logger.info(
        "",
        extra={
            "bench": True,
            "type": "timer",
            "action": "export",
            "event": "end",
            "value": time.time(),
            "file": f"{exec_file!s}",
        },
    )

    if not output_file.is_file():
        return None

    return quokka.Program(output_file, exec_path)


class ProgramLoader:
    @abstractmethod
    def get_program(
        self, binary_file: PathLike, export_file: PathLike
    ) -> quokka.Program:
        pass

    @abstractmethod
    def from_binary(self, binary_file: PathLike, *args, **kwargs) -> quokka.Program:
        pass

    @property
    @abstractmethod
    def has_program(self) -> bool:
        pass

    @staticmethod
    def _load_program(
        binary_file: PathLike, export_file: PathLike
    ) -> quokka.Program:
        return quokka.Program(export_file, binary_file)

    @staticmethod
    def _load_from_binary(binary_file: PathLike, *args, **kwargs) -> quokka.Program:

        if "timeout" not in kwargs:
            kwargs["timeout"] = qsig.Settings.EXPORT_TIMEOUT

        if logger.isEnabledFor(qsig.Verbosity.BENCHMARK):
            program = quokka_timed(binary_file, *args, **kwargs)
        else:
            program = quokka.Program.from_binary(binary_file, *args, timeout=None)

        return program


class SingleProgramLoader(ProgramLoader):
    def __init__(self) -> None:
        super().__init__()
        self._program: Optional[quokka.Program] = None

    def get_program(
        self, binary_file: PathLike, export_file: PathLike
    ) -> quokka.Program:
        if self._program is None or self._program.export_file != pathlib.Path(
            export_file
        ):
            self._program = self._load_program(binary_file, export_file)

        return self._program

    def from_binary(self, binary_file: PathLike, *args, **kwargs) -> quokka.Program:
        if self._program is None or self._program.executable.exec_file != pathlib.Path(
            binary_file
        ):
            self._program = self._load_from_binary(binary_file, *args, **kwargs)

        return self._program

    @property
    def has_program(self) -> bool:
        return self._program is not None


class MultipleProgramLoader(ProgramLoader):
    def __init__(self, bag_count: Optional[int] = 5):
        super().__init__()
        self.programs: Deque[quokka.Program] = collections.deque(
            [], maxlen=bag_count
        )

    def get_program(
        self, binary_file: PathLike, export_file: PathLike
    ) -> quokka.Program:
        for program in self.programs:
            if program.export_file == export_file:
                return program

        program = self._load_program(binary_file, export_file)
        self.programs.append(program)
        return program

    def from_binary(self, binary_file: PathLike, *args, **kwargs) -> quokka.Program:
        for program in self.programs:
            if program.executable.exec_file == pathlib.Path(binary_file):
                return program

        program = self._load_from_binary(binary_file, *args, **kwargs)
        self.programs.append(program)
        return program

    def has_program(self) -> bool:
        return len(self.programs) > 0
