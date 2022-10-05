import abc
import functools
import shutil
from pathlib import Path
from typing import Union, Optional


@functools.lru_cache(maxsize=8)
def find_executable(cmd: str) -> Optional[Path]:
    """Search for an executable in PATH"""
    return shutil.which(cmd)


class CommandError(Exception):
    pass


class Command:
    """Command wrapper

    This wraps a command utility on the file system.

    Args:
        command_path: Optional. Path to the command
    """

    name: str
    """Name of the command"""

    command: str
    """Executable command (can be different from the name)"""

    def __init__(self, command_path: Optional[Union[str, Path]] = None) -> None:
        """Constructor"""
        if command_path is None:
            command_path = find_executable(self.name)
            if command_path is None:
                raise CommandError(f"Unable to find binary {self.name}")

        self.command: str = str(command_path)

    @abc.abstractmethod
    def run(self, *args, **kwargs):
        """Run a command"""
        ...
