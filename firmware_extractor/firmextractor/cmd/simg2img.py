"""
Simg2img wrapper

This tool is used to convert sparse Android image to regular raw images.
"""

import pathlib
import subprocess
from typing import List

from firmextractor.cmd.command import Command, CommandError


class Simg2imgError(CommandError):
    pass


class Simg2img(Command):
    name: str = "simg2img"

    def run(self, args: List[str] = None) -> subprocess.CompletedProcess:
        final_command: List[str] = [self.command]
        if args is not None:
            final_command.extend(args)

        try:
            result = subprocess.run(
                final_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            raise Simg2imgError(f"Run: Unable to run the command {final_command}")

        return result

    def extract(
        self, source_file: pathlib.Path, destination_file: pathlib.Path
    ) -> None:
        result = self.run([str(source_file), str(destination_file)])
        if result.returncode != 0:
            raise Simg2imgError(f"Extract: Unable to extract image {source_file}")

    def __call__(
        self, source_file: pathlib.Path, destination_file: pathlib.Path
    ) -> None:
        self.extract(source_file, destination_file)
