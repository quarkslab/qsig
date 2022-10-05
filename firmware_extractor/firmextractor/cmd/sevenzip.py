"""
7Zip wrapper.
"""
import os
import pathlib
import logging
import subprocess
from typing import Optional, List

from firmextractor.cmd.command import Command, CommandError


logger: logging.Logger = logging.getLogger(__name__)
"""7Zip logger"""


class SevenZipError(CommandError):
    """Error handler for SevenZip"""

    pass


class SevenZip(Command):
    """Handler for 7z command"""

    name: str = "7z"
    """Name of the command line utility"""

    def run(
        self, subcommand: Optional[str] = None, args: List[str] = None
    ) -> subprocess.CompletedProcess:
        """Run the command and wrap results

        Args:
            subcommand: An optional subcommand (such as x)
            args: List of arguments

        Raises:
            SevenZipError when the command fails to run

        Returns:
            Subprocess CompletedProcess
        """

        final_command: List[str] = [self.command]

        if subcommand is not None:
            final_command.append(subcommand)

        if args is not None:
            final_command.extend(args)

        try:
            result = subprocess.run(
                final_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            raise SevenZipError(f"Run: Unable to run the command {final_command}")

        return result

    def extract(
        self,
        archive_path: pathlib.Path,
        extract_dir: Optional[pathlib.Path] = None,
        force: bool = False,
    ) -> pathlib.Path:
        """Extract the archive at `archive_path` to `extract_dir` if specified or the
        local directory.

        Args:
            archive_path: Path of the file to extract
            extract_dir: Where to extract
            force: Should we still try to extract if the extract dir exists ?

        Raises:
            SevenZipError if the extraction fails

        TODO(dm):
            check if this work when extract dir is not specified

        Returns:
            Path towards the extracted directory
        """

        # FIX: Assume -y to prevent the tool to stay in standby
        args: List[str] = ["-y", "-bb0", "-bd", f"-mmt{os.cpu_count()*2}"]

        if extract_dir is not None:
            if extract_dir.is_dir() and not force:
                logger.debug("Skip extraction because target directory exist")
                return extract_dir

            args.append(f"-o{extract_dir}")
            args.append("--")

        args.append(str(archive_path))

        result = self.run(subcommand="x", args=args)

        if result.returncode != 0:
            raise SevenZipError("Extract: Failed to extract")

        if extract_dir:
            return extract_dir
        else:
            return pathlib.Path(".").absolute()
