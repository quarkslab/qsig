import getpass
import pathlib
import re
import subprocess
from typing import Dict, List

from firmextractor.cmd.command import Command, CommandError


class UdisksctlError(CommandError):
    pass


class Udisksctl(Command):
    name: str = "udisksctl"
    username: str

    def __init__(self) -> None:
        super(Udisksctl, self).__init__()
        self.loops: Dict[int, str] = {}
        self.username = getpass.getuser()

    def run(
        self, subcommand: str = None, args: List[str] = None
    ) -> subprocess.CompletedProcess:

        final_cmd = [self.name]
        if subcommand is not None:
            final_cmd.append(subcommand)
            final_cmd.extend(args)

        try:
            r = subprocess.run(
                final_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
            )
        except subprocess.CalledProcessError as error:
            raise UdisksctlError(f"Error while running udiskctl {error}")

        return r

    def loop_setup(self, image_path: pathlib.Path) -> int:
        result = self.run(subcommand="loop-setup", args=["-f", str(image_path)])

        if result.returncode != 0:
            raise UdisksctlError("Loop-Setup: Unable to loop-setup")

        try:
            loop_count = int(
                re.findall(r"/dev/loop([0-9]+)", result.stdout.decode("utf-8"))[0]
            )
        except (IndexError, UnicodeDecodeError):
            raise UdisksctlError("Loop-Setup: Unable to retrieve loop count")

        self.loops[loop_count] = image_path.stem

        return loop_count

    def loop_delete(self, loop_count: int) -> None:

        if loop_count not in self.loops:
            raise UdisksctlError("Loop-Delete: Loop not mounted")

        result = self.run(
            subcommand="loop-delete", args=["-b", f"/dev/loop{loop_count}"]
        )
        if result.returncode != 0:
            raise UdisksctlError(f"Loop-Delete: Unable to delete loop {loop_count}")

        del self.loops[loop_count]

    def mount(self, loop_count: int) -> pathlib.Path:
        if loop_count not in self.loops:
            raise UdisksctlError("Mount: Loop not mounted")

        result = self.run(
            subcommand="mount", args=["-b", f"/dev/loop{loop_count}", "-o", "nosuid"]
        )
        if result.returncode != 0:
            raise UdisksctlError(f"Mount: Unable to mount loop {loop_count}")

        try:
            file_path = re.findall(
                f"(/media/{self.username}/[a-z0-9_]+)", result.stdout.decode("utf-8")
            )[0]
        except (IndexError, UnicodeDecodeError):
            raise UdisksctlError(f"Mount: Unable to retrieve mount point")

        file_path = pathlib.Path(file_path)

        # The naming schem of udiskctl is weird, but we have to obey
        # E.g. (vendor.raw -> /media/USER/vendor, system.raw -> /media/USER/_ )
        # if file_path.name != self.loops[loop_count]:
        #     self.loops[loop_count] = file_path.name

        return file_path

    def unmount(self, loop_count: int) -> None:
        if loop_count not in self.loops:
            raise UdisksctlError("UnMount: Loop not mounted")

        result = self.run(
            subcommand="unmount", args=["-b", f"/dev/loop{loop_count}", "-f"]
        )
        if result.returncode != 0:
            raise UdisksctlError("UnMount: Error while unmounting loop")

    def mount_image(self, image_path: pathlib.Path) -> pathlib.Path:
        loop_count = self.loop_setup(image_path)
        file_path = self.mount(loop_count)

        return file_path

    def unmount_image(self, image_path: pathlib.Path) -> bool:
        for loop_count, element in self.loops.items():
            if element == image_path.stem:
                break
        else:
            raise UdisksctlError("UnMount-Image: Unable to find image to unmount")

        self.unmount(loop_count)
        self.loop_delete(loop_count)

        return True
