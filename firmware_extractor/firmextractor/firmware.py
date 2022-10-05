"""Firmware class"""
import logging
from pathlib import Path
from typing import Generator

import firmextractor.fs


class Firmware:
    """Base class for firmwares

    Attributes:
        logger: Logger instance
        archive: Path towards the firmware
    """
    def __init__(self, firmware_path: Path):
        """Constructor"""
        self.logger = logging.getLogger(__name__)
        self.archive: Path = firmware_path

    def file_systems(self) -> Generator[None, firmextractor.fs.FileSystem, None]:
        """Returns a list of file system in the system"""
        ...

    def extract(self):
        """Extract a firmware in place"""
        ...

    def mount(self):
        """Mount a firmware"""
        ...

    def decompress(self, image_path: Path) -> Path:
        """Decompress a firmware"""
        ...
