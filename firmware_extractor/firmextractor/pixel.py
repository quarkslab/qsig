import logging
import pathlib
from typing import Optional, List, Dict, Generator, Callable, Any

import firmextractor.firmware
import firmextractor.fs
import firmextractor.cmd.sevenzip
import firmextractor.extractor.pixel


logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the module"""


def extractor_loaded(f: Callable[..., Any]) -> Any:
    """Decorator wrapper"""
    def load_extractor(self: Any, *args: Any, **kwargs: Any) -> Any:
        """Check if the extractor has been loaded and if not, load it
        """
        if self.extractor is None:
            self.extract()
        return f(self, *args, **kwargs)

    return load_extractor


class PixelError(Exception):
    """Base error for Pixel"""
    pass


class Pixel(firmextractor.firmware.Firmware):
    """Abstract an archive for a pixel by either mounting it or extracting it.
    """
    def __init__(self, archive_path: pathlib.Path) -> None:
        """Constructor"""
        super(Pixel, self).__init__(archive_path)

        self.extractor: Optional[firmextractor.extractor.pixel.PixelExtractor] = None

        self.udisksctl: Optional[firmextractor.cmd.udisksctl.Udisksctl] = None
        try:
            self.udisksctl = firmextractor.cmd.udisksctl.Udisksctl()
        except firmextractor.cmd.command.CommandError:
            pass

        self.seven_zip: Optional[firmextractor.cmd.sevenzip.SevenZip] = None
        try:
            self.seven_zip = firmextractor.cmd.sevenzip.SevenZip()
        except firmextractor.cmd.command.CommandError:
            pass

        self.mount_points: Dict[str, pathlib.Path] = {}

        self.decompress_directory: Dict[pathlib.Path, pathlib.Path] = {}

    def extract(self) -> None:
        """Extract the Pixel image using the PixelExtractor
        """
        self.logger.debug("Start to extract %s", self.archive.name)
        self.extractor = firmextractor.extractor.pixel.PixelExtractor(self.archive)

    @property  # type: ignore
    @extractor_loaded
    def images(self) -> List[pathlib.Path]:
        """List images found inside the pixel"""
        assert self.extractor is not None
        return self.extractor.images

    @property  # type: ignore
    @extractor_loaded
    def raw_images(self) -> List[pathlib.Path]:
        """List raw images found inside the Pixel"""
        assert self.extractor is not None
        return self.extractor.raw_images

    def mount_all(self) -> None:
        """Mount all raw images found using udisksctl."""

        if self.udisksctl is None:
            logger.error("Unable to mount as udisksctl is not found.")
            return

        for image in self.raw_images:
            if image.stem in self.mount_points:
                continue

            mount_point = self.udisksctl.mount_image(image_path=image)
            self.mount_points[image.stem] = mount_point

    @extractor_loaded
    def mount(self, image_name: str, extension: str = "raw") -> pathlib.Path:
        """Mount an image

        This uses Udisksctl to mount an image without superprivileges.

        Args:
            image_name: Name of the image
            extension: Image's extension

        Raises:
            PixelError if the mount fails

        Returns:
            A Path towards the mounted image
        """
        assert self.extractor is not None

        if self.udisksctl is None:
            logger.error("Unable to mount as udisksctl is not set.")
            raise PixelError("Unable to mount")

        if image_name not in self.mount_points:
            image_path = self.extractor.image_directory / f"{image_name}.{extension}"
            if not image_path.is_file():
                raise PixelError("Unable to find image")

            self.mount_points[image_name] = self.udisksctl.mount_image(
                image_path=image_path
            )

        return self.mount_points[image_name]

    def __del__(self) -> None:
        """Deletion

        If images have been mounted, unmount them.
        """
        if self.extractor is not None and self.udisksctl is not None:
            for image in self.images:
                if image.stem in self.mount_points:
                    self.udisksctl.unmount_image(image)

    def decompress(self, image_path: pathlib.Path) -> pathlib.Path:
        """Uncompress an image

        Args:
            image_path: Path towards the image to uncompress

        Returns:
            Path to the uncompressed directory
        """
        if image_path not in self.decompress_directory:
            out_directory = image_path.parent / image_path.stem
            self.decompress_directory[image_path] = self.seven_zip.extract(
                image_path, out_directory
            )

        return self.decompress_directory[image_path]

    def decompress_all(self) -> None:
        """Decompress all images found in the Pixel"""
        self.logger.info("Start to decompress all images")
        for image in self.raw_images:
            self.logger.debug("Decompress %s", image.stem)
            self.decompress(image)
            self.logger.debug("Finished to decompress %s", image.stem)

    def file_systems(self) -> Generator[firmextractor.fs.FileSystem, None, None]:
        """Find all file systems mounted in the Pixel.

        Yields:
            A FileSystem object
        """
        for name, extract_point in self.decompress_directory.items():
            yield firmextractor.fs.FileSystem(extract_point, name=name.stem)
