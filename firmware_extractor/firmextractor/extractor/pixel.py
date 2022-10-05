"""
Deal with Pixel-like archives.

Those archive are downloaded from Google website:
    https://developers.google.com/android/images
"""


import logging
import pathlib
import zipfile
from typing import List

import magic

import firmextractor.cmd


class PixelExtractorError(Exception):
    pass


class PixelExtractor:
    """Extract a Pixel image and convert sparses images to regular images.

    This will create a list of image in the `PixelExtarctor.DIRECTORY_NAME`.

    Input sould be something like :
        - blueline-pq1a.190105.004-factory-49adfd52.zip

    Args:
        archive_path: Where to find the input
    """

    DIRECTORY_NAME: str = "image"
    """Name of the output directory"""

    MIME_INFO: str = "Android sparse image"
    """Pattern to recognize sparse images"""

    def __init__(self, archive_path: pathlib.Path):
        """Constructor"""
        self.logger = logging.getLogger(__name__)

        self.image_path = archive_path
        self.image_directory = self.image_path.parent / PixelExtractor.DIRECTORY_NAME

        if not self.image_directory.is_dir():
            self.logger.info("Start to extract the archive")
            with zipfile.ZipFile(archive_path) as archive:
                archive.extractall(path=archive_path.parent)

            image_arch: pathlib.Path
            for item in self.image_path.parent.rglob("*.zip"):
                if item.name.startswith("image-"):
                    self.logger.debug("Found a suitable image %s", item.name)
                    image_arch = item
                    break
            else:
                raise PixelExtractorError("Unable to find image directory")

            self.logger.info("Start to extract the image")
            with zipfile.ZipFile(image_arch) as archive:
                archive.extractall(path=self.image_directory)
            self.logger.debug("Finished to extract the images")

        self.logger.debug("Separate image from raw images")
        self.regular_images: List[pathlib.Path] = []
        sparses_images: List[pathlib.Path] = []
        for image in self.image_directory.rglob("*.img"):
            if PixelExtractor.MIME_INFO in magic.from_file(str(image)):
                sparses_images.append(image)
            else:
                self.regular_images.append(image)

        self._raw_images: List[pathlib.Path] = []

        self.logger.info(
            "Found %d images and %d raw images in %s",
            len(self.regular_images),
            len(sparses_images),
            archive_path.stem,
        )

        self.logger.debug("Start to convert raw images")
        simg2img = firmextractor.cmd.simg2img.Simg2img()
        for sparse_image in sparses_images:
            raw_image = sparse_image.with_suffix(".raw")
            if not raw_image.is_file():
                try:
                    self.logger.debug("Convert %s", raw_image.stem)
                    simg2img(sparse_image, raw_image)
                    self.logger.debug("Conversion finished")
                except firmextractor.cmd.simg2img.Simg2imgError:
                    self.logger.error("Failed to extract the image %s", raw_image.stem)

            self._raw_images.append(raw_image)

    @property
    def images(self) -> List[pathlib.Path]:
        """List of images found in the archive"""
        return self.regular_images + self.raw_images

    @property
    def raw_images(self) -> List[pathlib.Path]:
        """List of raw images found in the archive"""
        return self._raw_images
