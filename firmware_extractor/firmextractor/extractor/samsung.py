"""

"""
import logging
import pathlib
import zipfile
from typing import List

import sh

import firmextractor.cmd.simg2img


class SamsungExtractorError(Exception):
    pass


class SamsungExtractor:

    def __init__(self, archive_path: pathlib.Path, force: bool = False):

        self.logger: logging.Logger = logging.getLogger(__name__)

        self.image_path: pathlib.Path = archive_path
        self.image_directory = self.image_path.parent / "image"

        if not self.image_directory.is_dir() or force:
            self.logger.info("Start to extract archive %s", archive_path.stem)
            self._extract_image()

    def _extract_image(self):

        working_directory: pathlib.Path = self.image_path.parent

        # Step 1: Extract the zip
        with zipfile.ZipFile(self.image_path) as archive:
            archive.extractall(path=working_directory)

        children = [f for f in working_directory.glob("*.tar.md5")]
        assert len(children) > 1, "Missing children here"

        # Step 2: tar xf the children
        for child in children:
            try:
                sh.tar("xf", f"{child}", _cwd=working_directory)
            except sh.ErrorReturnCode:
                self.logger.error("Unable to tar xf the image")
                continue

        lz4_files = [f for f in working_directory.glob("*.lz4")]
        assert len(lz4_files) > 1, "Missing lz4 files"

        for lz4_file in lz4_files:
            try:
                sh.lz4("-d", f"{lz4_file}", _cwd=working_directory)
            except sh.ErrorReturnCode:
                self.logger.error(f"Unable to lz4 -d {lz4_file.stem}")
                continue

        sim2img = firmextractor.cmd.simg2img.Simg2img()

        sparse_images = [f for f in working_directory.rglob("*.img")]
        assert len(sparse_images) > 1, "Missing sparse images"

        for sparse_image in sparse_images:
            try:
                sim2img(sparse_image, sparse_image.with_suffix(".raw"))
            except firmextractor.cmd.simg2img.Simg2imgError:
                self.logger.error(f"Failed to sparse image {sparse_image.stem}")
                continue

        raw_images = [f for f in working_directory.rglob("*.raw")]
        assert len(raw_images) > 1, "Missing raw images"

        self.image_directory.mkdir(parents=True, exist_ok=True)

        seven_zip = firmextractor.cmd.sevenzip.SevenZip()
        out_directories: List[pathlib.Path] = []
        for raw_image in raw_images:
            out_directory = self.image_directory / raw_image.stem

            if not out_directory.is_dir():
                try:
                    seven_zip.extract(
                        raw_image,
                        out_directory,
                        force=False,
                    )
                except firmextractor.cmd.sevenzip.SevenZipError:
                    self.logger.error(f"Failed to raw image {raw_image.stem}")
                    continue

            out_directories.append(out_directory)

        # Some cleaning
        for file in [*children, *lz4_files, *sparse_images, *raw_images]:
            file.unlink()

        return out_directories
