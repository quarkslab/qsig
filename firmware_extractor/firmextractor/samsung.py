import pathlib

import firmextractor
import firmextractor.extractor
import firmextractor.extractor.samsung


class Samsung(firmextractor.firmware.Firmware):

    def __init__(self, archive_path: pathlib.Path):
        super(Samsung, self).__init__(archive_path)
        self.extractor = None

    def extract(self):
        self.logger.info(f"Start to extract")
        self.extractor = firmextractor.extractor.samsung.SamsungExtractor(self.archive)

    def file_systems(self):
        for out_dir in (self.archive.parent / "image").glob("*"):
            if out_dir.is_dir():
                yield firmextractor.fs.FileSystem(out_dir, name=out_dir.stem)
