from __future__ import annotations

from abc import ABCMeta, abstractmethod
import logging
from os import PathLike
import pathlib
from typing import List, Any


import qsig
import qsig.detector
import firmextractor


class Detector(metaclass=ABCMeta):
    """
    A detector is responsible to check if a signature matches a (set of) candidates.

    To be a detector, one must implement at least 2 methods :
        - accept
        - match

    """

    """The signature attached to this detector"""
    signature: qsig.sig.Signature

    """Logger for detector"""
    logger: logging.Logger = logging.getLogger(__name__)

    @abstractmethod
    def accept(self, firmware_file: firmextractor.fs.ExecutableFile) -> bool:
        """
        Check if a firmware_file is accepted by the detector.

        Args:
            firmware_file: Candidate to check

        Returns:
            Boolean for success
        """
        raise NotImplementedError()

    @abstractmethod
    def match(self, firmware_file: firmextractor.fs.ExecutableFile) -> bool:
        """Perform a matching between the firmware file and the signature attached to
        the detector

        Args:
            firmware_file: Candidate to check

        Returns:
            Boolean for success
        """
        raise NotImplementedError()

    @abstractmethod
    def __str__(self) -> str:
        """String representation of the detector"""
        raise NotImplementedError()


def init_detectors(
    signatures_path: PathLike,
    program_loader: qsig.ProgramLoader,
    **kwargs: Any,
) -> List[qsig.detector.CVEDetector]:
    """Initialize the detectors

    For each signature, creates a detector and prepare it.
    Note that the program loader is shared between all the detectors to avoid memory
    exhaustion.

    Args:
        signatures_path: Path towards signatures
        program_loader: A ProgramLoader instance

    Returns:
        A list of detectors initialized for each signature
    """

    signatures_path = pathlib.Path(signatures_path)
    if signatures_path.is_dir():
        signatures = signatures_path.rglob("*")
    else:
        signatures = [signatures_path]

    detectors: List[qsig.detector.CVEDetector] = []
    for signature_file in signatures:
        if not signature_file.is_file() or signature_file.suffix != ".sig":
            continue

        sig = qsig.sig.CVESignature()
        try:
            sig.load(signature_file)
        except qsig.sig.SignatureException:
            Detector.logger.error("Failed to load signature in %s", signature_file.name)
            continue

        detectors.append(qsig.detector.CVEDetector(sig, program_loader, **kwargs))

    return detectors
