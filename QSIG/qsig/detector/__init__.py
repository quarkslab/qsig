"""
QSIG - Detector
---------------
"""
from qsig.detector.detector import Detector, init_detectors
from qsig.detector.vulnerability import CVEDetector
from qsig.detector.file import FileDetector
from qsig.detector.function import ChunkDetector

__all__ = [
    # From detector.py
    "Detector",
    "init_detectors",
    # From vulnerability.py
    "CVEDetector",
    # From file.py
    "FileDetector",
    # From function.py
    "ChunkDetector",
]
