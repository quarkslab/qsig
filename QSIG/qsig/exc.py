class QSigException(Exception):
    """Base class for QSIG Exceptions"""

    pass


class GeneratorException(QSigException):
    pass


class NoFuncException(GeneratorException):
    pass


class DetectorException(QSigException):
    """Base exception class for QSIG"""

    pass


class ArchiveException(QSigException):
    """Exceptions that are thrown by the CVE module"""

    pass


class LogException(QSigException):
    """Logger exceptions"""

    pass


class CveException(QSigException):
    """CVE Exceptions"""

    pass
