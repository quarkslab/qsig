import qsig.exc


class SignatureException(qsig.exc.QSigException):
    """Base class for signature exceptions"""

    pass


class BincatException(SignatureException):
    """BinCAT exceptions"""

    pass


class ConditionException(SignatureException):
    """Conditions exceptions"""

    pass


class YaraToolException(SignatureException):
    """YARA exceptions"""

    pass
