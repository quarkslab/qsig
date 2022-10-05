"""
QSIG - Settings
---------------

The settings of QSig are grouped in this module.
They are updatable from the environment using the 'QSIG_' prefix.

Value are lazily type checked and for optional values, -1 == None.

Example:
QSIG_AUTHOR="$USER" python -m qsig.app generate ...

"""

import os
from typing import get_type_hints, Optional, List


class Settings:

    # Signature settings
    AUTHOR: str = "dm"
    """Author for signature"""

    MIN_CONSTANT: int = 0x1000
    """Min constant: every new constant below the threshold won't be considered."""

    MAX_CONSTANT: int = 0xFFFF - 0x1000
    """Max constant: every new constant above the threshold will be dismissed."""

    GENERATOR_TIMEOUT: int = 300
    """Timeout (in seconds) for the generator."""

    # Detector settings
    # # Selector settings
    SIMILAR_CHUNK: Optional[int] = 3
    """How many chunks to consider using the selector. Set to None to prevent filtering.
    """

    # # Prematch settings
    NAME_THRESHOLD: float = 0.5
    """Threshold for name consideration.
    """

    EXPORT_TIMEOUT: Optional[int] = None
    """Timeout for quokka."""

    BINCAT_TIMEOUT: Optional[int] = 600
    """Timeout for BinCAT."""

    @staticmethod
    def update_settings():
        """Update the settings according to values set in the ENV."""
        qsig_vars = [
            variable for variable in os.environ if variable.startswith("QSIG_")
        ]

        local_constants = [
            cst for cst in dir(Settings) if not cst.startswith("__") and cst.isupper()
        ]

        variable_types = get_type_hints(Settings)

        for variable in local_constants:
            variable_env = f"QSIG_{variable}"
            if variable_env in qsig_vars:

                variable_type = variable_types[variable]
                variable_value = os.environ.get(variable_env)

                if variable_type is int:
                    base = 10
                    if variable_value.startswith("0x") or variable_value.startswith(
                        "0X"
                    ):
                        base = 16
                    value = int(variable_value, base=base)
                elif variable_type is str:
                    value = variable_value
                elif variable_type is float:
                    value = float(variable_value)
                # HACK: Use get_args after Python3.8
                elif "Optional[int]" in str(variable_type):
                    value = int(variable_value)
                    if value == -1:
                        value = None
                else:
                    raise Exception(
                        f"Unknown variable type {variable_type} for {variable}"
                    )

                setattr(Settings, variable, value)
