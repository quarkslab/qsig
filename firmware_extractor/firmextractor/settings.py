"""
Firmware extractor - Settings
---------------

The settings of Firware Extracotr are grouped in this module.
They are updatable from the environment using the 'FW_' prefix.

Value are lazily type checked and for optional values, -1 == None.

Example:
export FW_SHADOW="$(pwd)"

"""

import os
import pathlib
from typing import get_type_hints, Optional, List


class Settings:
    __PREFIX: str = "FW_"
    __HAS_BEEN_UPDATED: bool = False

    SHADOW: pathlib.Path = pathlib.Path("/home/alexis/Project/PatchSig/Shadow")
    """Shadow path"""

    PROCESSES: Optional[int] = None
    """Number of processes to use. Default to max"""

    @staticmethod
    def update_settings() -> None:
        """Update the settings according to values set in the ENV."""

        if Settings.__HAS_BEEN_UPDATED is True:
            return

        qsig_vars = [
            variable
            for variable in os.environ
            if variable.startswith(Settings.__PREFIX)
        ]

        local_constants = [
            cst for cst in dir(Settings) if not cst.startswith("__") and cst.isupper()
        ]

        variable_types = get_type_hints(Settings)

        for variable in local_constants:
            variable_env = f"{Settings.__PREFIX}{variable}"
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
                elif variable_type is pathlib.Path:
                    value = pathlib.Path(variable_value)
                # HACK: Use get_args after Python3.8
                elif "NoneType" in str(variable_type):
                    value = int(variable_value)
                    if value == -1:
                        value = None
                else:
                    raise Exception(
                        f"Unknown variable type {variable_type} for {variable}"
                    )

                setattr(Settings, variable, value)

        Settings.__HAS_BEEN_UPDATED = True


Settings.update_settings()
