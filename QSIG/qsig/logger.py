import datetime
import enum
import logging
import pathlib
from typing import Any, List

from pythonjsonlogger import jsonlogger
import typer


class ColorFormatter(logging.Formatter):
    """Color formatter

    Nice formatter for Typer CLI.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a record for printing.

        Args:
            record: Record to format

        Returns:
            A nice looking string
        """
        level: int = record.levelno
        message: str = record.getMessage()

        if level >= logging.ERROR:
            if record.exc_info:
                return typer.style(
                    self.formatException(record.exc_info),
                    fg=typer.colors.RED,
                    bg=typer.colors.BRIGHT_WHITE,
                )

            # Format: ERROR: {message:s}
            return typer.style(
                f"ERROR: {message:s}", fg=typer.colors.RED, bg=typer.colors.BRIGHT_BLACK
            )

        elif level == logging.INFO:
            # Format : INFO: {message:s}
            return typer.style(
                f"INFO: {message:s}",
                fg=typer.colors.BLACK,
                bg=typer.colors.BRIGHT_YELLOW,
            )

        elif level >= logging.DEBUG:
            # Format : [funcName] - {pathname}:{lineno} - {message}
            return typer.style(
                f"[{record.funcName:^20}] - {record.pathname}:{record.lineno} - {message:s}",
                fg=typer.colors.BLACK,
                bg=typer.colors.BRIGHT_WHITE,
            )

        else:
            return typer.style(f"UNK: {message:s}")


class TyperHandler(logging.Handler):
    """Typer Handler - logging handler for Typer

    Based on a StreamHandler, but adapted for Typer.
    """

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a record (e.g. print it)

        Args:
            record: Record to emit
        """
        try:
            message: str = self.format(record)
            typer.echo(message)

            if record.levelno >= logging.ERROR:
                # raise typer.Exit(code=1)  # TODO(dm) CHANGE ME
                pass

        except Exception:
            self.handleError(record)

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter records for benchmark purposes so they don't pollute the output.

        Args:
            record: Record to consider

        Returns:
            Boolean if we should keep the record
        """
        return not hasattr(record, "bench") and super(TyperHandler, self).filter(record)


class CustomFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return hasattr(record, "bench")  # TODO(dm) Rename me


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record: Any, record: Any, message_dict: Any) -> None:
        del record.message
        del record.bench
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)

    def parse(self) -> List[str]:
        # Override to prevent "message" field
        return []


class Verbosity(enum.IntEnum):
    ERROR = logging.ERROR
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    BENCHMARK = logging.INFO - 1


def setup_logger(verbosity: Verbosity = Verbosity.INFO) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(verbosity)

    typer_handler: TyperHandler = TyperHandler()
    typer_handler.setFormatter(ColorFormatter())
    typer_handler.setLevel(verbosity)

    root_logger.handlers = [typer_handler]
    root_logger.propagate = False

    if verbosity <= Verbosity.BENCHMARK:

        now = datetime.datetime.now()

        current_file: pathlib.Path = pathlib.Path(__file__)
        log_dir = (current_file.parent.parent.parent / "logs").resolve()

        file_handler: logging.FileHandler = logging.FileHandler(
            filename=now.strftime(f"{log_dir}/%y_%m_%d_%H_%M_%S_result.log"),
            mode="a",
        )

        file_handler.addFilter(CustomFilter())
        file_handler.setFormatter(CustomJsonFormatter())
        file_handler.setLevel(verbosity)

        root_logger.addHandler(file_handler)
