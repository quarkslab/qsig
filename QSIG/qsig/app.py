import collections
import logging
import pathlib
import re
from typing import Optional, Generator, List, Iterable, DefaultDict, Counter
from typing_extensions import TypedDict
import typer

import firmextractor
import qsig


app = typer.Typer()

State = TypedDict(
    "State",
    {
        "logger": logging.Logger,
    },
    total=False,
)

state: State = {}


@app.command(name="generate-multiple")
def generate_multiple(
    cve_path: pathlib.Path,
    arch: qsig.cve.Architecture = typer.Option(
        qsig.cve.Architecture.x64.value,
        help="Architecture to generate the signature from",
    ),
    force: bool = typer.Option(False, help="Overwrite existing signature"),
) -> None:
    """Generate signature for every CVE found in a directory."""

    logger = state["logger"]

    cve_pattern = re.compile(r"CVE-20([0-9]+)-([0-9]{4,})")
    candidates: List[qsig.cve.Vulnerability] = []
    for cve_directory in cve_path.iterdir():
        if not cve_directory.is_dir():
            continue

        cve: Optional[qsig.cve.Vulnerability] = None
        if cve_pattern.match(cve_directory.name):
            # Try and load an Compiled CVE
            for commit_directory in cve_directory.iterdir():
                if len(commit_directory.name) == 40 or commit_directory.suffix in (
                    ".tgz",
                    ".zst",
                ):
                    cve = qsig.cve.CompiledCve(commit_directory.with_suffix(""))
                    break

        elif (cve_directory / "functions.json").is_file():
            try:
                cve = qsig.cve.CGCVuln(cve_directory)
            except qsig.exc.CveException:
                pass

        if cve is None:
            continue

        try:
            if not cve.valid:
                logger.info(f"CVE %s is not valid", cve.name)
                continue
        except qsig.exc.CveException:
            continue

        output_file = cve_path / f"{cve.name}.sig"
        if output_file.is_file() and not force:
            logger.info("Skip %s because force was not set", cve.name)
            continue

        candidates.append(cve)

    logger.info("Start generating for %d candidates", len(candidates))
    qsig.generator.generate_multiple_signature(candidates, arch)


@app.command()
def generate(
    cve_path: pathlib.Path,
    signature_path: Optional[pathlib.Path] = typer.Option(
        None, help="Where to store the signature"
    ),
    arch: qsig.cve.Architecture = typer.Option(
        qsig.cve.Architecture.x64.value,
        help="Architecture to generate the signature from",
    ),
) -> None:
    """Generate a signature based on a CVE directory

    The cve_path must be a valid AOSP CVE or  a CGC vuln
    """

    logger = state["logger"]

    if len(cve_path.stem) == 40:  # We have a commit ID
        cve = qsig.cve.CompiledCve(cve_path)
    else:
        cve = qsig.cve.CGCVuln(cve_path)

    try:
        if not cve.valid:
            logger.debug(f"CVE is invalid - trying to continue.")
    except qsig.exc.CveException:
        logger.error("Unable to load the CVE.")
        raise typer.Exit(code=1)

    try:
        signature_path = qsig.generator.generate_signature(cve, signature_path, arch)
    except qsig.GeneratorException as e:
        logger.error(e)
        raise typer.Exit(code=1)

    logger.info(
        f"Signature has been generated for {cve.name} and stored in {signature_path}"
    )


@app.command()
def detector(
    archive_path: pathlib.Path = typer.Argument(
        ...,
        file_okay=True,
        dir_okay=True,
        exists=True,
        readable=True,
        resolve_path=True,
        help="Firmware patch",
    ),
    signature_path: pathlib.Path = typer.Argument(
        ...,
        file_okay=True,
        dir_okay=True,
        exists=True,
        readable=True,
        resolve_path=True,
        help="Signature(s) path",
    ),
    bgraph: pathlib.Path = typer.Option(
        None, file_okay=True, readable=True, resolve_path=True, help="Path to a BGraph"
    ),
) -> None:
    """Detect if a patch has been applied to a firmware image

    The archive path should be a valid firmware archive.
    The signature path should points towards a valid signature file or a directory
    containing the signatures.

    When matching AOSP firmwares, an optional path to a BGraph can be given in order to
    improve filtering.
    """
    logger = state["logger"]

    logger.info("Load signatures")

    # Create the program loader
    # TODO(dm): When multithreaded, create multiple program loader
    program_loader = qsig.program.SingleProgramLoader()

    detectors: List[qsig.detector.CVEDetector] = qsig.detector.init_detectors(
        signature_path, program_loader, bgraph=bgraph
    )

    logger.info(f"Successfully loaded %d detectors", len(detectors))

    if not detectors:
        logger.info(f"No signatures found, abort.")
        raise typer.Exit(code=1)

    for cve_detector in detectors:
        logger.info(f"%s", cve_detector)

    logger.info(f"Extract and mount filesystem")
    # TODO(dm) Better mechanism for accepting archives
    if archive_path.suffix == ".zip":
        pixel = firmextractor.pixel.Pixel(archive_path)
        pixel.decompress_all()
        file_systems = pixel.file_systems()

    elif archive_path.is_dir():
        file_systems = [firmextractor.fs.FileSystem(archive_path)]

    else:
        logger.error("Firmware format not recognized, aborting.")
        raise typer.Exit(code=1)

    for file_system in file_systems:
        results: DefaultDict[str, Counter[str]] = collections.defaultdict(
            collections.Counter
        )

        logger.info(
            "Start with image %s mounted at %s", file_system.name, file_system.base_path
        )

        firmware_file: firmextractor.fs.ExecutableFile
        for firmware_file in file_system.elf_files(with_special=False):
            logger.debug("Probing %s", firmware_file.name)
            for cve_detector in detectors:
                results[cve_detector.cve_id]["tests"] += 1
                if cve_detector.accept(firmware_file):
                    logger.debug(
                        "Cve %s pre-matched on %s",
                        cve_detector.cve_id,
                        firmware_file.name,
                    )
                    try:
                        result = cve_detector.match(firmware_file)
                    except (qsig.exc.DetectorException, Exception) as e:
                        logger.exception(e)
                        results[cve_detector.cve_id]["failed"] += 1
                        continue

                    if result is True:
                        results[cve_detector.cve_id]["found"] += 1

        logger.info("For image %s (found/tested/failed)", file_system.name)
        for cve_detector in detectors:
            logger.info(
                "\t[%s] : %d / %d ( %d failed)",
                cve_detector.cve_id,
                results[cve_detector.cve_id]["found"],
                results[cve_detector.cve_id]["tests"],
                results[cve_detector.cve_id]["failed"],
            )


@app.command()
def info(signatures: List[pathlib.Path], signature_ext: str = ".sig") -> None:
    """Dump info on the signatures."""

    logger = state["logger"]

    def find_signatures(path: pathlib.Path) -> Generator[pathlib.Path, None, None]:
        if path.is_file():
            if path.suffix == signature_ext:
                yield path
            return

        for file in path.iterdir():
            yield from find_signatures(file)

    sig_count = 0

    sig = qsig.sig.signature.CVESignature()
    for signature in signatures:
        for signature_file in find_signatures(signature):
            try:
                sig.load(signature_file)
                logger.info("%s", sig)
                sig_count += 1
            except qsig.sig.exc.SignatureException:
                continue

    if sig_count > 1:
        logger.info("Found %d signatures", sig_count)


@app.command()
def detect(file: pathlib.Path, signature: pathlib.Path, force: bool = False) -> None:
    """Apply a signature onto a file."""
    logger = state["logger"]

    if not file.is_file():
        logger.error("Did not find %s", file)
        raise typer.Exit(code=2)

    program_loader = qsig.program.SingleProgramLoader()
    cve_detectors: List[qsig.detector.CVEDetector] = qsig.detector.init_detectors(
        signature, program_loader
    )

    if len(cve_detectors) != 1:
        logger.error("Unable to load the signature %s", signature)
        raise typer.Exit(code=2)

    cve_detector = cve_detectors.pop()

    file_system = firmextractor.fs.FileSystem(file.parent)
    exec_file = firmextractor.fs.ExecutableFile(
        file_path=file, alternative_names=[], mime_type=None, firmware=file_system
    )

    if cve_detector.accept(exec_file, force=force):
        try:
            result = cve_detector.match(exec_file)
        except qsig.exc.DetectorException:
            logger.error("Error during detection")
            raise typer.Exit(code=2)

        if result is False:
            logger.info("Did not match %s for %s", file.name, cve_detector.cve_id)
            raise typer.Exit(code=1)


@app.callback()
def main(
    debug: bool = typer.Option(False, "--debug", "-d", help="Activate debug output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silence output"),
    bench: bool = typer.Option(
        False, "--bench", "-b", help="Activate benchmark output"
    ),
) -> None:
    """
    QSIG CLI - Use to generate signature or match firmwares images
    """

    verbosity = qsig.logger.Verbosity.INFO
    if debug:
        verbosity = qsig.logger.Verbosity.DEBUG
    elif quiet:
        verbosity = qsig.logger.Verbosity.ERROR
    elif bench:
        verbosity = qsig.logger.Verbosity.BENCHMARK

    qsig.Settings.update_settings()

    qsig.logger.setup_logger(verbosity)
    state["logger"] = logging.getLogger()


if __name__ == "__main__":
    import warnings

    warnings.warn("use 'python -m qsig', not 'python -m qsig.app'", DeprecationWarning)
    app()
