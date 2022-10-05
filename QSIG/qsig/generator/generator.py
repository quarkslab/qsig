from __future__ import annotations
import logging
import multiprocessing
import pathlib
from typing import Optional, Tuple, List

import qsig
import qsig.generator


logger = logging.getLogger(__name__)


def generate_signature(
    vulnerability: qsig.Vulnerability,
    signature_path: Optional[pathlib.Path] = None,
    arch: qsig.Architecture = qsig.cve.Architecture.x64,
) -> pathlib.Path:
    """Generates a signature for the `vulnerability`.

    Args:
        vulnerability: Vulnerability to generate the signature for
        signature_path: Path of the signature
        arch: Architecture to generate for.

    Raises:
        GeneratorException if the generation fails

    Returns:
        The path of the signature
    """
    generator = qsig.generator.CveGenerator(vulnerability)

    result = generator.generate(arch)
    if result:
        return generator.save(output_file=signature_path)

    raise qsig.GeneratorException("Unable to generate the signature.")


def generate_multiple_signature(
    vulnerabilities: List[qsig.Vulnerability],
    architecture: qsig.Architecture,
) -> List[pathlib.Path]:
    """Generates multiple signatures from a list of vulnerabilities

    Args:
        vulnerabilities: Vulnerabilities
        architecture: Architecture to generate the signature for

    Returns:
        The list of signatures generated

    """
    with multiprocessing.Pool() as pool:

        failed: int = 0
        signatures_paths: List[pathlib.Path] = []
        for vulnerability in vulnerabilities:
            result = pool.apply_async(
                generate_signature,
                (
                    vulnerability,
                    vulnerability.path.parent / f"{vulnerability.name}.sig",
                    architecture,
                ),
            )

            try:
                signatures_paths.append(result.get(qsig.Settings.GENERATOR_TIMEOUT))
            except qsig.CveException:
                logger.error("CVE %s is invalid", vulnerability.name)
                failed += 1
            except qsig.GeneratorException:
                logger.error("Unable to generate for %s", vulnerability.name)
                failed += 1
            except multiprocessing.TimeoutError:
                logger.error("Timeout for %s", vulnerability.name)
                failed += 1
            except Exception as e:
                logger.error("Failed with unknown exception", exc_info=e)
                failed += 1

    logger.info("Failed to generate signatures for %d/%d", failed, len(vulnerabilities))

    return signatures_paths
