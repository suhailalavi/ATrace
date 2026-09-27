import os
import shutil
import subprocess
import tempfile
import logging
from typing import List, Optional, Tuple
from alavitrace.core.models import Target

logger = logging.getLogger("ATrace")

class NmapError(Exception):
    """Base exception for Nmap scanner operations."""
    pass

class NmapNotFoundError(NmapError):
    """Raised when Nmap executable is not found in PATH."""
    pass

class NmapExecutionError(NmapError):
    """Raised when Nmap process fails or returns a non-zero status."""
    pass

class NmapTimeoutError(NmapError):
    """Raised when Nmap scan execution times out."""
    pass

class NmapScanner:
    """
    Safely executes Nmap service detection scans via subprocess.run(shell=False)
    and manages temporary XML output files.
    """

    def __init__(self, nmap_binary: str = "nmap", timeout_seconds: int = 300):
        self.nmap_binary = nmap_binary
        self.timeout_seconds = timeout_seconds

    def check_nmap_installed(self) -> str:
        """
        Verifies that Nmap is installed and accessible via PATH.
        Returns the resolved absolute path to nmap executable.
        """
        executable_path = shutil.which(self.nmap_binary)
        if not executable_path:
            raise NmapNotFoundError(
                f"Nmap executable '{self.nmap_binary}' was not found in system PATH. "
                "Please install Nmap or add it to PATH."
            )
        return executable_path

    def run_scan(self, target: Target, extra_args: Optional[List[str]] = None) -> Tuple[str, List[str]]:
        """
        Executes an Nmap scan against a validated target and outputs XML to a temporary file.

        Args:
            target: Validated Target object.
            extra_args: Optional controlled extra flags (default: None).

        Returns:
            Tuple[str, List[str]]: Path to generated temporary XML file, and full argument list used.
        """
        if not target.is_valid:
            raise ValueError(f"Cannot scan invalid target: {target.error_message}")

        self.check_nmap_installed()

        # Create temporary file safely
        temp_xml = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        xml_path = temp_xml.name
        temp_xml.close()

        # Build controlled command list with shell=False
        cmd = [self.nmap_binary, "-sV", "-oX", xml_path]

        # Allow extra controlled flags if provided (e.g. -Pn)
        if extra_args:
            for flag in extra_args:
                if flag in ["-Pn"]:
                    cmd.append(flag)

        cmd.append(target.normalized)

        logger.info(f"Executing Nmap scanner command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False
            )

            if result.returncode != 0:
                self.cleanup_xml(xml_path)
                raise NmapExecutionError(
                    f"Nmap execution failed with return code {result.returncode}.\n"
                    f"Stderr: {result.stderr.strip()}"
                )

            if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
                self.cleanup_xml(xml_path)
                raise NmapExecutionError("Nmap completed but generated an empty or missing XML output file.")

            logger.info(f"Nmap scan completed successfully. XML generated at: {xml_path}")
            return xml_path, cmd

        except FileNotFoundError:
            self.cleanup_xml(xml_path)
            raise NmapNotFoundError(f"Nmap binary '{self.nmap_binary}' could not be executed.")
        except subprocess.TimeoutExpired:
            self.cleanup_xml(xml_path)
            raise NmapTimeoutError(f"Nmap scan timed out after {self.timeout_seconds} seconds.")

    @staticmethod
    def cleanup_xml(xml_path: str) -> None:
        """Safely removes the temporary XML output file."""
        if xml_path and os.path.exists(xml_path):
            try:
                os.remove(xml_path)
                logger.debug(f"Cleaned up temporary Nmap XML output file: {xml_path}")
            except OSError as e:
                logger.warning(f"Failed to remove temporary XML file '{xml_path}': {e}")
