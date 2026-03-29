# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

# Directories to ignore during scanning
IGNORED_DIRECTORIES = frozenset({
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "env",
})


@dataclass(frozen=True)
class ScannedFile:
    """
    Represents a scanned file with its metadata.

    Attributes:
        path: Absolute path to the file.
        size: File size in bytes.
        modified_time: Last modification time as datetime.
        honeypot: Name of the source honeypot (e.g., 'dionaea', 'cowrie').
    """

    path: Path
    size: int
    modified_time: datetime
    honeypot: str = ""


class PayloadScanner:
    """
    Scans filesystem directories for payload files.

    Recursively scans specified directories for files, filtering out
    ignored directories and optionally filtering by last scan time.
    Symlinks are not followed to prevent infinite loops and security issues.
    """

    def __init__(
        self,
        ignored_dirs: frozenset[str] | None = None,
        follow_symlinks: bool = False,
    ):
        """
        Initialize the PayloadScanner.

        Args:
            ignored_dirs: Set of directory names to ignore during scanning.
                          Defaults to IGNORED_DIRECTORIES if not provided.
            follow_symlinks: Whether to follow symbolic links. Defaults to False
                             for security reasons (prevents infinite loops and
                             symlink attacks).
        """
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.ignored_dirs = ignored_dirs if ignored_dirs is not None else IGNORED_DIRECTORIES
        self.follow_symlinks = follow_symlinks

    def _should_ignore_directory(self, dir_name: str) -> bool:
        """
        Check if a directory should be ignored during scanning.

        Args:
            dir_name: Name of the directory to check.

        Returns:
            True if the directory should be ignored, False otherwise.
        """
        return dir_name in self.ignored_dirs

    def _get_file_modified_time(self, file_path: Path) -> datetime:
        """
        Get the last modification time of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Datetime of the last modification.
        """
        stat_result = file_path.stat()
        return datetime.fromtimestamp(stat_result.st_mtime)

    def _create_scanned_file(
        self,
        file_path: Path,
        honeypot: str = "",
    ) -> ScannedFile:
        """
        Create a ScannedFile instance from a file path.

        Args:
            file_path: Path to the file.
            honeypot: Name of the source honeypot.

        Returns:
            ScannedFile instance with file metadata.
        """
        stat_result = file_path.stat()
        return ScannedFile(
            path=file_path,
            size=stat_result.st_size,
            modified_time=datetime.fromtimestamp(stat_result.st_mtime),
            honeypot=honeypot,
        )

    def scan_directory(
        self,
        directory: str | Path,
        last_scan_time: datetime | None = None,
        honeypot: str = "",
    ) -> Iterator[ScannedFile]:
        """
        Recursively scan a directory for payload files.

        Args:
            directory: Path to the directory to scan.
            last_scan_time: Optional datetime to filter files.
                            Only files modified after this time are returned.
            honeypot: Name of the source honeypot for attribution.

        Yields:
            ScannedFile instances for each discovered file.

        Raises:
            FileNotFoundError: If the directory does not exist.
            PermissionError: If the directory cannot be accessed.
        """
        directory_path = Path(directory)

        if not directory_path.exists():
            self.log.warning(f"Directory does not exist: {directory}")
            return

        if not directory_path.is_dir():
            self.log.warning(f"Path is not a directory: {directory}")
            return

        self.log.info(f"Scanning directory: {directory} (honeypot: {honeypot or 'unknown'})")
        file_count = 0

        for root, dirs, files in os.walk(directory_path):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]

            for file_name in files:
                file_path = Path(root) / file_name

                try:
                    scanned_file = self._create_scanned_file(file_path, honeypot)

                    # Filter by last scan time if provided
                    if last_scan_time is not None:
                        if scanned_file.modified_time <= last_scan_time:
                            continue

                    file_count += 1
                    yield scanned_file

                except (OSError, PermissionError) as e:
                    self.log.warning(f"Cannot access file {file_path}: {e}")
                    continue

        self.log.info(f"Scan complete. Found {file_count} files in {directory}")

    def scan_directories(
        self,
        directories: list[str | Path] | dict[str, str | Path],
        last_scan_time: datetime | None = None,
    ) -> Iterator[ScannedFile]:
        """
        Scan multiple directories for payload files.

        Args:
            directories: Either a list of directory paths to scan, or a dict
                         mapping honeypot names to directory paths.
                         Example: {"dionaea": "/data/dionaea/binaries",
                                   "cowrie": "/data/cowrie/downloads"}
            last_scan_time: Optional datetime to filter files.
                            Only files modified after this time are returned.

        Yields:
            ScannedFile instances for each discovered file across all directories.
        """
        if isinstance(directories, dict):
            for honeypot, directory in directories.items():
                yield from self.scan_directory(directory, last_scan_time, honeypot)
        else:
            for directory in directories:
                yield from self.scan_directory(directory, last_scan_time)

    def count_files(
        self,
        directory: str | Path,
        last_scan_time: datetime | None = None,
    ) -> int:
        """
        Count the number of files in a directory without loading all metadata.

        Args:
            directory: Path to the directory to scan.
            last_scan_time: Optional datetime to filter files.

        Returns:
            Number of files found.
        """
        return sum(1 for _ in self.scan_directory(directory, last_scan_time))
