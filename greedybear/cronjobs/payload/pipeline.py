# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from greedybear.cronjobs.payload.processor import ProcessedPayload
from greedybear.cronjobs.payload.scanner import PayloadScanner, ScannedFile


@dataclass
class ExtractionResult:
    """
    Result of a payload extraction pipeline run.

    Attributes:
        new_payloads: List of newly discovered payloads.
        updated_payloads: List of payloads that were already known (duplicates).
        failed_files: List of file paths that failed to process.
        total_scanned: Total number of files scanned.
        total_new: Count of new unique payloads.
        total_duplicates: Count of duplicate payloads.
        total_failed: Count of files that failed processing.
    """

    new_payloads: list[ProcessedPayload] = field(default_factory=list)
    updated_payloads: list[ProcessedPayload] = field(default_factory=list)
    failed_files: list[Path] = field(default_factory=list)
    total_scanned: int = 0
    total_new: int = 0
    total_duplicates: int = 0
    total_failed: int = 0


@dataclass
class PayloadUpdate:
    """
    Represents an update to an existing payload.

    Attributes:
        sha256: SHA256 hash of the payload.
        last_seen: New last seen timestamp.
        source_path: Path where the duplicate was found.
    """

    sha256: str
    last_seen: datetime
    source_path: Path


class PayloadExtractionPipeline:
    """
    Orchestrates the payload extraction workflow.

    Coordinates the scanner and processor to:
    1. Find new payload files in configured directories
    2. Process files to extract metadata and compute hashes
    3. Deduplicate payloads using SHA256
    4. Prepare data for database storage

    This class does not handle database operations directly;
    it prepares data structures that can be persisted by a repository.
    """

    def __init__(
        self,
        scanner: PayloadScanner | None = None,
        processor: "PayloadProcessor | None" = None,
    ):
        """
        Initialize the PayloadExtractionPipeline.

        Args:
            scanner: PayloadScanner instance for finding files.
                     Creates a default instance if not provided.
            processor: PayloadProcessor instance for processing files.
                       Creates a default instance if not provided.
        """
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Lazy import to avoid circular imports
        from greedybear.cronjobs.payload.processor import PayloadProcessor

        self.scanner = scanner if scanner is not None else PayloadScanner()
        self.processor = processor if processor is not None else PayloadProcessor()

        # Track known SHA256 hashes for deduplication within a run
        self._known_hashes: set[str] = set()

    def _is_duplicate(self, sha256: str) -> bool:
        """
        Check if a payload with the given SHA256 is already known.

        Args:
            sha256: SHA256 hash to check.

        Returns:
            True if the hash is already known, False otherwise.
        """
        return sha256 in self._known_hashes

    def _register_hash(self, sha256: str) -> None:
        """
        Register a SHA256 hash as known.

        Args:
            sha256: SHA256 hash to register.
        """
        self._known_hashes.add(sha256)

    def load_known_hashes(self, hashes: set[str]) -> None:
        """
        Load a set of known SHA256 hashes for deduplication.

        This should be called before execute() with hashes from
        the database to avoid reprocessing existing payloads.

        Args:
            hashes: Set of SHA256 hashes already in the database.
        """
        self._known_hashes = hashes.copy()
        self.log.info(f"Loaded {len(self._known_hashes)} known payload hashes")

    def clear_known_hashes(self) -> None:
        """Clear the set of known hashes."""
        self._known_hashes.clear()

    def _process_scanned_file(
        self,
        scanned_file: ScannedFile,
    ) -> tuple[ProcessedPayload | None, bool]:
        """
        Process a single scanned file.

        Args:
            scanned_file: ScannedFile instance to process.

        Returns:
            Tuple of (ProcessedPayload or None, is_duplicate).
            Returns (None, False) if processing failed.
        """
        try:
            processed = self.processor.process(
                scanned_file.path,
                honeypot=scanned_file.honeypot,
            )

            if self._is_duplicate(processed.sha256):
                return processed, True

            self._register_hash(processed.sha256)
            return processed, False

        except (OSError, PermissionError) as e:
            self.log.warning(f"Failed to process {scanned_file.path}: {e}")
            return None, False

    def execute(
        self,
        directories: list[str | Path] | dict[str, str | Path],
        last_scan_time: datetime | None = None,
    ) -> ExtractionResult:
        """
        Execute the payload extraction pipeline.

        Scans the specified directories for payload files, processes
        each file to extract metadata and compute hashes, and
        deduplicates based on SHA256.

        Args:
            directories: Either a list of directory paths to scan, or a dict
                         mapping honeypot names to directory paths for source
                         attribution.
                         Example: {"dionaea": "/data/dionaea/binaries",
                                   "cowrie": "/data/cowrie/downloads"}
            last_scan_time: Optional datetime to filter files.
                            Only files modified after this time are processed.

        Returns:
            ExtractionResult containing all discovered and updated payloads.
        """
        result = ExtractionResult()

        dir_count = len(directories) if isinstance(directories, (list, dict)) else 1
        self.log.info(f"Starting payload extraction from {dir_count} directories")

        if last_scan_time:
            self.log.info(f"Filtering files modified after {last_scan_time}")

        # Scan all directories
        for scanned_file in self.scanner.scan_directories(directories, last_scan_time):
            result.total_scanned += 1

            processed, is_duplicate = self._process_scanned_file(scanned_file)

            if processed is None:
                result.failed_files.append(scanned_file.path)
                result.total_failed += 1
                continue

            if is_duplicate:
                result.updated_payloads.append(processed)
                result.total_duplicates += 1
                self.log.debug(f"Duplicate payload: {processed.sha256[:16]}...")
            else:
                result.new_payloads.append(processed)
                result.total_new += 1
                self.log.debug(f"New payload: {processed.sha256[:16]}...")

        self.log.info(
            f"Extraction complete: {result.total_new} new, "
            f"{result.total_duplicates} duplicates, "
            f"{result.total_failed} failed"
        )

        return result

    def execute_single_directory(
        self,
        directory: str | Path,
        last_scan_time: datetime | None = None,
    ) -> ExtractionResult:
        """
        Execute the pipeline for a single directory.

        Convenience method for scanning a single directory.

        Args:
            directory: Directory path to scan.
            last_scan_time: Optional datetime to filter files.

        Returns:
            ExtractionResult containing all discovered payloads.
        """
        return self.execute([directory], last_scan_time)

    def get_payload_updates(
        self,
        result: ExtractionResult,
    ) -> list[PayloadUpdate]:
        """
        Extract payload updates from an extraction result.

        Creates PayloadUpdate instances for all duplicate payloads,
        which can be used to update last_seen timestamps and
        increment times_seen counters in the database.

        Args:
            result: ExtractionResult from a pipeline run.

        Returns:
            List of PayloadUpdate instances for duplicates.
        """
        updates = []

        for payload in result.updated_payloads:
            update = PayloadUpdate(
                sha256=payload.sha256,
                last_seen=payload.modified_time,
                source_path=payload.path,
            )
            updates.append(update)

        return updates
