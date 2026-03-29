# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import logging
import mimetypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Try to import python-magic for better file type detection
try:
    import magic

    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# Default chunk size for reading files (64 KB)
DEFAULT_CHUNK_SIZE = 64 * 1024

# Magic bytes for common file types (fallback when python-magic is unavailable)
MAGIC_BYTES = {
    b"\x7fELF": "application/x-executable",
    b"MZ": "application/x-dosexec",
    b"PK\x03\x04": "application/zip",
    b"\x1f\x8b": "application/gzip",
    b"BZ": "application/x-bzip2",
    b"\xca\xfe\xba\xbe": "application/x-mach-binary",
    b"\x89PNG": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF8": "image/gif",
    b"%PDF": "application/pdf",
    b"Rar!": "application/x-rar-compressed",
    b"7z\xbc\xaf": "application/x-7z-compressed",
    b"\xd0\xcf\x11\xe0": "application/x-ole-storage",
}


@dataclass(frozen=True)
class FileHashes:
    """
    Container for file hash values.

    Attributes:
        sha256: SHA-256 hash as hexadecimal string.
        sha1: SHA-1 hash as hexadecimal string.
        md5: MD5 hash as hexadecimal string.
    """

    sha256: str
    sha1: str
    md5: str


@dataclass(frozen=True)
class ProcessedPayload:
    """
    Represents a fully processed payload with all metadata.

    Attributes:
        path: Original file path.
        sha256: SHA-256 hash.
        sha1: SHA-1 hash.
        md5: MD5 hash.
        file_size: Size in bytes.
        file_type: MIME type or detected file type.
        file_name: Original filename.
        modified_time: Last modification time.
        honeypot: Name of the source honeypot (e.g., 'dionaea', 'cowrie').
    """

    path: Path
    sha256: str
    sha1: str
    md5: str
    file_size: int
    file_type: str
    file_name: str
    modified_time: datetime
    honeypot: str = ""


class PayloadProcessor:
    """
    Processes payload files to extract metadata and compute hashes.

    Handles file processing efficiently using chunked reading for
    large files. Computes multiple hash algorithms in a single pass.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize the PayloadProcessor.

        Args:
            chunk_size: Size of chunks for reading files in bytes.
                        Defaults to 64 KB.
        """
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.chunk_size = chunk_size

    def compute_hashes(self, file_path: Path) -> FileHashes:
        """
        Compute SHA256, SHA1, and MD5 hashes for a file.

        Reads the file in chunks to efficiently handle large files,
        computing all three hashes in a single pass.

        Args:
            file_path: Path to the file to hash.

        Returns:
            FileHashes containing all computed hashes.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            OSError: If there is an I/O error reading the file.
        """
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(self.chunk_size):
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                md5_hash.update(chunk)

        return FileHashes(
            sha256=sha256_hash.hexdigest(),
            sha1=sha1_hash.hexdigest(),
            md5=md5_hash.hexdigest(),
        )

    def detect_file_type(self, file_path: Path) -> str:
        """
        Detect the MIME type of a file.

        Detection priority:
        1. python-magic library (most accurate, uses libmagic)
        2. Extension-based detection via mimetypes module
        3. Manual magic byte detection (fallback)

        Args:
            file_path: Path to the file.

        Returns:
            MIME type string, or "application/octet-stream" if unknown.
        """
        # Try python-magic first (most accurate)
        if MAGIC_AVAILABLE:
            try:
                mime_type = self._detect_by_python_magic(file_path)
                if mime_type and mime_type != "application/octet-stream":
                    return mime_type
            except Exception as e:
                self.log.debug(f"python-magic detection failed for {file_path}: {e}")

        # Try extension-based detection
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type:
            return mime_type

        # Fall back to manual magic byte detection
        try:
            return self._detect_by_magic_bytes(file_path)
        except (OSError, PermissionError) as e:
            self.log.warning(f"Cannot read magic bytes from {file_path}: {e}")
            return "application/octet-stream"

    def _detect_by_python_magic(self, file_path: Path) -> str:
        """
        Detect file type using python-magic library.

        Uses libmagic for accurate file type detection based on
        file contents rather than extension.

        Args:
            file_path: Path to the file.

        Returns:
            Detected MIME type.

        Raises:
            Exception: If python-magic fails to detect the file type.
        """
        if not MAGIC_AVAILABLE:
            raise RuntimeError("python-magic is not installed")

        mime = magic.Magic(mime=True)
        return mime.from_file(str(file_path))

    def _detect_by_magic_bytes(self, file_path: Path) -> str:
        """
        Detect file type using manual magic bytes inspection.

        Fallback method when python-magic is unavailable.

        Args:
            file_path: Path to the file.

        Returns:
            Detected MIME type or "application/octet-stream" if unknown.
        """
        with open(file_path, "rb") as f:
            header = f.read(16)

        for magic_bytes, mime_type in MAGIC_BYTES.items():
            if header.startswith(magic_bytes):
                return mime_type

        return "application/octet-stream"

    def get_file_size(self, file_path: Path) -> int:
        """
        Get the size of a file in bytes.

        Args:
            file_path: Path to the file.

        Returns:
            File size in bytes.

        Raises:
            FileNotFoundError: If the file does not exist.
            OSError: If the file cannot be accessed.
        """
        return file_path.stat().st_size

    def get_modified_time(self, file_path: Path) -> datetime:
        """
        Get the last modification time of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Datetime of the last modification.

        Raises:
            FileNotFoundError: If the file does not exist.
            OSError: If the file cannot be accessed.
        """
        return datetime.fromtimestamp(file_path.stat().st_mtime)

    def process(
        self,
        file_path: Path | str,
        honeypot: str = "",
    ) -> ProcessedPayload:
        """
        Fully process a payload file.

        Computes all hashes and extracts all metadata in an efficient
        manner, minimizing file system operations.

        Args:
            file_path: Path to the file to process.
            honeypot: Name of the source honeypot for attribution.

        Returns:
            ProcessedPayload containing all extracted metadata and hashes.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            OSError: If there is an I/O error.
        """
        file_path = Path(file_path)

        self.log.debug(f"Processing payload: {file_path} (honeypot: {honeypot or 'unknown'})")

        # Compute hashes (single pass through the file)
        hashes = self.compute_hashes(file_path)

        # Get file metadata
        stat_result = file_path.stat()
        file_size = stat_result.st_size
        modified_time = datetime.fromtimestamp(stat_result.st_mtime)

        # Detect file type
        file_type = self.detect_file_type(file_path)

        processed = ProcessedPayload(
            path=file_path,
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            file_size=file_size,
            file_type=file_type,
            file_name=file_path.name,
            modified_time=modified_time,
            honeypot=honeypot,
        )

        self.log.debug(f"Processed payload: {hashes.sha256[:16]}... ({file_type})")

        return processed

    def process_multiple(
        self,
        file_paths: list[Path | str],
    ) -> list[ProcessedPayload]:
        """
        Process multiple payload files.

        Args:
            file_paths: List of paths to files to process.

        Returns:
            List of ProcessedPayload instances. Files that fail to
            process are logged and skipped.
        """
        results = []

        for file_path in file_paths:
            try:
                processed = self.process(file_path)
                results.append(processed)
            except (OSError, PermissionError) as e:
                self.log.warning(f"Failed to process {file_path}: {e}")
                continue

        return results
