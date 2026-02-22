"""
mimblewimble/mmr/sync.py

TxHashSet state-sync: download and validate a TxHashSet ZIP from a Grin node.

Grin nodes expose the TxHashSet archive at:
  GET /v1/txhashset/outputs/byid?id={header_hash_hex}

The ZIP contains the flat PMMR files for output, rangeproof and kernel,
matching the on-disk layout of this Python implementation.

Usage::

    from mimblewimble.mmr.sync import TxHashSetSync
    txhs = TxHashSetSync.sync(
        node_url="https://grinnode.live:3413",
        header=block_header,
        data_dir=Path("/var/grin/chain_data/txhashset"),
    )
    # txhs is a fully validated TxHashSet instance
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from mimblewimble.mmr.txhashset import TxHashSet, TxHashSetError

# ---------------------------------------------------------------------------
# TxHashSetSync
# ---------------------------------------------------------------------------


class TxHashSetSync:
    """End-to-end TxHashSet download, extraction, and validation."""

    # Grin v2 node API endpoints
    _HEADERS_ENDPOINT = "/v1/headers/{hash}"
    _TXHASHSET_ENDPOINT = "/v1/txhashset/outputs/byid?id={hash}"
    _TXHASHSET_ROOTS_ENDPOINT = "/v1/txhashset/roots"
    _MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024
    _MAX_ZIP_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
    _MAX_SINGLE_ENTRY_BYTES = 2 * 1024 * 1024 * 1024
    _MAX_COMPRESSION_RATIO = 200

    @classmethod
    def sync(
        cls,
        node_url: str,
        header,
        data_dir: Path,
        timeout: int = 300,
    ) -> TxHashSet:
        """Download, extract, open and validate a TxHashSet from *node_url*.

        Parameters
        ----------
        node_url:
            Base URL of the Grin node, e.g. ``"https://grinnode.live:3413"``.
        header:
            ``BlockHeader`` whose hash identifies the archive and whose root
            hashes are used for validation.
        data_dir:
            Directory where the extracted PMMR files will be stored.
        timeout:
            HTTP timeout in seconds.

        Returns
        -------
        TxHashSet
            A fully validated, ready-to-use TxHashSet instance.
        """
        header_hash = cls._header_hash_hex(header)
        zip_path = cls.download(node_url, header_hash, data_dir, timeout=timeout)
        cls.extract(zip_path, data_dir)
        txhs = TxHashSet(data_dir)
        txhs.validate_roots(header)
        return txhs

    @classmethod
    def download(
        cls,
        node_url: str,
        header_hash_hex: str,
        dest_dir: Path,
        timeout: int = 300,
    ) -> Path:
        """Stream the TxHashSet ZIP from *node_url* to *dest_dir*.

        Returns the local path of the downloaded ZIP.
        """
        try:
            import requests  # type: ignore
        except ImportError as e:
            raise TxHashSetError(
                "The 'requests' package is required for state sync.  "
                "Install it with: pip install requests"
            ) from e

        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        url = node_url.rstrip("/") + cls._TXHASHSET_ENDPOINT.format(
            hash=header_hash_hex
        )
        zip_path = dest_dir / f"txhashset_{header_hash_hex[:16]}.zip"

        with requests.get(url, stream=True, timeout=timeout) as resp:
            resp.raise_for_status()
            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                try:
                    expected_bytes = int(content_length)
                except ValueError as e:
                    raise TxHashSetError("Invalid Content-Length in response") from e
                if expected_bytes < 0 or expected_bytes > cls._MAX_DOWNLOAD_BYTES:
                    raise TxHashSetError(
                        f"TxHashSet archive too large ({expected_bytes} bytes)"
                    )

            downloaded = 0
            with open(zip_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 20):  # 1 MiB chunks
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > cls._MAX_DOWNLOAD_BYTES:
                        raise TxHashSetError(
                            f"TxHashSet archive exceeds max allowed size ({cls._MAX_DOWNLOAD_BYTES} bytes)"
                        )
                    f.write(chunk)

        return zip_path

    @classmethod
    def extract(cls, zip_path: Path, data_dir: Path) -> None:
        """Extract a TxHashSet ZIP into the canonical PMMR directory layout.

        The ZIP must contain entries like:
            output/pmmr_hash.bin
            rangeproof/pmmr_hash.bin
            kernel/pmmr_hash.bin
            kernel/pmmr_data.bin
            ...

        Files are placed into *data_dir*/{output,rangeproof,kernel}/.
        """
        zip_path = Path(zip_path)
        data_dir = Path(data_dir)

        with zipfile.ZipFile(zip_path, "r") as zf:
            total_uncompressed = 0
            for entry in zf.infolist():
                if entry.is_dir():
                    continue

                # Sanitise entry name to prevent zip-slip attacks
                normalized_name = entry.filename.replace("\\", "/")
                entry_path = Path(normalized_name)
                parts = entry_path.parts
                if (
                    not parts
                    or entry_path.is_absolute()
                    or ".." in parts
                    or any(":" in p for p in parts)
                ):
                    continue

                # Only extract output/, rangeproof/, kernel/ sub-trees
                if parts[0] not in ("output", "rangeproof", "kernel"):
                    continue

                if entry.file_size < 0 or entry.file_size > cls._MAX_SINGLE_ENTRY_BYTES:
                    raise TxHashSetError(
                        f"Archive entry too large: {entry.filename} ({entry.file_size} bytes)"
                    )

                compressed = max(entry.compress_size, 1)
                ratio = entry.file_size / compressed
                if ratio > cls._MAX_COMPRESSION_RATIO:
                    raise TxHashSetError(
                        f"Suspicious compression ratio in {entry.filename} ({ratio:.1f}x)"
                    )

                total_uncompressed += entry.file_size
                if total_uncompressed > cls._MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise TxHashSetError(
                        "Archive uncompressed size exceeds safety limit"
                    )

                dest = data_dir / entry_path
                dest_resolved = dest.resolve()
                data_dir_resolved = data_dir.resolve()
                if data_dir_resolved not in dest_resolved.parents:
                    raise TxHashSetError(
                        f"Unsafe archive path outside destination: {entry.filename}"
                    )
                dest.parent.mkdir(parents=True, exist_ok=True)

                with zf.open(entry) as src, open(dest, "wb") as dst:
                    written = 0
                    while True:
                        buf = src.read(1 << 20)
                        if not buf:
                            break
                        written += len(buf)
                        if written > cls._MAX_SINGLE_ENTRY_BYTES:
                            raise TxHashSetError(
                                f"Archive entry exceeds max allowed size while extracting: {entry.filename}"
                            )
                        dst.write(buf)

    @classmethod
    def validate_from_header(cls, txhashset: TxHashSet, header) -> bool:
        """Convenience wrapper: validate *txhashset* roots against *header*."""
        return txhashset.validate_roots(header)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _header_hash_hex(header) -> str:
        """Return the block header hash as a hex string."""
        if hasattr(header, "getHash"):
            return header.getHash().hex()
        if hasattr(header, "hash"):
            h = header.hash
            return h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
        raise ValueError("Cannot extract hash from header object")
