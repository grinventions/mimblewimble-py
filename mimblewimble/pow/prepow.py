from typing import Dict
from datetime import datetime

import struct


def serialize_pre_pow(header: Dict) -> bytes:
    """
    Serializes block header fields in the same order as BlockHeader::GetPreProofOfWork()
    Returns: bytes (exactly what should be hashed in PoW)
    """
    pieces = []

    # 1. version                  → uint16_t (2 bytes)
    version = header["version"]
    pieces.append(struct.pack(">H", version))  # little-endian

    # 2. height                   → uint64_t (8 bytes)
    height = header["height"]
    pieces.append(struct.pack(">Q", height))

    # 3. timestamp                → int64_t (8 bytes)
    ts_str = header["timestamp"]
    if isinstance(ts_str, int):
        timestamp_sec = ts_str
    else:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        timestamp_sec = int(dt.timestamp())
    pieces.append(struct.pack(">q", timestamp_sec))  # signed int64_le

    # 4–8. 32-byte hashes (big-endian in serialization!)
    def append_hash32(field_name: str):
        h = header[field_name]  # hex string
        h_bytes = bytes.fromhex(h)
        if len(h_bytes) != 32:
            raise ValueError(f"{field_name} must be 32 bytes")
        pieces.append(h_bytes)  # as-is = big-endian

    append_hash32("previous")  # previousBlockHash
    append_hash32("prev_root")  # previousRoot
    append_hash32("output_root")  # outputRoot
    append_hash32("range_proof_root")  # rangeProofRoot
    append_hash32("kernel_root")  # kernelRoot

    # 9. total_kernel_offset      → 32-byte big integer
    kernel_offset_hex = header["total_kernel_offset"]
    kernel_offset_bytes = bytes.fromhex(kernel_offset_hex)
    if len(kernel_offset_bytes) != 32:
        raise ValueError("total_kernel_offset must be 32 bytes")
    pieces.append(kernel_offset_bytes)

    # 10. output_mmr_size         → uint64_t
    pieces.append(struct.pack(">Q", header["output_mmr_size"]))

    # 11. kernel_mmr_size         → uint64_t
    pieces.append(struct.pack(">Q", header["kernel_mmr_size"]))

    # 12. total_difficulty        → uint64_t
    pieces.append(struct.pack(">Q", header["total_difficulty"]))

    # 13. secondary_scaling       → uint32_t   (in json it's called secondary_scaling)
    pieces.append(struct.pack(">I", header["secondary_scaling"]))

    # 14. nonce                   → uint64_t
    pieces.append(struct.pack(">Q", header["nonce"]))

    return b"".join(pieces)
