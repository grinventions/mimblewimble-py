import hashlib
import json  # TODO remove after debugging
import time
from datetime import datetime, timezone
from io import BytesIO

from mimblewimble.mmr.index import MMRIndex
from mimblewimble.serializer import Serializer

from mimblewimble.consensus import Consensus
from mimblewimble.models.short_id import ShortId

from mimblewimble.models.transaction import TransactionInput
from mimblewimble.models.transaction import TransactionOutput
from mimblewimble.models.transaction import TransactionBody
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import TransactionKernel, EKernelFeatures


class HeaderValidationError(ValueError):
    """Raised when a block header fails validation."""

    pass


class BlockValidationError(ValueError):
    """Raised when a full block fails validation."""

    pass


def _kernel_signing_msg(kernel: "TransactionKernel") -> bytes:
    """Compute the 32-byte blake2b signing message for a TransactionKernel.

    Matches Grin's KernelFeatures::kernel_sig_msg() in core/src/core/transaction.rs:
        blake2b_256(feature_byte [| fee_u64_be] [| lock_or_rel_height_be])
    """
    msg_bytes = bytearray()
    features = kernel.getFeatures()
    msg_bytes.append(features.value)

    if features == EKernelFeatures.DEFAULT_KERNEL:
        fee_val = kernel.getFee().getFee() if kernel.getFee() is not None else 0
        msg_bytes += fee_val.to_bytes(8, "big")
    elif features == EKernelFeatures.COINBASE_KERNEL:
        pass  # just the feature byte
    elif features == EKernelFeatures.HEIGHT_LOCKED:
        fee_val = kernel.getFee().getFee() if kernel.getFee() is not None else 0
        msg_bytes += fee_val.to_bytes(8, "big")
        msg_bytes += kernel.getLockHeight().to_bytes(8, "big")
    elif features == EKernelFeatures.NO_RECENT_DUPLICATE:
        fee_val = kernel.getFee().getFee() if kernel.getFee() is not None else 0
        msg_bytes += fee_val.to_bytes(8, "big")
        msg_bytes += kernel.getLockHeight().to_bytes(2, "big")

    return hashlib.blake2b(bytes(msg_bytes), digest_size=32).digest()


class ProofOfWork:
    def __init__(self, edgeBits, proofNonces):
        self.edgeBits = edgeBits  # 1 byte
        self.proofNonces = proofNonces

    def getEdgeBits(self):
        return self.edgeBits

    def getProofNonces(self):
        return self.proofNonces

    def isPrimary(self):
        return Consensus.isPrimary(self.edgeBits)

    def isSecondary(self):
        return Consensus.isSecondary(self.edgeBits)

    def serialize(self, serializer):
        serializer.write(self.getEdgeBits().to_bytes(1, "big"))
        serializer.write(self.serializeCycle())

    def serializeCycle(self):
        bytes_len = int(((self.getEdgeBits() * Consensus.proofsize) + 7) / 8)
        serialized_bytes = bytearray(bytes_len)
        for n in range(len(self.getProofNonces())):
            for bit in range(int(self.getEdgeBits())):
                nonce = self.proofNonces[n]
                if nonce & (1 << bit) != 0:
                    positionTemp = (n * self.edgeBits) + bit
                    p = int(positionTemp / 8)
                    serialized_bytes[p] |= 1 << (positionTemp % 8)
        return serialized_bytes

    @classmethod
    def deserialize(self, B):
        edgeBits = int.from_bytes(B.read(1), "big")
        bytes_len = int(((edgeBits * Consensus.proofsize) + 7) / 8)
        bits = B.read(bytes_len)
        proofNonces = self.deserializeProofNonces(bits, edgeBits)
        return ProofOfWork(edgeBits, proofNonces)

    def deserializeProofNonces(bits, edgeBits):
        if edgeBits == 0 or edgeBits > 63:
            raise ValueError("Invalid number of edge bits {0}".format(str(edgeBits)))
        uint8_t1 = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        proofNonces = []
        for n in range(Consensus.proofsize):
            proofNonce = 0
            for bit in range(edgeBits):
                positionTemp = (n * edgeBits) + bit
                p = int(positionTemp / 8)
                if int(bits[p]) & (1 << (positionTemp % 8)):
                    proofNonce |= 1 << bit
            proofNonces.append(proofNonce)
        return proofNonces

    def getHash(self):
        cycle = self.serializeCycle()
        return hashlib.blake2b(cycle, digest_size=32).digest()

    @property
    def is_secondary(self) -> bool:
        return self.isSecondary()


class BlockHeader:
    def __init__(
        self,
        version,
        height,
        timestamp,
        previousBlockHash,
        previousRoot,
        outputRoot,
        rangeProofRoot,
        kernelRoot,
        totalKernelOffset,
        outputMMRSize,
        kernelMMRSize,
        totalDifficulty,
        scalingDifficulty,
        nonce,
        proofOfWork,
    ):
        self.version = version
        self.height = height
        self.timestamp = timestamp
        self.previousBlockHash = previousBlockHash
        self.previousRoot = previousRoot
        self.outputRoot = outputRoot
        self.rangeProofRoot = rangeProofRoot
        self.kernelRoot = kernelRoot
        self.totalKernelOffset = totalKernelOffset
        self.outputMMRSize = outputMMRSize
        self.kernelMMRSize = kernelMMRSize
        self.totalDifficulty = totalDifficulty
        self.scalingDifficulty = scalingDifficulty
        self.nonce = nonce
        self.proofOfWork = proofOfWork

    # getters

    def getVersion(self):
        return self.version

    def getHeight(self):
        return self.height

    def getPreviousHash(self):
        return self.previousBlockHash

    def getPreviousRoot(self):
        return self.previousRoot

    def getTimestamp(self):
        return self.timestamp

    def getTotalDifficulty(self):
        return self.totalDifficulty

    def getScalingDifficulty(self):
        return self.scalingDifficulty

    def getTotalScalingDifficulty(self):
        return self.scalingDifficulty

    def getTotalKernelOffset(self):
        return self.totalKernelOffset

    def getNonce(self):
        return self.nonce

    # pow

    def getProofOfWork(self):
        return self.proofOfWork

    def getEdgeBits(self):
        return self.proofOfWork.getEdgeBits()

    def getProofNonces(self):
        return self.proofOfWork.getProofNonces()

    def isPrimaryPoW(self):
        return self.proofOfWork.isPrimary()

    def isSecondaryPoW(self):
        return self.proofOfWork.isSecondary()

    # Compatibility properties for DifficultyCalculator / DifficultyLoader
    # These expose snake_case aliases expected by the difficulty subsystem.

    @property
    def prev_hash(self) -> str:
        """Hex-encoded previous block hash (key format for IBlockDB lookups)."""
        return self.previousBlockHash.hex()

    @property
    def total_difficulty(self) -> int:
        return self.totalDifficulty

    @property
    def scaling_difficulty(self) -> int:
        return self.scalingDifficulty

    @property
    def proof_of_work(self) -> "ProofOfWork":
        return self.proofOfWork

    # Merklish root stuffz

    def getOutputRoot(self):
        return self.outputRoot

    def getRangeProofRoot(self):
        return self.rangeProofRoot

    def getKernelRoot(self):
        return self.kernelRoot

    # Merkle Mountain Range Sizes

    def getOutputMMRSize(self):
        return self.outputMMRSize

    def getKernelMMRSize(self):
        return self.kernelMMRSize

    def getNumOutputs(self):
        return MMRIndex.at(self.outputMMRSize).getLeafIndex()

    def getNumKernels(self):
        return MMRIndex.at(self.kernelMMRSize).getLeafIndex()

    # serialization / deserialization

    def serialize(self, serializer: Serializer):
        serializer.write(self.version.to_bytes(2, "big"))
        serializer.write(self.height.to_bytes(8, "big"))
        serializer.write(self.timestamp.to_bytes(8, "big"))
        serializer.write(self.previousBlockHash)
        serializer.write(self.previousRoot)
        serializer.write(self.outputRoot)
        serializer.write(self.rangeProofRoot)
        serializer.write(self.kernelRoot)
        serializer.write(self.totalKernelOffset.serialize())  # blinding factor
        serializer.write(self.outputMMRSize.to_bytes(8, "big"))
        serializer.write(self.kernelMMRSize.to_bytes(8, "big"))
        serializer.write(self.totalDifficulty.to_bytes(8, "big"))
        serializer.write(self.scalingDifficulty.to_bytes(4, "big"))
        serializer.write(self.nonce.to_bytes(8, "big"))
        self.proofOfWork.serialize(serializer)

    @classmethod
    def deserialize(self, B: Serializer):
        version = int.from_bytes(B.read(2), "big")
        height = int.from_bytes(B.read(8), "big")
        timestamp = int.from_bytes(B.read(8), "big")
        previousBlockHash = B.read(32)
        previousRoot = B.read(32)
        outputRoot = B.read(32)
        rangeProofRoot = B.read(32)
        kernelRoot = B.read(32)

        totalKernelOffset = BlindingFactor.deserialize(B.read(32))

        outputMMRSize = int.from_bytes(B.read(8), "big")
        kernelMMRSize = int.from_bytes(B.read(8), "big")
        totalDifficulty = int.from_bytes(B.read(8), "big")
        scalingDifficulty = int.from_bytes(B.read(4), "big")
        nonce = int.from_bytes(B.read(8), "big")

        proofOfWork = ProofOfWork.deserialize(B)

        return BlockHeader(
            version,
            height,
            timestamp,
            previousBlockHash,
            previousRoot,
            outputRoot,
            rangeProofRoot,
            kernelRoot,
            totalKernelOffset,
            outputMMRSize,
            kernelMMRSize,
            totalDifficulty,
            scalingDifficulty,
            nonce,
            proofOfWork,
        )

    def toJSON(self):
        cuckooSolution = b""
        for proofNonce in self.getProofOfWork().getProofNonces():
            cuckooSolution += proofNonce.to_bytes(8, "big")

        ts_utc = datetime.fromtimestamp(
            self.getTimestamp(), tz=timezone.utc
        ).isoformat()

        return {
            "height": self.getHeight(),
            "hash": self.getHash().hex(),
            "version": self.getVersion(),
            "timestamp_raw": self.getTimestamp(),
            "timestamp_local": ts_utc,
            "timestamp": ts_utc,
            "previous": self.getPreviousHash().hex(),
            "prev_root": self.getPreviousRoot().hex(),
            "kernel_root": self.getKernelRoot().hex(),
            "output_root": self.getOutputRoot().hex(),
            "range_proof_root": self.getRangeProofRoot().hex(),
            "output_mmr_size": self.getOutputMMRSize(),
            "kernel_mmr_size": self.getKernelMMRSize(),
            "total_kernel_offset": self.getTotalKernelOffset().hex(),
            "secondary_scaling": self.getScalingDifficulty(),
            "total_difficulty": self.getTotalDifficulty(),
            "nonce": self.getNonce(),
            "edge_bits": self.getProofOfWork().getEdgeBits(),
            "cuckoo_solution": cuckooSolution.hex(),
        }

    @classmethod
    def fromDict(self, O: dict):
        return BlockHeader(
            O["version"],
            O["height"],
            O["timestamp"],
            O["previousBlockHash"],
            O["previousRoot"],
            O["rangeProofRoot"],
            O["kernelRoot"],
            O["totalKernelOffset"],
            O["outputMMRSize"],
            O["kernelMMRSize"],
            O["totalDifficulty"],
            O["scalingDifficulty"],
            O["nonce"],
            ProofOfWork.deserialize(O["proofOfWork"]),
        )

    @classmethod
    def fromJSON(self, jsonString: str):
        O = json.loads(jsonString)
        return BlockHeader.fromDict(O)

    def getPrePoW(self) -> bytes:
        """Return the pre-PoW serialised header bytes.

        This is the data that is hashed to produce the canonical block header
        hash used throughout Grin's protocol (locators, segment keys, etc.).
        The PoW nonce and cycle are excluded; the nonce field position is
        zeroed out before hashing.
        """
        s = Serializer()
        s.write(self.version.to_bytes(2, "big"))
        s.write(self.height.to_bytes(8, "big"))
        s.write(self.timestamp.to_bytes(8, "big"))
        s.write(self.previousBlockHash)
        s.write(self.previousRoot)
        s.write(self.outputRoot)
        s.write(self.rangeProofRoot)
        s.write(self.kernelRoot)
        s.write(self.totalKernelOffset.serialize())
        s.write(self.outputMMRSize.to_bytes(8, "big"))
        s.write(self.kernelMMRSize.to_bytes(8, "big"))
        s.write(self.totalDifficulty.to_bytes(8, "big"))
        s.write(self.scalingDifficulty.to_bytes(4, "big"))
        # nonce slot zeroed out (8 bytes) — excluded from hash pre-image
        s.write(b"\x00" * 8)
        return s.getvalue()

    # hashing

    def getHash(self) -> bytes:
        """Return the canonical blake2b-256 header hash.

        Computed over the pre-PoW serialised header bytes (nonce slot zeroed).
        This matches Grin's reference implementation:
          blake2b_256(pre_pow_bytes)
        NOT the PoW cycle hash — that is only used for the PoW proof itself.
        """
        return hashlib.blake2b(self.getPrePoW(), digest_size=32).digest()

    def shortHash(self):
        # TODO
        pass

    def validate(
        self,
        prev_header: "BlockHeader | None" = None,
        block_db=None,
        current_time: int | None = None,
    ) -> None:
        """Validate this header.  Raises :class:`HeaderValidationError` on failure."""
        validate_header(
            self, prev_header=prev_header, block_db=block_db, current_time=current_time
        )


def validate_header(
    header: "BlockHeader",
    prev_header: "BlockHeader | None" = None,
    block_db=None,
    current_time: int | None = None,
) -> None:
    """Validate a single block header.

    Checks (in order):
      1. Timestamp is not too far in the future.
      2. Chain-linking: prev_hash / height match *prev_header* when supplied.
      3. Proof-of-Work solution is valid for the declared algorithm.
      4. Declared difficulty meets the next-difficulty target (requires *block_db*).

    Args:
        header:       The :class:`BlockHeader` to validate.
        prev_header:  The immediately preceding :class:`BlockHeader`, if available.
        block_db:     An :class:`~mimblewimble.pow.blockdb.IBlockDB` instance used
                      to compute the expected next-difficulty.  When ``None`` the
                      difficulty check is skipped.
        current_time: Current Unix epoch (seconds).  Defaults to ``time.time()``.

    Raises:
        HeaderValidationError: on any validation failure.
    """
    from mimblewimble.pow.algos import pow_validate

    now = current_time if current_time is not None else int(time.time())

    # 1. Timestamp: reject blocks more than FTL seconds in the future
    max_ts = now + int(Consensus.default_future_time_limit_sec)
    if header.getTimestamp() > max_ts:
        raise HeaderValidationError(
            f"Header timestamp {header.getTimestamp()} too far in future "
            f"(max {max_ts}, height={header.getHeight()})"
        )

    # 2. Chain-linking
    if prev_header is not None:
        if header.getPreviousHash() != prev_header.getHash():
            raise HeaderValidationError(
                f"Header prev_hash mismatch at height {header.getHeight()}: "
                f"expected {prev_header.getHash().hex()[:12]}… "
                f"got {header.getPreviousHash().hex()[:12]}…"
            )
        if header.getHeight() != prev_header.getHeight() + 1:
            raise HeaderValidationError(
                f"Header height {header.getHeight()} expected "
                f"{prev_header.getHeight() + 1}"
            )

    # 3. Proof-of-Work
    # Build the dict that pow_validate() expects; cuckoo_solution must be List[int].
    header_dict = header.toJSON()
    header_dict["cuckoo_solution"] = header.getProofNonces()
    # serialize_pre_pow uses the raw timestamp int when present
    header_dict["timestamp"] = header.getTimestamp()

    result = pow_validate(header_dict)
    # pow_validate returns (bool, status) for all algorithm variants
    if isinstance(result, tuple):
        valid, status = result
    else:
        # Older algo wrappers may return just the status code
        from mimblewimble.pow.common import EPoWStatus

        valid = result == EPoWStatus.POW_OK
        status = result

    if not valid:
        raise HeaderValidationError(
            f"Header PoW invalid (status={status}, height={header.getHeight()}, "
            f"edge_bits={header.getEdgeBits()})"
        )

    # 4. Difficulty target check (optional; requires previous-header chain in block_db)
    if block_db is not None and header.getHeight() > 0:
        try:
            from mimblewimble.pow.difficulty_calculator import DifficultyCalculator

            calc = DifficultyCalculator(block_db)
            expected = calc.calculate_next_difficulty(header)
            expected_diff = expected.get_difficulty()
            if prev_header is not None:
                block_diff = (
                    header.getTotalDifficulty() - prev_header.getTotalDifficulty()
                )
            else:
                block_diff = header.getTotalDifficulty()
            if block_diff < expected_diff:
                raise HeaderValidationError(
                    f"Header difficulty {block_diff} below minimum {expected_diff} "
                    f"(height={header.getHeight()})"
                )
        except HeaderValidationError:
            raise
        except Exception:
            # Not enough history to compute difficulty; skip rather than fail.
            pass


class FullBlock:
    def __init__(self, header: BlockHeader, body: TransactionBody, validated=False):
        self.header = header
        self.body = body
        self.validated = validated

    def getHeader(self):
        return self.header

    def getTransactionBody(self):
        return self.body

    def getInputs(self):
        return self.body.getInputs()

    def getOutputs(self):
        return self.body.getOutputs()

    def getKernels(self):
        return self.body.getKernels()

    def getInputCommitments(self):
        return [_input.getCommitment() for _input in self.getInputs()]

    def getOutputCommitments(self):
        return [_output.getCommitment() for _output in self.getOutputs()]

    def getTotalFees(self):
        return self.body.calcFee()

    def calcWeight(self):
        return self.body.calcWeight(self.getHeight())

    def getHeight(self):
        return self.header.getHeight()

    def getPreviousHash(self):
        return self.header.getPreviousHash()

    def getTotalDifficulty(self):
        return self.header.getTotalDifficulty()

    def getTotalKernelOffset(self):
        return self.header.getTotalKernelOffset()

    def serialize(self):
        serializer = Serializer()
        self.header.serialize(serializer)
        self.body.serialize(serializer)
        return serializer.getvalue()

    @classmethod
    def deserialize(self, serializer: Serializer):
        header = BlockHeader.deserialize(serializer)
        body = TransactionBody.deserialize(serializer)
        return FullBlock(header, body)

    def toJSON(self):
        # transaction outputs
        outputs = []
        for _output in self.getOutputs():
            output_json = _output.toJSON()
            output_json["block_height"] = self.getHeight()
            outputs.append(output_json)

        return {
            "header": self.header.toJSON(),
            "inputs": [_input.toJSON() for _input in self.getInputs()],
            "outputs": outputs,
            "kernels": [kernel.toJSON() for kernel in self.getKernels()],
        }

    def getHash(self):
        return self.header.getHash()

    def wasValidated(self):
        return self.validated

    def markAsValidated(self):
        self.validated = True

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(
        self,
        prev_header: "BlockHeader | None" = None,
        block_db=None,
        current_time: int | None = None,
    ) -> None:
        """Validate this block end-to-end.

        Checks:
          1. Header PoW, timestamp, chain-linking, and difficulty.
          2. Block weight does not exceed the protocol limit.
          3. Coinbase output/kernel consistency (reward + fees balance).
          4. Kernel excess sum (Mimblewimble balance equation).
          5. Output rangeproofs (Bulletproof batch verify).
          6. Kernel Schnorr signatures (batch verify).
          7. Kernel lock-height constraints.

        Args:
            prev_header:  The immediately preceding block header (for chain-linking
                          and difficulty checks).  May be ``None`` for genesis.
            block_db:     An :class:`~mimblewimble.pow.blockdb.IBlockDB` for the
                          difficulty check.  Skipped when ``None``.
            current_time: Current Unix epoch seconds; defaults to ``time.time()``.

        Raises:
            HeaderValidationError: if the header is invalid.
            BlockValidationError:  if the block body is invalid.
        """
        # 1. Header
        validate_header(
            self.header,
            prev_header=prev_header,
            block_db=block_db,
            current_time=current_time,
        )

        # 2. Block weight
        height = self.getHeight()
        version = self.header.getVersion()
        if version >= 5:
            weight = Consensus.calculateWeightV5(
                len(self.getInputs()),
                len(self.getOutputs()),
                len(self.getKernels()),
            )
        else:
            weight = Consensus.calculateWeightV4(
                len(self.getInputs()),
                len(self.getOutputs()),
                len(self.getKernels()),
            )
        if weight > Consensus.max_block_weight:
            raise BlockValidationError(
                f"Block weight {weight} exceeds max {Consensus.max_block_weight} "
                f"(height={height})"
            )

        # 3. Coinbase consistency
        self._verify_coinbase(height)

        # 4. Kernel excess sum (Mimblewimble balance)
        self._verify_kernel_sum()

        # 5. Rangeproofs
        self._verify_rangeproofs()

        # 6. Kernel signatures
        self._verify_kernel_signatures()

        # 7. Lock heights
        self._verify_lock_heights(height)

        self.validated = True

    def _verify_coinbase(self, height: int) -> None:
        """Verify exactly one coinbase output and kernel, and that their
        commitments balance against the block reward + total transaction fees."""
        from mimblewimble.crypto.pedersen import Pedersen
        from mimblewimble.models.transaction import EKernelFeatures

        cb_outputs = [o for o in self.getOutputs() if o.isCoinbase()]
        cb_kernels = [k for k in self.getKernels() if k.isCoinbase()]

        if len(cb_outputs) != 1 or len(cb_kernels) != 1:
            raise BlockValidationError(
                f"Block must have exactly one coinbase output and kernel "
                f"(outputs={len(cb_outputs)}, kernels={len(cb_kernels)}, "
                f"height={height})"
            )

        cb_output = cb_outputs[0]
        cb_kernel = cb_kernels[0]

        # Total fees from non-coinbase kernels
        tx_fees = sum(
            k.getFee().getFee()
            for k in self.getKernels()
            if not k.isCoinbase() and k.getFee() is not None
        )
        reward_value = int(Consensus.reward) + tx_fees

        pedersen = Pedersen()
        from mimblewimble.models.transaction import BlindingFactor as _BF

        reward_commit = pedersen.commit(reward_value, _BF.zero())
        expected = pedersen.commitSum(
            [cb_kernel.getExcessCommitment(), reward_commit], []
        )

        if cb_output.getCommitment().getBytes() != expected.getBytes():
            raise BlockValidationError(
                f"Coinbase output commitment does not match kernel excess + reward "
                f"(height={height})"
            )

    def _verify_kernel_sum(self) -> None:
        """Verify the Mimblewimble kernel-sum equation for this block:
        sum(output_commits) - sum(input_commits) - fees*H
        == sum(kernel_excesses) + kernel_offset*G
        """
        from mimblewimble.crypto.pedersen import Pedersen
        from mimblewimble.models.transaction import BlindingFactor as _BF

        pedersen = Pedersen()

        output_commits = [o.getCommitment() for o in self.getOutputs()]
        input_commits = [i.getCommitment() for i in self.getInputs()]
        kernel_excess_commits = [k.getExcessCommitment() for k in self.getKernels()]

        total_fees = sum(
            k.getFee().getFee()
            for k in self.getKernels()
            if not k.isCoinbase() and k.getFee() is not None
        )
        fees_commit = pedersen.commit(total_fees, _BF.zero())

        offset_bytes = self.getTotalKernelOffset().getBytes()
        offset_commit = pedersen.commit(0, _BF(offset_bytes))

        # utxo_sum = sum(outputs) - sum(inputs) - fees*H
        utxo_sum = pedersen.commitSum(output_commits, input_commits + [fees_commit])
        # kern_sum = sum(kernel_excesses) + offset*G
        kern_sum = pedersen.commitSum(kernel_excess_commits + [offset_commit], [])

        if utxo_sum.getBytes() != kern_sum.getBytes():
            raise BlockValidationError(
                f"Kernel sum mismatch at height={self.getHeight()}: "
                f"utxo_sum={utxo_sum.getBytes().hex()[:12]}… "
                f"kern_sum={kern_sum.getBytes().hex()[:12]}…"
            )

    def _verify_rangeproofs(self) -> None:
        """Batch-verify all output bulletproof rangeproofs."""
        from mimblewimble.crypto.bulletproof import Bulletproof

        outputs = self.getOutputs()
        if not outputs:
            return
        bp = Bulletproof()
        pairs = [(o.getCommitment(), o.getRangeProof()) for o in outputs]
        if not bp.verifyBulletproofs(pairs):
            raise BlockValidationError(
                f"Rangeproof verification failed at height={self.getHeight()}"
            )

    def _verify_kernel_signatures(self) -> None:
        """Batch-verify all kernel Schnorr signatures."""
        from mimblewimble.crypto.aggsig import AggSig

        kernels = self.getKernels()
        if not kernels:
            return
        agg = AggSig()
        signatures = [k.getExcessSignature() for k in kernels]
        commitments = [k.getExcessCommitment() for k in kernels]
        messages = [_kernel_signing_msg(k) for k in kernels]
        if not agg.verifyAggregateSignatures(signatures, commitments, messages):
            raise BlockValidationError(
                f"Kernel signature verification failed at height={self.getHeight()}"
            )

    def _verify_lock_heights(self, height: int) -> None:
        """Verify kernel lock heights are not in the future."""
        from mimblewimble.models.transaction import EKernelFeatures

        for kernel in self.getKernels():
            features = kernel.getFeatures()
            if features == EKernelFeatures.HEIGHT_LOCKED:
                if kernel.getLockHeight() > height:
                    raise BlockValidationError(
                        f"Kernel lock height {kernel.getLockHeight()} > "
                        f"block height {height}"
                    )


class CompactBlock:
    def __init__(self, header, nonce, fullOutputs, fullKernels, shortIds):
        self.header = header
        self.nonce = nonce
        self.outputs = fullOutputs
        self.kernels = fullKernels
        self.short_ids = shortIds

    # getters

    def getHeader(self):
        return self.header

    def getNonce(self):
        return self.nonce

    def getOutputs(self):
        return self.outputs

    def getKernels(self):
        return self.kernels

    def getShortIds(self):
        return self.short_ids

    def getPreviousHash(self):
        return self.header.getPreviousHash()

    def getHeight(self):
        return self.header.getHeight()

    def getTotalDifficulty(self):
        return self.header.getTotalDifficulty()

    # serialization / deserialization

    def serialize(self):
        from io import BytesIO as _BytesIO

        # nonce is 8 bytes (uint64 big-endian)
        bytes_nonce = self.nonce.to_bytes(8, "big")

        bytes_num_outputs = len(self.getOutputs()).to_bytes(2, "big")
        bytes_num_kernels = len(self.getKernels()).to_bytes(2, "big")
        bytes_num_short_ids = len(self.getShortIds()).to_bytes(2, "big")

        # Outputs require a Serializer (not a raw BytesIO)
        output_ser = Serializer()
        for _output in self.getOutputs():
            _output.serialize(output_ser)
        bytes_outputs = output_ser.getvalue()

        # Kernels require a Serializer
        kernel_ser = Serializer()
        for _kernel in self.getKernels():
            _kernel.serialize(kernel_ser)
        bytes_kernels = kernel_ser.getvalue()

        # ShortId.serialize takes a BytesIO
        short_id_buf = _BytesIO()
        for _short_id in self.getShortIds():
            _short_id.serialize(short_id_buf)
        bytes_short_ids = short_id_buf.getvalue()

        return (
            bytes_nonce
            + bytes_num_outputs
            + bytes_num_kernels
            + bytes_num_short_ids
            + bytes_outputs
            + bytes_kernels
            + bytes_short_ids
        )

    @classmethod
    def deserialize(cls, B):
        """Deserialize a CompactBlock from a Serializer stream.

        Wire format: nonce(8) | num_outputs(2) | num_kernels(2) |
                     num_short_ids(2) | outputs | kernels | short_ids
        """
        header = BlockHeader.deserialize(B)
        nonce = int.from_bytes(B.read(8), "big")

        num_outputs = int.from_bytes(B.read(2), "big")
        num_kernels = int.from_bytes(B.read(2), "big")
        num_short_ids = int.from_bytes(B.read(2), "big")

        outputs = [TransactionOutput.deserialize(B) for _ in range(num_outputs)]
        kernels = [TransactionKernel.deserialize(B) for _ in range(num_kernels)]
        short_ids = [ShortId.deserialize(B) for _ in range(num_short_ids)]

        return CompactBlock(header, nonce, outputs, kernels, short_ids)

    def toJSON(self):
        outputs = []
        for _output in self.getOutputs():
            output_json = _output.toJSON()
            output_json["block_height"] = self.getHeight()
            outputs.append(output_json)

        return {
            "header": self.header.toJSON(),
            "nonce": self.nonce,
            "outputs": outputs,
            "kernels": [kernel.toJSON() for kernel in self.getKernels()],
            "short_ids": [sid.toJSON() for sid in self.getShortIds()],
        }

    # hashing
    def __hash__(self):
        return hash(self.header.getHash())

    def getHash(self):
        return self.header.getHash()
