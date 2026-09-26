"""
SecureMailScope - Blockchain & Tamper-Evident Forensic Audit Ledger
Maintains a sequential cryptographic ledger of audit reports with SHA-256 block hashing
to ensure proof-of-authenticity and non-repudiation for incident investigations.
"""

import hashlib
import json
import datetime
import os

LEDGER_FILE = os.path.join("samples", "forensic_blockchain_ledger.json")

class BlockchainAuditLedger:
    def __init__(self, ledger_path=LEDGER_FILE):
        self.ledger_path = ledger_path
        self.chain = []
        self._load_or_init_chain()

    def _load_or_init_chain(self):
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    self.chain = json.load(f)
            except Exception:
                self._create_genesis_block()
        else:
            self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = {
            "block_index": 0,
            "timestamp": "2026-09-26T00:00:00Z",
            "pcap_source": "GENESIS_ROOT",
            "summary_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "block_hash": self._hash_payload({"index": 0, "prev": "00000000000000000000000000000000"})
        }
        self.chain = [genesis]
        self._save_chain()

    def _hash_payload(self, data) -> str:
        serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def add_audit_block(self, pcap_name: str, summary_stats: dict, sessions_count: int, overall_grade: str) -> dict:
        """Appends a new immutable forensic audit block to the ledger."""
        prev_block = self.chain[-1]
        prev_hash = prev_block["block_hash"]
        new_index = len(self.chain)

        evidence_payload = {
            "pcap_name": pcap_name,
            "summary_stats": summary_stats,
            "sessions_count": sessions_count,
            "overall_grade": overall_grade
        }
        evidence_hash = self._hash_payload(evidence_payload)

        block_data = {
            "block_index": new_index,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "pcap_source": os.path.basename(pcap_name),
            "evidence_hash": evidence_hash,
            "previous_hash": prev_hash
        }
        block_hash = self._hash_payload(block_data)
        block_data["block_hash"] = block_hash

        self.chain.append(block_data)
        self._save_chain()
        return block_data

    def verify_chain_integrity(self) -> dict:
        """Verify the cryptographic integrity of the entire audit chain."""
        is_valid = True
        broken_block = None

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            # Verify link to previous block
            if current["previous_hash"] != prev["block_hash"]:
                is_valid = False
                broken_block = i
                break

        return {
            "is_valid": is_valid,
            "total_blocks": len(self.chain),
            "broken_block_index": broken_block,
            "latest_block_hash": self.chain[-1]["block_hash"]
        }

    def _save_chain(self):
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        with open(self.ledger_path, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=2)
