# src/receiver.py
import logging
from reedsolo import RSCodec, ReedSolomonError
from cryptography.exceptions import InvalidTag
from src.packet_format import PacketHeader
from src.network_handler import NetworkHandler
from src.crypto_utils import CryptoUtils
from src.file_handler import FileChunker

import os


class Receiver:
    def __init__(self, host="localhost", port=5000):
        self.network = NetworkHandler(host, port)
        self.crypto = CryptoUtils()
        self.rsc = RSCodec(10)
        self.chunker = FileChunker()
        self.logger = logging.getLogger("Receiver")
        self.active_transfers = {}

    def receive_file(self, output_dir: str = "."):
        self.network.setup_receiver()
        self.logger.info(f"Listening on {self.network.host}:{self.network.port}")

        try:
            while True:
                data, addr = self.network.receive_packet()
                if not data:
                    continue

                try:
                    header = PacketHeader.unpack(data)
                    raw_fec_payload = data[PacketHeader.HEADER_SIZE :]

                    # 1. FEC Decode (Fix Errors FIRST)
                    try:
                        # .decode returns [decoded_data, decoded_data_with_ecc, err_indices]
                        # We just want the first element (the original encrypted_payload)
                        encrypted_payload = self.rsc.decode(raw_fec_payload)[0]
                    except ReedSolomonError:
                        self.logger.error(f"FEC Failed: Too many errors from {addr}")
                        continue

                    # 2. Verify HMAC (On the fixed data)
                    header_clean = header.pack_without_hmac()
                    if not self.crypto.verify_hmac(
                        header_clean + encrypted_payload, header.hmac_signature
                    ):
                        self.logger.critical(
                            f"HMAC Failure: Tampering detected from {addr}"
                        )
                        continue

                    # 3. Decrypt
                    aad = str(header.sequence_num).encode()
                    decrypted_chunk = self.crypto.decrypt(
                        encrypted_payload, associated_data=aad
                    )

                    # 4. Store to Disk
                    fid = header.file_id.hex()
                    temp_path = f"{output_dir}/{fid}.part"

                    # Calculate offset
                    offset = header.sequence_num * header.original_chunk_size

                    # Write immediately
                    self.chunker.save_chunk(temp_path, decrypted_chunk, offset)

                    # Update State
                    if fid not in self.active_transfers:
                        self.active_transfers[fid] = {
                            "received_seqs": set(),
                            "total": header.total_packets,
                            "path": temp_path,
                        }

                    self.active_transfers[fid]["received_seqs"].add(header.sequence_num)

                    # Check Completion
                    if (
                        len(self.active_transfers[fid]["received_seqs"])
                        == header.total_packets
                    ):
                        self.logger.info(f"Transfer Complete: {fid}")
                        # Rename .part to final (In real app, get filename from metadata packet)
                        final_path = f"{output_dir}/received_{fid}.dat"
                        os.rename(temp_path, final_path)
                        del self.active_transfers[fid]
                        # Removed the 'break' so it keeps listening

                except InvalidTag:
                    self.logger.error("Decryption Failed")
                except Exception as e:
                    self.logger.error(f"Error: {e}")

        finally:
            self.network.close()

    def reassemble_file(self, file_id: str, output_path: str):
        with open(output_path, "wb") as f:
            for seq in sorted(self.received_packets[file_id].keys()):
                f.write(self.received_packets[file_id][seq])
        self.logger.info("File saved.")
