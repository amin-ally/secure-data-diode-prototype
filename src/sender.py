# src/sender.py
import time
import logging
from src.packet_format import PacketHeader
from src.network_handler import NetworkHandler
from src.file_handler import FileChunker
from src.crypto_utils import CryptoUtils


class Sender:
    def __init__(self, host="localhost", port=5000, chunk_size=1024):
        self.network = NetworkHandler(host, port)
        self.chunker = FileChunker(chunk_size)
        self.crypto = CryptoUtils()
        self.logger = logging.getLogger("Sender")

    def send_file(self, filepath: str):
        file_id = self.chunker.generate_file_id()
        self.logger.info(f"Starting encrypted transfer: {filepath}")
        self.network.setup_sender()

        try:
            for chunk, seq_num, total in self.chunker.read_file_chunks(filepath):
                # 1. Encrypt
                aad = str(seq_num).encode()
                encrypted_payload = self.crypto.encrypt(chunk, associated_data=aad)

                # 2. Prepare Header
                header = PacketHeader(
                    version=1,
                    file_id=file_id,
                    sequence_num=seq_num,
                    total_packets=total,
                    timestamp=int(time.time() * 1000000),
                    payload_size=len(encrypted_payload),
                    crc_checksum=0,  # Not implemented yet
                    hmac_signature=b"\x00" * 32,
                )

                # 3. Sign (Header + Encrypted Payload)
                header_bytes = header.pack_without_hmac()
                header.hmac_signature = self.crypto.compute_hmac(
                    header_bytes + encrypted_payload
                )

                # 4. Send
                self.network.send_packet(header.pack() + encrypted_payload)

                time.sleep(0.005)
                if seq_num % 10 == 0:
                    self.logger.info(f"Sent encrypted packet {seq_num + 1}/{total}")

        finally:
            self.network.close()
