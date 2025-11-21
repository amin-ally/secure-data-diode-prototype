# src/sender.py
import time
import logging
import zlib
from reedsolo import RSCodec, ReedSolomonError
from src.packet_format import PacketHeader
from src.network_handler import NetworkHandler
from src.file_handler import FileChunker
from src.crypto_utils import CryptoUtils


class Sender:
    def __init__(self, host="localhost", port=5000, chunk_size=1024):
        self.network = NetworkHandler(host, port)
        self.chunker = FileChunker(chunk_size)
        self.crypto = CryptoUtils()
        self.rsc = RSCodec(10)
        self.logger = logging.getLogger("Sender")

    def send_file(self, filepath: str):
        file_id = self.chunker.generate_file_id()
        self.logger.info(f"Starting secure transfer: {filepath}")
        self.network.setup_sender()

        try:
            for chunk, seq_num, total in self.chunker.read_file_chunks(filepath):
                # 1. Encrypt
                aad = str(seq_num).encode()
                encrypted_payload = self.crypto.encrypt(chunk, associated_data=aad)

                # 2. Apply FEC (Encode the encrypted payload)
                # We do this EARLY so we can calculate the final size and CRC
                fec_payload = self.rsc.encode(encrypted_payload)

                # 3. Calculate CRC32 on the final wire payload
                crc = zlib.crc32(fec_payload)

                # 4. Create Header (Now with the CORRECT CRC and SIZE)
                header = PacketHeader(
                    version=1,
                    file_id=file_id,
                    sequence_num=seq_num,
                    total_packets=total,
                    timestamp=int(time.time() * 1000000),
                    payload_size=len(fec_payload),
                    crc_checksum=crc,  # CRC is set BEFORE signing
                    hmac_signature=b"\x00" * 32,
                )

                # 5. Sign the Packet
                # We sign: Header(includes CRC) + EncryptedPayload
                # Note: We sign the EncryptedPayload (without FEC parity) to ensure
                # we are verifying the data content, not the transmission wrapper.
                header_bytes = header.pack_without_hmac()
                header.hmac_signature = self.crypto.compute_hmac(
                    header_bytes + encrypted_payload
                )

                # 6. Send
                self.network.send_packet(header.pack() + fec_payload)

                time.sleep(0.005)

        finally:
            self.network.close()
