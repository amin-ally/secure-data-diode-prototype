# src/sender.py
import time
import logging
from src.packet_format import PacketHeader
from src.network_handler import NetworkHandler
from src.file_handler import FileChunker


class Sender:
    """
    Main sender agent that orchestrates file transfer.
    """

    def __init__(self, host="localhost", port=5000, chunk_size=1024):
        self.network = NetworkHandler(host, port)
        self.chunker = FileChunker(chunk_size)
        self.logger = logging.getLogger(__name__)

    def send_file(self, filepath: str):
        """
        Main method to send a file.
        For now, sends unencrypted chunks (encryption in Step 3).
        """
        # Generate unique file ID for this transfer
        file_id = self.chunker.generate_file_id()
        self.logger.info(f"Starting transfer of {filepath} with ID {file_id.hex()}")

        # Create sender socket
        self.network.setup_sender()

        try:
            # Send each chunk as a packet
            for chunk, seq_num, total in self.chunker.read_file_chunks(filepath):
                # Create packet header
                header = PacketHeader(
                    version=1,
                    file_id=file_id,
                    sequence_num=seq_num,
                    total_packets=total,
                    timestamp=int(time.time() * 1000000),  # Microsecond timestamp
                    payload_size=len(chunk),
                    crc_checksum=0,  # Will add in Step 4
                    hmac_signature=b"\x00" * 32,  # Placeholder, will add in Step 3
                )

                # Combine header and payload
                packet = header.pack() + chunk

                # Send packet
                self.network.send_packet(packet)
                self.logger.info(f"Sent packet {seq_num + 1}/{total}")

                # Small delay to avoid overwhelming receiver
                time.sleep(0.01)

        finally:
            self.network.close()
            self.logger.info("Transfer complete")
