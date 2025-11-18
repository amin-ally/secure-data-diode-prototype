# src/receiver.py
import logging
from src.packet_format import PacketHeader
from src.network_handler import NetworkHandler


class Receiver:
    """
    Main receiver agent that listens for and reassembles files.
    """

    def __init__(self, host="localhost", port=5000):
        self.network = NetworkHandler(host, port)
        self.logger = logging.getLogger(__name__)
        self.received_packets = {}  # file_id -> {seq_num: data}

    def receive_file(self, output_path: str, expected_packets: int = None):
        """
        Listen for packets and reassemble file.
        """
        self.network.setup_receiver()
        self.logger.info(f"Listening on {self.network.host}:{self.network.port}")

        try:
            while True:
                # Receive packet
                packet_data, sender = self.network.receive_packet()

                if not packet_data:
                    continue

                # Parse header
                header = PacketHeader.unpack(packet_data)
                payload = packet_data[PacketHeader.HEADER_SIZE :]

                # Store packet (organize by file_id for concurrent transfers)
                file_id_hex = header.file_id.hex()
                if file_id_hex not in self.received_packets:
                    self.received_packets[file_id_hex] = {}
                    self.logger.info(f"New file transfer detected: {file_id_hex}")

                self.received_packets[file_id_hex][header.sequence_num] = payload
                self.logger.info(
                    f"Received packet {header.sequence_num + 1}/{header.total_packets}"
                )

                # Check if we have all packets
                if len(self.received_packets[file_id_hex]) == header.total_packets:
                    self.reassemble_file(file_id_hex, output_path)
                    break

        except KeyboardInterrupt:
            self.logger.info("Receive interrupted by user")
        finally:
            self.network.close()

    def reassemble_file(self, file_id: str, output_path: str):
        """
        Reassemble packets into original file.
        """
        packets = self.received_packets[file_id]

        with open(output_path, "wb") as file:
            # Write packets in sequence order
            for seq_num in sorted(packets.keys()):
                file.write(packets[seq_num])

        self.logger.info(f"File reassembled and saved to {output_path}")
