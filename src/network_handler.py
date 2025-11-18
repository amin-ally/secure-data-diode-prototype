import socket
import logging
from typing import Optional, Tuple

# Set up logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkHandler:
    """
    Handles UDP socket operations for one-way communication.

    Educational notes:
    - We use UDP because it doesn't require handshakes or acknowledgments
    - This simulates a data diode where information flows in only one direction
    - In production, you'd have separate sender/receiver machines
    """

    def __init__(self, host: str = "localhost", port: int = 5000):
        self.host = host
        self.port = port
        self.socket = None
        self.buffer_size = 65535  # Max UDP packet size

    def setup_sender(self):
        """Initialize socket for sending packets"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.info(f"Sender socket created for {self.host}:{self.port}")

    def setup_receiver(self):
        """Initialize socket for receiving packets"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        logger.info(f"Receiver listening on {self.host}:{self.port}")

    def send_packet(self, data: bytes) -> int:
        """
        Send a packet via UDP.
        Returns number of bytes sent.
        """
        if not self.socket:
            raise RuntimeError("Socket not initialized. Call setup_sender() first.")

        bytes_sent = self.socket.sendto(data, (self.host, self.port))
        logger.debug(f"Sent {bytes_sent} bytes")
        return bytes_sent

    def receive_packet(
        self, timeout: Optional[float] = None
    ) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive a packet.
        Returns (data, sender_address).
        """
        if not self.socket:
            raise RuntimeError("Socket not initialized. Call setup_receiver() first.")

        if timeout:
            self.socket.settimeout(timeout)

        data, addr = self.socket.recvfrom(self.buffer_size)
        logger.debug(f"Received {len(data)} bytes from {addr}")
        return data, addr

    def close(self):
        """Clean up socket resources"""
        if self.socket:
            self.socket.close()
            logger.info("Socket closed")
