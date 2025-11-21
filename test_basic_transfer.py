# demo_transfer.py
import threading
import time
import os
import logging
import random
from src.sender import Sender
from src.receiver import Receiver
from src.packet_format import PacketHeader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Demo")


def corrupt_data(data: bytes) -> bytes:
    """
    Simulates network noise by flipping a bit in the payload.
    We target the payload (after the header) to test FEC.
    """
    # Only corrupt randomly (e.g., 20% chance)
    if random.random() > 0.2:
        return data

    data_array = bytearray(data)
    # Target a byte in the payload area (Header is roughly 70-80 bytes)
    if len(data_array) > 100:
        target_idx = random.randint(80, len(data_array) - 1)
        original = data_array[target_idx]

        # Flip bits (XOR with 0xFF)
        data_array[target_idx] ^= 0xFF

        logger.warning(f"⚡ SIMULATED NOISE: Corrupted byte at index {target_idx}")

    return bytes(data_array)


def run_resilient_demo():
    input_file = "mission_critical.dat"
    output_file = "recovered_mission.dat"

    # 1. Create Dummy File
    with open(input_file, "wb") as f:
        # Create enough data to force multiple packets
        f.write(os.urandom(1024 * 50))
    logger.info(f"Generated {input_file} (50KB)")

    # 2. Start Receiver
    receiver = Receiver(port=9999)
    rx_thread = threading.Thread(target=receiver.receive_file, args=(output_file,))
    rx_thread.daemon = True
    rx_thread.start()
    time.sleep(0.5)

    # 3. Setup Sender with Noise Simulation
    sender = Sender(port=9999)

    # --- MONKEY PATCHING ---
    # We intercept the network send to inject errors
    real_send_packet = sender.network.send_packet

    def noisy_send_packet(data):
        corrupted = corrupt_data(data)
        return real_send_packet(corrupted)

    sender.network.send_packet = noisy_send_packet
    # -----------------------

    logger.info(
        "Starting transfer with Simulated Network Noise (20% packet corruption)..."
    )
    sender.send_file(input_file)

    # 4. Verify
    rx_thread.join(timeout=10)

    if os.path.exists(output_file):
        in_hash = hash(open(input_file, "rb").read())
        out_hash = hash(open(output_file, "rb").read())

        if in_hash == out_hash:
            logger.info(
                "✅ SUCCESS: File recovered perfectly despite network corruption!"
            )
            logger.info("   (Reed-Solomon FEC successfully corrected the bit flips)")
        else:
            logger.error("❌ FAILURE: File corrupted beyond repair.")
    else:
        logger.error("❌ FAILURE: Output file not created.")


if __name__ == "__main__":
    run_resilient_demo()
