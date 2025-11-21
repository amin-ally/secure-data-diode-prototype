# demo_transfer.py
import threading
import time
import os
import logging
from src.sender import Sender
from src.receiver import Receiver

# Configure logging to show the flow
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Demo")


def run_secure_demo():
    input_file = "confidential_doc.txt"
    output_file = "received_doc.txt"

    # 1. Create a dummy "Confidential" file
    logger.info("--- Step 1: Generating Confidential Data ---")
    with open(input_file, "wb") as f:
        f.write(b"TOP SECRET DATA: " * 500)  # 8.5KB file

    # 2. Start Receiver (Background Thread)
    logger.info("--- Step 2: Starting Secure Receiver ---")
    receiver = Receiver(port=9999)
    rx_thread = threading.Thread(target=receiver.receive_file, args=(output_file,))
    rx_thread.daemon = True
    rx_thread.start()
    time.sleep(0.5)  # Allow bind

    # 3. Start Sender
    logger.info("--- Step 3: Starting Secure Sender ---")
    sender = Sender(port=9999)
    sender.send_file(input_file)

    # 4. Wait and Verify
    rx_thread.join(timeout=5)

    logger.info("--- Step 4: Verifying Integrity ---")
    if os.path.exists(output_file):
        with open(input_file, "rb") as f1, open(output_file, "rb") as f2:
            if f1.read() == f2.read():
                logger.info("✅ SUCCESS: File decrypted and authenticated correctly.")
            else:
                logger.error("❌ FAILURE: Content mismatch (Decryption failed).")
    else:
        logger.error("❌ FAILURE: File not received.")

    # Cleanup
    for f in [input_file, output_file]:
        if os.path.exists(f):
            os.remove(f)


if __name__ == "__main__":
    run_secure_demo()
