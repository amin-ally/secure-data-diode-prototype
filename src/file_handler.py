# src/file_handler.py
import os
import uuid
from typing import Generator, Tuple
from pathlib import Path


class FileChunker:
    """
    Responsible for breaking files into manageable chunks.
    """

    def __init__(self, chunk_size: int = 1024):
        """
        Initialize with chunk size.
        1024 bytes is small enough to fit in UDP packets with overhead.
        """
        self.chunk_size = chunk_size

    def read_file_chunks(
        self, filepath: str
    ) -> Generator[Tuple[bytes, int, int], None, None]:
        """
        Generator that yields file chunks.
        Returns: (chunk_data, chunk_number, total_chunks)

        Generators are memory-efficient for large files.
        """
        file_size = os.path.getsize(filepath)
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        with open(filepath, "rb") as file:
            chunk_num = 0
            while True:
                chunk = file.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk, chunk_num, total_chunks
                chunk_num += 1

    def generate_file_id(self) -> bytes:
        """Generate a unique identifier for this file transfer"""
        return uuid.uuid4().bytes  # 16 bytes

    def ensure_file_exists(self, filepath: str):
        """Create an empty file if it doesn't exist."""
        if not os.path.exists(filepath):
            with open(filepath, "wb") as f:
                pass

    def save_chunk(self, filepath: str, chunk: bytes, offset: int):
        """
        Save a chunk to a specific offset in the file.
        Uses r+b to allow seeking without truncating.
        """
        self.ensure_file_exists(filepath)

        with open(filepath, "r+b") as file:
            file.seek(offset)
            file.write(chunk)
