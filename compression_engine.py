"""
compression_engine.py
Adaptive Compression Engine - LZW + Huffman
Diadaptasi dari notebook lzw_smart_storage_colab_ADAPTIVE_LZW_HUFFMAN
"""

import os
import struct
import time
import hashlib
import heapq
import numpy as np
from pathlib import Path

# ============================================================
# KONFIGURASI LZW
# ============================================================
LZW_CODE_WIDTH = 12
LZW_MAX_DICT_SIZE = 2 ** LZW_CODE_WIDTH  # 4096
LZW_MAGIC = b"LZW1"
HEADER_FMT = ">4sBIQB"  # magic, code_width, n_codes, original_size, ext_len
HEADER_FIXED_SIZE = struct.calcsize(HEADER_FMT)

# ============================================================
# KONFIGURASI HUFFMAN
# ============================================================
HUFFMAN_MAGIC = b"HUF1"
HUFFMAN_HEADER_FMT = ">4sQQ32s"  # magic, original_size, payload_bit_length, original_sha256_bytes
HUFFMAN_HEADER_FIXED_SIZE = struct.calcsize(HUFFMAN_HEADER_FMT)


# ============================================================
# LZW IMPLEMENTATION
# ============================================================
def lzw_compress_bytes_fast(data: bytes) -> list:
    """
    Kompresi LZW cepat dengan dictionary berbasis tuple.
    Tidak pernah membangun objek bytes yang tumbuh panjang di dalam loop utama.
    """
    if not data:
        return []

    dictionary = {}
    dict_get = dictionary.get
    dict_size = 256
    max_dict_size = LZW_MAX_DICT_SIZE

    result = []
    result_append = result.append

    w_code = data[0]

    for byte in data[1:]:
        key = (w_code, byte)
        code = dict_get(key)
        if code is not None:
            w_code = code
        else:
            result_append(w_code)
            if dict_size < max_dict_size:
                dictionary[key] = dict_size
                dict_size += 1
            w_code = byte

    result_append(w_code)
    return result


def lzw_decompress_codes_fast(codes: list) -> bytes:
    """
    Dekompresi LZW yang konsisten dengan lzw_compress_bytes_fast.
    Dictionary memetakan code -> bytes (untuk code >= 256).
    """
    if not codes:
        return b""

    dictionary = {}
    dict_get = dictionary.get
    dict_size = 256
    max_dict_size = LZW_MAX_DICT_SIZE

    result = bytearray()
    result_extend = result.extend

    prev = bytes([codes[0]])
    result_extend(prev)

    for k in codes[1:]:
        if k < 256:
            entry = bytes([k])
        else:
            entry = dict_get(k)
            if entry is None:
                if k == dict_size:
                    entry = prev + prev[0:1]
                else:
                    raise ValueError(f"Kode LZW tidak valid saat dekompresi: {k}")

        result_extend(entry)

        if dict_size < max_dict_size:
            dictionary[dict_size] = prev + entry[0:1]
            dict_size += 1

        prev = entry

    return bytes(result)


def pack_codes_12bit(codes: list) -> bytes:
    """
    Memadatkan list kode 12-bit menjadi byte stream memakai numpy (vectorized).
    Skema: setiap 2 kode 12-bit -> 3 byte.
    """
    n = len(codes)
    if n == 0:
        return b""

    arr = np.asarray(codes, dtype=np.uint32)
    padded = (n % 2 == 1)
    if padded:
        arr = np.append(arr, np.uint32(0))

    arr = arr.reshape(-1, 2)
    b0 = (arr[:, 0] >> 4) & 0xFF
    b1 = ((arr[:, 0] & 0xF) << 4) | ((arr[:, 1] >> 8) & 0xF)
    b2 = arr[:, 1] & 0xFF

    out = np.empty((arr.shape[0], 3), dtype=np.uint8)
    out[:, 0] = b0
    out[:, 1] = b1
    out[:, 2] = b2

    return out.tobytes()


def unpack_codes_12bit(packed: bytes, n_codes: int) -> list:
    """Membongkar byte stream hasil pack_codes_12bit kembali menjadi list kode integer."""
    if n_codes == 0:
        return []

    arr = np.frombuffer(packed, dtype=np.uint8)
    n_triplets = len(arr) // 3
    arr = arr[:n_triplets * 3].reshape(-1, 3).astype(np.uint32)

    c0 = (arr[:, 0] << 4) | (arr[:, 1] >> 4)
    c1 = ((arr[:, 1] & 0xF) << 8) | arr[:, 2]

    codes = np.empty(n_triplets * 2, dtype=np.uint32)
    codes[0::2] = c0
    codes[1::2] = c1

    return codes[:n_codes].tolist()


def compress_lzw(data: bytes) -> dict:
    """
    Mengompresi data dengan LZW dan mengembalikan dictionary hasil.
    """
    if not data:
        return {
            'data': b'',
            'original_size': 0,
            'compressed_size': 0,
            'algorithm': 'LZW'
        }

    original_size = len(data)
    original_hash = hashlib.sha256(data).digest()

    codes = lzw_compress_bytes_fast(data)
    n_codes = len(codes)
    packed = pack_codes_12bit(codes)

    header = struct.pack(HEADER_FMT, LZW_MAGIC, LZW_CODE_WIDTH, n_codes, original_size, 0)
    compressed = header + original_hash + packed

    return {
        'data': compressed,
        'original_size': original_size,
        'compressed_size': len(compressed),
        'algorithm': 'LZW',
        'n_codes': n_codes,
        'original_hash': original_hash.hex()
    }


def decompress_lzw(compressed_data: bytes) -> bytes:
    """
    Mendekompresi data LZW dan mengembalikan bytes asli.
    """
    if not compressed_data:
        return b""

    # Baca header
    magic, code_width, n_codes, original_size, ext_len = struct.unpack(
        HEADER_FMT, compressed_data[:HEADER_FIXED_SIZE]
    )

    # ✅ PERBAIKAN: Error message tanpa input_path
    if magic != LZW_MAGIC:
        raise ValueError("Data tidak valid: magic bytes LZW tidak cocok")

    offset = HEADER_FIXED_SIZE
    offset += 32  # lewati sha256 asli
    packed = compressed_data[offset:]

    codes = unpack_codes_12bit(packed, n_codes)
    data = lzw_decompress_codes_fast(codes)

    return data


# ============================================================
# HUFFMAN IMPLEMENTATION
# ============================================================
def build_huffman_codebook(data: bytes):
    """Membangun codebook Huffman: byte -> (code_int, code_length)."""
    if not data:
        return {}, [0] * 256

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    heap = []
    counter = 0
    for b, f in enumerate(freq):
        if f > 0:
            heapq.heappush(heap, (f, counter, b))
            counter += 1

    if len(heap) == 1:
        only_byte = heap[0][2]
        return {only_byte: (0, 1)}, freq

    while len(heap) > 1:
        f1, _, left = heapq.heappop(heap)
        f2, _, right = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, counter, (left, right)))
        counter += 1

    root = heap[0][2]
    codebook = {}

    def walk(node, code, length):
        if isinstance(node, int):
            codebook[node] = (code, max(length, 1))
            return
        left, right = node
        walk(left, code << 1, length + 1)
        walk(right, (code << 1) | 1, length + 1)

    walk(root, 0, 0)
    return codebook, freq


def pack_huffman_bits(data: bytes, codebook: dict):
    """Encode data memakai codebook Huffman menjadi byte payload + jumlah bit valid."""
    out = bytearray()
    buffer = 0
    nbits = 0
    total_bits = 0

    for b in data:
        code, length = codebook[b]
        buffer = (buffer << length) | code
        nbits += length
        total_bits += length
        while nbits >= 8:
            shift = nbits - 8
            out.append((buffer >> shift) & 0xFF)
            nbits -= 8
            buffer &= (1 << nbits) - 1 if nbits > 0 else 0

    if nbits > 0:
        out.append((buffer << (8 - nbits)) & 0xFF)

    return bytes(out), total_bits


def build_huffman_tree_from_freq(freq):
    """Membangun Huffman tree dari frekuensi untuk decoding."""
    heap = []
    counter = 0
    for b, f in enumerate(freq):
        if int(f) > 0:
            heapq.heappush(heap, (int(f), counter, b))
            counter += 1

    if len(heap) == 0:
        return None
    if len(heap) == 1:
        return heap[0][2]

    while len(heap) > 1:
        f1, _, left = heapq.heappop(heap)
        f2, _, right = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, counter, (left, right)))
        counter += 1

    return heap[0][2]


def unpack_huffman_bits(payload: bytes, payload_bit_length: int, freq, original_size: int) -> bytes:
    """Decode payload Huffman menjadi bytes asli."""
    if original_size == 0:
        return b""

    root = build_huffman_tree_from_freq(freq)
    if root is None:
        return b""

    if isinstance(root, int):
        return bytes([root]) * original_size

    out = bytearray()
    node = root
    bits_read = 0

    for byte in payload:
        for shift in range(7, -1, -1):
            if bits_read >= payload_bit_length:
                break
            bit = (byte >> shift) & 1
            node = node[1] if bit else node[0]
            if isinstance(node, int):
                out.append(node)
                if len(out) == original_size:
                    return bytes(out)
                node = root
            bits_read += 1

    return bytes(out)


def compress_huffman(data: bytes) -> dict:
    """
    Mengompresi data dengan Huffman dan mengembalikan dictionary hasil.
    """
    if not data:
        return {
            'data': b'',
            'original_size': 0,
            'compressed_size': 0,
            'algorithm': 'HUFFMAN'
        }

    original_size = len(data)
    original_hash = hashlib.sha256(data).digest()
    codebook, freq = build_huffman_codebook(data)
    payload, payload_bit_length = pack_huffman_bits(data, codebook) if data else (b"", 0)

    header = struct.pack(HUFFMAN_HEADER_FMT, HUFFMAN_MAGIC, original_size, payload_bit_length, original_hash)
    freq_arr = np.asarray(freq, dtype=">u4").tobytes()  # 256 x uint32 big endian

    compressed = header + freq_arr + payload

    return {
        'data': compressed,
        'original_size': original_size,
        'compressed_size': len(compressed),
        'algorithm': 'HUFFMAN',
        'payload_bit_length': payload_bit_length,
        'original_hash': original_hash.hex()
    }


def decompress_huffman(compressed_data: bytes) -> bytes:
    """
    Mendekompresi data Huffman dan mengembalikan bytes asli.
    """
    if not compressed_data:
        return b""

    # Baca header
    magic, original_size, payload_bit_length, original_hash = struct.unpack(
        HUFFMAN_HEADER_FMT, compressed_data[:HUFFMAN_HEADER_FIXED_SIZE]
    )

    # ✅ PERBAIKAN: Error message tanpa input_path
    if magic != HUFFMAN_MAGIC:
        raise ValueError("Data tidak valid: magic bytes Huffman tidak cocok")

    offset = HUFFMAN_HEADER_FIXED_SIZE
    freq_bytes = compressed_data[offset:offset + 256 * 4]
    offset += 256 * 4
    freq = np.frombuffer(freq_bytes, dtype=">u4").astype(int).tolist()
    payload = compressed_data[offset:]

    data = unpack_huffman_bits(payload, int(payload_bit_length), freq, int(original_size))

    return data


# ============================================================
# ADAPTIVE COMPRESSION ENGINE
# ============================================================
class AdaptiveCompressor:
    """
    Adaptive compression engine yang memilih LZW atau Huffman
    berdasarkan hasil kompresi terbaik (lossless).
    """
    
    def __init__(self):
        self.stats = {
            'total_files': 0,
            'total_original_size': 0,
            'total_compressed_size': 0,
            'lzw_count': 0,
            'huffman_count': 0,
            'original_count': 0,
        }

    def compress(self, data: bytes, filename: str = None) -> dict:
        """
        Kompresi adaptif - pilih algoritma terbaik.
        
        Returns:
            dict: {
                'data': bytes terkompresi,
                'original_size': int,
                'compressed_size': int,
                'algorithm': str ('LZW'/'HUFFMAN'/'ORIGINAL'),
                'compression_ratio': float,
                'space_saving': float,
                'original_hash': str,
                'filename': str,
                'is_lossless': bool,
                'lzw_result': dict,
                'huffman_result': dict
            }
        """
        if not data:
            return {
                'data': b'',
                'original_size': 0,
                'compressed_size': 0,
                'algorithm': 'ORIGINAL',
                'compression_ratio': 100.0,
                'space_saving': 0.0,
                'original_hash': '',
                'filename': filename,
                'is_lossless': True,
                'lzw_result': {'size': 0, 'lossless': True},
                'huffman_result': {'size': 0, 'lossless': True}
            }

        original_size = len(data)

        # ==========================================================
        # 1. LZW Compression
        # ==========================================================
        try:
            lzw_result = compress_lzw(data)
            lzw_size = lzw_result['compressed_size']
            lzw_data = lzw_result['data']
            
            # Verifikasi lossless
            lzw_decompressed = decompress_lzw(lzw_data)
            lzw_lossless = (lzw_decompressed == data)
        except Exception as e:
            lzw_size = original_size
            lzw_data = data
            lzw_lossless = False

        # ==========================================================
        # 2. Huffman Compression
        # ==========================================================
        try:
            huff_result = compress_huffman(data)
            huff_size = huff_result['compressed_size']
            huff_data = huff_result['data']
            
            # Verifikasi lossless
            huff_decompressed = decompress_huffman(huff_data)
            huff_lossless = (huff_decompressed == data)
        except Exception as e:
            huff_size = original_size
            huff_data = data
            huff_lossless = False

        # ==========================================================
        # 3. Select Best (pilih yang terkecil dan lossless)
        # ==========================================================
        candidates = [
            ('ORIGINAL', original_size, data, True)
        ]
        
        if lzw_lossless:
            candidates.append(('LZW', lzw_size, lzw_data, True))
        
        if huff_lossless:
            candidates.append(('HUFFMAN', huff_size, huff_data, True))
        
        # Pilih yang terkecil
        best_algorithm, best_size, best_data, is_lossless = min(
            candidates,
            key=lambda x: x[1]
        )
        
        # Jika ukuran terpilih >= original, gunakan original
        if best_size >= original_size:
            best_algorithm = 'ORIGINAL'
            best_size = original_size
            best_data = data
            is_lossless = True

        # ==========================================================
        # 4. Update Stats
        # ==========================================================
        self.stats['total_files'] += 1
        self.stats['total_original_size'] += original_size
        self.stats['total_compressed_size'] += best_size
        
        if best_algorithm == 'LZW':
            self.stats['lzw_count'] += 1
        elif best_algorithm == 'HUFFMAN':
            self.stats['huffman_count'] += 1
        else:
            self.stats['original_count'] += 1

        compression_ratio = (best_size / original_size) * 100 if original_size > 0 else 0
        space_saving = (1 - best_size / original_size) * 100 if original_size > 0 else 0

        return {
            'data': best_data,
            'original_size': original_size,
            'compressed_size': best_size,
            'algorithm': best_algorithm,
            'compression_ratio': round(compression_ratio, 2),
            'space_saving': round(space_saving, 2),
            'original_hash': hashlib.sha256(data).hexdigest(),
            'filename': filename,
            'is_lossless': is_lossless,
            'lzw_result': {
                'size': lzw_size,
                'lossless': lzw_lossless
            },
            'huffman_result': {
                'size': huff_size,
                'lossless': huff_lossless
            }
        }

    def decompress(self, data: bytes, algorithm: str) -> bytes:
        """
        Dekompresi data berdasarkan algoritma yang digunakan.
        """
        if algorithm == 'LZW':
            return decompress_lzw(data)
        elif algorithm == 'HUFFMAN':
            return decompress_huffman(data)
        else:
            return data

    def get_stats(self) -> dict:
        """Dapatkan statistik kompresi keseluruhan."""
        total = self.stats['total_original_size']
        if total == 0:
            return {**self.stats, 'overall_saving': 0, 'avg_ratio': 0}
        
        overall_saving = (1 - self.stats['total_compressed_size'] / total) * 100
        
        return {
            **self.stats,
            'overall_saving': round(overall_saving, 2),
            'avg_ratio': round(self.stats['total_compressed_size'] / total * 100, 2)
        }


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def get_file_extension(filename: str) -> str:
    """Dapatkan ekstensi file."""
    return Path(filename).suffix.lower()


def is_image_file(filename: str) -> bool:
    """Cek apakah file adalah gambar."""
    ext = get_file_extension(filename)
    return ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.webp', '.gif']


def is_text_file(filename: str) -> bool:
    """Cek apakah file adalah teks."""
    ext = get_file_extension(filename)
    return ext in ['.txt', '.json', '.xml', '.csv', '.html', '.css', '.js', '.py', '.md']


def get_file_size_str(size_bytes: int) -> str:
    """Format ukuran file menjadi string yang mudah dibaca."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


# ============================================================
# SANITY CHECK (untuk testing)
# ============================================================
if __name__ == '__main__':
    print("🧪 Running sanity check...")
    
    # Test data
    test_data = b"Hello World! This is a test for LZW and Huffman compression." * 100
    
    # Test LZW
    print("Testing LZW...")
    lzw_result = compress_lzw(test_data)
    lzw_decompressed = decompress_lzw(lzw_result['data'])
    assert lzw_decompressed == test_data, "LZW sanity check failed!"
    print(f"  ✅ LZW: {len(test_data)} -> {lzw_result['compressed_size']} bytes")
    
    # Test Huffman
    print("Testing Huffman...")
    huff_result = compress_huffman(test_data)
    huff_decompressed = decompress_huffman(huff_result['data'])
    assert huff_decompressed == test_data, "Huffman sanity check failed!"
    print(f"  ✅ Huffman: {len(test_data)} -> {huff_result['compressed_size']} bytes")
    
    # Test Adaptive
    print("Testing Adaptive Compressor...")
    compressor = AdaptiveCompressor()
    result = compressor.compress(test_data, "test.txt")
    print(f"  ✅ Adaptive: {result['algorithm']} selected")
    print(f"     Original: {result['original_size']} bytes")
    print(f"     Compressed: {result['compressed_size']} bytes")
    print(f"     Space Saving: {result['space_saving']}%")
    
    print("\n✅ All sanity checks passed!")