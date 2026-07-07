"""
compression_engine.py
Adaptive Compression Engine - LZW + Huffman
Dengan deteksi file terkompresi dan entropy analysis
"""

import os
import struct
import time
import hashlib
import heapq
import numpy as np
from pathlib import Path
from collections import Counter

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
# FILE TYPE DETECTION & ENTROPY ANALYSIS
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
    return ext in ['.txt', '.json', '.xml', '.csv', '.html', '.css', '.js', '.py', '.md', '.log']


def get_file_size_str(size_bytes: int) -> str:
    """Format ukuran file menjadi string yang mudah dibaca."""
    if size_bytes == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def calculate_entropy(data: bytes) -> float:
    """
    Hitung entropy Shannon dari data.
    Entropy tinggi (7.5+) mengindikasikan data sudah terkompresi atau terenkripsi.
    """
    if not data:
        return 0.0
    
    # Gunakan Counter untuk frekuensi
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in freq.values():
        if count > 0:
            p = count / length
            # Gunakan math.log2 untuk akurasi
            import math
            entropy -= p * math.log2(p)
    
    return entropy


def is_pre_compressed(data: bytes, filename: str = None) -> tuple:
    """
    Deteksi apakah file sudah terkompresi.
    Returns: (is_compressed, reason, confidence)
    """
    if not data or len(data) < 100:
        return (False, "File terlalu kecil untuk deteksi", 0.0)
    
    # ==========================================================
    # 1. CEK EKSTENSI FILE
    # ==========================================================
    if filename:
        ext = get_file_extension(filename)
        
        # Format yang sudah terkompresi (lossy atau lossless)
        compressed_exts = {
            '.pdf': 'PDF (sudah terkompresi)',
            '.zip': 'ZIP archive',
            '.gz': 'GZIP archive',
            '.rar': 'RAR archive',
            '.7z': '7-Zip archive',
            '.bz2': 'BZIP2 archive',
            '.xz': 'XZ archive',
            '.tar': 'TAR archive (bisa dikompresi)',
            '.jar': 'Java archive',
            '.war': 'Web archive',
            '.ear': 'Enterprise archive',
            '.jpg': 'JPEG image (lossy)',
            '.jpeg': 'JPEG image (lossy)',
            '.png': 'PNG image (lossless)',
            '.gif': 'GIF image',
            '.webp': 'WebP image',
            '.bmp': 'BMP image (bisa dikompresi)',
            '.tiff': 'TIFF image',
            '.tif': 'TIFF image',
            '.mp3': 'MP3 audio',
            '.mp4': 'MP4 video',
            '.avi': 'AVI video',
            '.mkv': 'MKV video',
            '.mov': 'MOV video',
            '.wmv': 'WMV video',
            '.flv': 'FLV video',
            '.docx': 'Word document (ZIP)',
            '.xlsx': 'Excel spreadsheet (ZIP)',
            '.pptx': 'PowerPoint presentation (ZIP)',
            '.odt': 'OpenDocument text (ZIP)',
            '.ods': 'OpenDocument spreadsheet (ZIP)',
            '.odp': 'OpenDocument presentation (ZIP)',
        }
        
        if ext in compressed_exts:
            return (True, compressed_exts[ext], 0.95)
    
    # ==========================================================
    # 2. CEK MAGIC BYTES
    # ==========================================================
    magic_map = {
        b'PK\x03\x04': ('ZIP archive / Office file', 0.99),
        b'PK\x05\x06': ('ZIP archive (empty)', 0.99),
        b'PK\x07\x08': ('ZIP archive (spanned)', 0.99),
        b'%PDF': ('PDF document', 0.98),
        b'\x89PNG\x0d\x0a\x1a\x0a': ('PNG image', 0.99),
        b'\xff\xd8\xff': ('JPEG image', 0.99),
        b'GIF8': ('GIF image', 0.99),
        b'BM': ('BMP image', 0.90),
        b'RIFF': ('RIFF container (AVI/WAV)', 0.85),
        b'ID3': ('MP3 audio', 0.95),
        b'\x1f\x8b': ('GZIP archive', 0.99),
        b'BZh': ('BZIP2 archive', 0.99),
        b'\xfd7zXZ': ('XZ archive', 0.99),
        b'Rar!': ('RAR archive', 0.99),
        b'7z\xbc\xaf\x27\x1c': ('7-Zip archive', 0.99),
        b'\x00\x00\x01\xba': ('MPEG video', 0.85),
        b'\x00\x00\x01\xb3': ('MPEG video', 0.85),
        b'ftyp': ('MP4/MOV video', 0.85),
        b'\x00\x00\x00\x18ftyp': ('MP4 video', 0.85),
        b'\x00\x00\x00\x1cftyp': ('MP4 video', 0.85),
        b'\x00\x00\x00\x20ftyp': ('MP4 video', 0.85),
    }
    
    for magic, (name, confidence) in magic_map.items():
        if data.startswith(magic):
            return (True, name, confidence)
    
    # ==========================================================
    # 3. CEK ENTROPY (untuk data yang sudah dikompresi)
    # ==========================================================
    # Ambil sampel untuk efisiensi (maks 1MB)
    sample = data[:min(len(data), 1024 * 1024)]
    entropy = calculate_entropy(sample)
    
    # Entropy threshold:
    # - < 5.0: Data terstruktur (teks, code) → baik untuk kompresi
    # - 5.0 - 7.0: Data semi-terstruktur → mungkin kompresi
    # - > 7.5: Data acak (terkompresi/terenkripsi) → tidak efektif
    if entropy > 7.5:
        return (True, f"Entropy tinggi ({entropy:.2f}) - data sudah terkompresi/terenkripsi", 0.90)
    elif entropy > 7.0:
        return (True, f"Entropy sedang-tinggi ({entropy:.2f}) - kemungkinan terkompresi", 0.70)
    
    # ==========================================================
    # 4. CEK REPETISI UNTUK FILE TEKS
    # ==========================================================
    # Jika file teks, cek karakter yang sering muncul
    if filename and is_text_file(filename):
        # Cek rasio karakter unik
        unique_chars = len(set(data[:min(len(data), 10000)]))
        if len(data) > 100 and unique_chars / len(data[:min(len(data), 10000)]) > 0.8:
            return (False, "Teks dengan variasi tinggi - masih bisa dikompresi", 0.50)
    
    return (False, "Data dapat dikompresi", 0.95)


def should_compress(data: bytes, filename: str = None) -> dict:
    """
    Evaluasi apakah kompresi bermanfaat.
    Returns: dict dengan rekomendasi
    """
    if not data or len(data) < 100:
        return {
            'compress': False,
            'reason': 'File terlalu kecil (minimal 100 bytes)',
            'recommended': 'store_original',
            'confidence': 1.0,
            'message': 'File terlalu kecil untuk kompresi yang berarti'
        }
    
    is_compressed, reason, confidence = is_pre_compressed(data, filename)
    
    if is_compressed:
        return {
            'compress': False,
            'reason': reason,
            'recommended': 'store_original',
            'confidence': confidence,
            'message': f'File sudah terkompresi ({reason}). Kompresi tidak akan efektif.'
        }
    
    # Cek ukuran minimum untuk kompresi efektif
    if len(data) < 500:
        return {
            'compress': True,
            'reason': 'Ukuran kecil tapi tetap bisa dikompresi',
            'recommended': 'adaptive',
            'confidence': 0.70,
            'message': 'File kecil - kompresi mungkin memberikan sedikit penghematan'
        }
    
    return {
        'compress': True,
        'reason': 'Data dapat dikompresi secara efektif',
        'recommended': 'adaptive',
        'confidence': confidence,
        'message': 'File siap dikompresi'
    }


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
    """Memadatkan list kode 12-bit menjadi byte stream memakai numpy."""
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
    """Membongkar byte stream hasil pack_codes_12bit."""
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
    """Mengompresi data dengan LZW."""
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
    """Mendekompresi data LZW."""
    if not compressed_data:
        return b""

    # Baca header
    magic, code_width, n_codes, original_size, ext_len = struct.unpack(
        HEADER_FMT, compressed_data[:HEADER_FIXED_SIZE]
    )

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
    """Membangun codebook Huffman."""
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
    """Encode data memakai codebook Huffman."""
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
    """Decode payload Huffman."""
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
    """Mengompresi data dengan Huffman."""
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
    """Mendekompresi data Huffman."""
    if not compressed_data:
        return b""

    # Baca header
    magic, original_size, payload_bit_length, original_hash = struct.unpack(
        HUFFMAN_HEADER_FMT, compressed_data[:HUFFMAN_HEADER_FIXED_SIZE]
    )

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
            'skipped_count': 0,  # File yang dilewati (sudah terkompresi)
        }

    def compress(self, data: bytes, filename: str = None) -> dict:
        """
        Kompresi adaptif - pilih algoritma terbaik.
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
                'huffman_result': {'size': 0, 'lossless': True},
                'skipped': False,
                'skip_reason': ''
            }

        original_size = len(data)

        # ==========================================================
        # CEK APAKAH FILE SUDAH TERKOMPRESI
        # ==========================================================
        compress_check = should_compress(data, filename)
        
        if not compress_check['compress']:
            self.stats['total_files'] += 1
            self.stats['total_original_size'] += original_size
            self.stats['total_compressed_size'] += original_size
            self.stats['skipped_count'] += 1
            
            return {
                'data': data,
                'original_size': original_size,
                'compressed_size': original_size,
                'algorithm': 'ORIGINAL',
                'compression_ratio': 100.0,
                'space_saving': 0.0,
                'original_hash': hashlib.sha256(data).hexdigest(),
                'filename': filename,
                'is_lossless': True,
                'lzw_result': {'size': original_size, 'lossless': True},
                'huffman_result': {'size': original_size, 'lossless': True},
                'skipped': True,
                'skip_reason': compress_check['message']
            }

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

        # Hitung SASADA Score (efficiency rating)
        sasada_score = self._calculate_sasada_score(original_size, best_size, best_algorithm)

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
            },
            'skipped': False,
            'skip_reason': '',
            'sasada_score': sasada_score
        }

    def _calculate_sasada_score(self, original_size: int, compressed_size: int, algorithm: str) -> int:
        """
        Hitung SASADA Score (0-100) berdasarkan efisiensi kompresi.
        """
        if original_size == 0:
            return 0
        
        saving = (1 - compressed_size / original_size) * 100
        
        # Base score berdasarkan space saving
        if saving <= 0:
            base_score = 0
        elif saving < 10:
            base_score = 20
        elif saving < 25:
            base_score = 40
        elif saving < 50:
            base_score = 60
        elif saving < 75:
            base_score = 80
        else:
            base_score = 95
        
        # Bonus untuk algoritma tertentu
        algorithm_bonus = {
            'LZW': 5 if saving > 20 else 0,
            'HUFFMAN': 5 if saving > 20 else 0,
            'ORIGINAL': 0
        }.get(algorithm, 0)
        
        # Bonus untuk file yang sangat besar (>1MB)
        size_bonus = 5 if original_size > 1024 * 1024 else 0
        
        score = min(100, base_score + algorithm_bonus + size_bonus)
        return score

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
# SANITY CHECK (untuk testing)
# ============================================================
if __name__ == '__main__':
    print(" Running sanity check...")
    
    # Test data
    test_data = b"Hello World! This is a test for LZW and Huffman compression." * 100
    
    # Test LZW
    print("Testing LZW...")
    lzw_result = compress_lzw(test_data)
    lzw_decompressed = decompress_lzw(lzw_result['data'])
    assert lzw_decompressed == test_data, "LZW sanity check failed!"
    print(f" LZW: {len(test_data)} -> {lzw_result['compressed_size']} bytes")
    
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
    
    # Test file detection
    print("\nTesting file detection...")
    
    # Test dengan data PDF simulasi
    pdf_data = b"%PDF-1.4\n%some pdf content" + test_data[:500]
    check = should_compress(pdf_data, "test.pdf")
    print(f"  PDF detection: compress={check['compress']}, reason={check['reason']}")
    
    # Test dengan data teks biasa
    check = should_compress(test_data, "test.txt")
    print(f"  Text detection: compress={check['compress']}, reason={check['reason']}")
    
    # Test dengan data acak (entropy tinggi)
    import random
    random_data = bytes([random.randint(0, 255) for _ in range(1000)])
    check = should_compress(random_data, "random.bin")
    print(f"  Random data: compress={check['compress']}, reason={check['reason']}")
    
    print("\n✅ All sanity checks passed!")