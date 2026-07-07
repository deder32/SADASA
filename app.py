"""
app.py
SASADA - Saving Space Data
Adaptive Compression dengan LZW + Huffman
"""

import os
import uuid
import json
import base64
import hashlib 
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, url_for, send_file, Response
from werkzeug.utils import secure_filename
from compression_engine import (
    AdaptiveCompressor, 
    decompress_lzw, 
    decompress_huffman,
    is_image_file,
    is_text_file,
    get_file_size_str,
    get_file_extension,
    should_compress,  
    calculate_entropy, 
    is_pre_compressed  
)

# ============================================================
# KONFIGURASI
# ============================================================
BASE_DIR = Path(__file__).parent

# Folder untuk menyimpan file
UPLOAD_FOLDER = BASE_DIR / 'uploads'          # Temporary upload
COMPRESSED_FOLDER = BASE_DIR / 'compressed'   # File .lzw / .huff
DECOMPRESSED_FOLDER = BASE_DIR / 'decompressed' # Hasil dekompresi
HISTORY_FILE = BASE_DIR / 'history.json'      # History data

# Buat folder jika belum ada
for folder in [UPLOAD_FOLDER, COMPRESSED_FOLDER, DECOMPRESSED_FOLDER]:
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)

# Inisialisasi compressor
compressor = AdaptiveCompressor()

# Ekstensi file yang diizinkan
ALLOWED_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.webp', '.gif',
    '.zip', '.gz', '.mp3', '.mp4', '.avi', '.mkv',
    '.json', '.xml', '.csv', '.html', '.css', '.js', '.py', '.md',
    '.log', '.csv', '.tsv', '.rtf'
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def allowed_file(filename: str) -> bool:
    """Cek apakah ekstensi file diizinkan."""
    return get_file_extension(filename) in ALLOWED_EXTENSIONS


def load_history() -> list:
    """Load history dari file JSON."""
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except:
                return []
    return []


def save_history(entry: dict):
    """Save history ke file JSON."""
    history = load_history()
    history.append(entry)
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def index():
    """Halaman utama SASADA."""
    history = load_history()[-20:]  # 20 history terakhir
    stats = compressor.get_stats()
    
    # Konversi ukuran untuk display
    stats_display = {
        **stats,
        'total_original_size_mb': round(stats['total_original_size'] / (1024*1024), 2),
        'total_compressed_size_mb': round(stats['total_compressed_size'] / (1024*1024), 2)
    }
    
    return render_template(
        'index.html', 
        history=history, 
        stats=stats_display,
        allowed_extensions=sorted(ALLOWED_EXTENSIONS)
    )


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload dan kompresi file dengan SASADA.
    File akan disimpan sebagai .lzw atau .huff di folder compressed.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed'}), 400

    try:
        # Baca file
        file_data = file.read()
        original_filename = secure_filename(file.filename)
        file_extension = get_file_extension(original_filename)
        file_id = str(uuid.uuid4())[:8]

        # ==========================================================
        # CEK APAKAH FILE SUDAH TERKOMPRESI SEBELUM KOMPRESI
        # ==========================================================
        compress_check = should_compress(file_data, original_filename)
        
        if not compress_check['compress']:
            # File sudah terkompresi - simpan sebagai original
            compressed_filename = f"{file_id}_{original_filename}"
            compressed_path = COMPRESSED_FOLDER / f"{compressed_filename}.original"
            
            # Simpan file asli
            with open(compressed_path, 'wb') as f:
                f.write(file_data)
            
            # Simpan ke history
            history_entry = {
                'id': file_id,
                'filename': original_filename,
                'extension': file_extension,
                'original_size': len(file_data),
                'original_size_str': get_file_size_str(len(file_data)),
                'compressed_size': len(file_data),
                'compressed_size_str': get_file_size_str(len(file_data)),
                'algorithm': 'ORIGINAL',
                'compression_ratio': 100.0,
                'space_saving': 0.0,
                'is_lossless': True,
                'timestamp': datetime.now().isoformat(),
                'lzw_size': len(file_data),
                'lzw_lossless': True,
                'huffman_size': len(file_data),
                'huffman_lossless': True,
                'compressed_path': str(compressed_path),
                'original_hash': hashlib.sha256(file_data).hexdigest(),
                'sasada_score': 0,
                'skipped': True,
                'skip_reason': compress_check['message']
            }
            save_history(history_entry)
            
            return jsonify({
                'success': True,
                'file_id': file_id,
                'filename': original_filename,
                'original_size': get_file_size_str(len(file_data)),
                'compressed_size': get_file_size_str(len(file_data)),
                'algorithm': 'ORIGINAL',
                'compression_ratio': 100.0,
                'space_saving': 0.0,
                'is_lossless': True,
                'skipped': True,
                'skip_reason': compress_check['message'],
                'entropy': round(calculate_entropy(file_data[:min(len(file_data), 1024*1024)]), 2),
                'download_url': url_for('download_file', file_id=file_id)
            })

        # ==========================================================
        # KOMPRESI ADAPTIF DENGAN SASADA
        # ==========================================================
        result = compressor.compress(file_data, original_filename)

        # ==========================================================
        # SIMPAN FILE TERKOMPRESI
        # ==========================================================
        compressed_filename = f"{file_id}_{original_filename}"
        compressed_path = COMPRESSED_FOLDER / f"{compressed_filename}.{result['algorithm'].lower()}"
        
        with open(compressed_path, 'wb') as f:
            f.write(result['data'])

        # ==========================================================
        # SIMPAN KE HISTORY
        # ==========================================================
        history_entry = {
            'id': file_id,
            'filename': original_filename,
            'extension': file_extension,
            'original_size': result['original_size'],
            'original_size_str': get_file_size_str(result['original_size']),
            'compressed_size': result['compressed_size'],
            'compressed_size_str': get_file_size_str(result['compressed_size']),
            'algorithm': result['algorithm'],
            'compression_ratio': result['compression_ratio'],
            'space_saving': result['space_saving'],
            'is_lossless': result['is_lossless'],
            'timestamp': datetime.now().isoformat(),
            'lzw_size': result['lzw_result']['size'],
            'lzw_lossless': result['lzw_result']['lossless'],
            'huffman_size': result['huffman_result']['size'],
            'huffman_lossless': result['huffman_result']['lossless'],
            'compressed_path': str(compressed_path),
            'original_hash': result['original_hash'],
            'sasada_score': result.get('sasada_score', 0),
            'skipped': False,
            'skip_reason': ''
        }
        save_history(history_entry)

        # ==========================================================
        # PREVIEW UNTUK GAMBAR
        # ==========================================================
        preview_data = None
        if is_image_file(original_filename):
            try:
                decompressed = compressor.decompress(result['data'], result['algorithm'])
                preview_data = base64.b64encode(decompressed).decode('utf-8')
            except Exception as e:
                pass

        # ==========================================================
        # RESPONSE
        # ==========================================================
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': original_filename,
            'original_size': get_file_size_str(result['original_size']),
            'compressed_size': get_file_size_str(result['compressed_size']),
            'algorithm': result['algorithm'],
            'compression_ratio': result['compression_ratio'],
            'space_saving': result['space_saving'],
            'is_lossless': result['is_lossless'],
            'lzw_size': get_file_size_str(result['lzw_result']['size']),
            'lzw_lossless': result['lzw_result']['lossless'],
            'huffman_size': get_file_size_str(result['huffman_result']['size']),
            'huffman_lossless': result['huffman_result']['lossless'],
            'preview_data': preview_data,
            'is_image': is_image_file(original_filename),
            'download_url': url_for('download_file', file_id=file_id),
            'preview_url': url_for('preview_file', file_id=file_id),
            'sasada_score': result.get('sasada_score', 0),
            'skipped': False,
            'skip_reason': ''
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/download/<file_id>')
def download_file(file_id):
    """Download file terkompresi SASADA (.lzw atau .huff)."""
    history = load_history()
    entry = next((h for h in history if h['id'] == file_id), None)

    if not entry:
        return jsonify({'error': 'File not found'}), 404

    compressed_path = Path(entry['compressed_path'])
    if not compressed_path.exists():
        return jsonify({'error': 'File not found'}), 404

    # Tentukan ekstensi download
    if entry.get('skipped', False) or entry['algorithm'] == 'ORIGINAL':
        download_name = entry['filename']
    else:
        download_name = f"{entry['filename']}.{entry['algorithm'].lower()}"
    
    return send_file(
        compressed_path,
        as_attachment=True,
        download_name=download_name
    )


@app.route('/preview/<file_id>')
def preview_file(file_id):
    """Preview file SASADA - dekompresi dan tampilkan hasil."""
    history = load_history()
    entry = next((h for h in history if h['id'] == file_id), None)

    if not entry:
        return jsonify({'error': 'File not found'}), 404

    compressed_path = Path(entry['compressed_path'])
    if not compressed_path.exists():
        return jsonify({'error': 'File not found'}), 404

    try:
        with open(compressed_path, 'rb') as f:
            compressed_data = f.read()

        # Jika file adalah original (skipped), langsung tampilkan
        if entry.get('skipped', False) or entry['algorithm'] == 'ORIGINAL':
            decompressed = compressed_data
        else:
            decompressed = compressor.decompress(compressed_data, entry['algorithm'])

        # ==========================================================
        # KASUS: FILE GAMBAR
        # ==========================================================
        if is_image_file(entry['filename']):
            ext = entry['extension']
            mime_map = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.bmp': 'image/bmp',
                '.tiff': 'image/tiff',
                '.tif': 'image/tiff',
                '.webp': 'image/webp'
            }
            mimetype = mime_map.get(ext, 'image/png')
            return Response(decompressed, mimetype=mimetype)

        # ==========================================================
        # KASUS: FILE TEKS
        # ==========================================================
        if is_text_file(entry['filename']):
            try:
                return Response(
                    decompressed.decode('utf-8'),
                    mimetype='text/plain'
                )
            except:
                pass

        # ==========================================================
        # KASUS: FILE LAINNYA - DOWNLOAD
        # ==========================================================
        temp_path = DECOMPRESSED_FOLDER / f"preview_{file_id}{entry['extension']}"
        with open(temp_path, 'wb') as f:
            f.write(decompressed)

        return send_file(
            temp_path,
            as_attachment=False,
            download_name=f"preview_{entry['filename']}"
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history')
def view_history():
    """Halaman history kompresi SASADA."""
    history = load_history()
    stats = compressor.get_stats()
    stats_display = {
        **stats,
        'total_original_size_mb': round(stats['total_original_size'] / (1024*1024), 2),
        'total_compressed_size_mb': round(stats['total_compressed_size'] / (1024*1024), 2)
    }
    return render_template('history.html', history=history, stats=stats_display)


@app.route('/api/stats')
def api_stats():
    """API statistik kompresi SASADA."""
    return jsonify(compressor.get_stats())


@app.route('/api/history')
def api_history():
    """API history kompresi SASADA."""
    limit = request.args.get('limit', 50, type=int)
    history = load_history()[-limit:]
    return jsonify(history)


@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """API untuk menganalisis file tanpa kompresi."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        file_data = file.read()
        filename = secure_filename(file.filename)
        
        # Analisis file
        is_compressed, reason, confidence = is_pre_compressed(file_data, filename)
        entropy = calculate_entropy(file_data[:min(len(file_data), 1024*1024)])
        compress_check = should_compress(file_data, filename)
        
        return jsonify({
            'filename': filename,
            'size': len(file_data),
            'size_str': get_file_size_str(len(file_data)),
            'entropy': round(entropy, 4),
            'is_compressed': is_compressed,
            'compression_reason': reason,
            'confidence': round(confidence, 4),
            'should_compress': compress_check['compress'],
            'recommendation': compress_check['recommended'],
            'message': compress_check['message']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear history SASADA."""
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
    # Reset stats di compressor
    compressor.stats = {
        'total_files': 0,
        'total_original_size': 0,
        'total_compressed_size': 0,
        'lzw_count': 0,
        'huffman_count': 0,
        'original_count': 0,
        'skipped_count': 0,
    }
    return jsonify({'success': True})


# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    print("""
    ================================================================
    SASADA - Saving Space Data
    Plugin Smart Storage Berbasis Adaptive Lossless Compression
    ================================================================
    
    Server running at: http://localhost:5000
    
    Features:
    - Adaptive compression (LZW + Huffman)
    - Smart file type detection (skip already compressed files)
    - Entropy analysis for compression effectiveness
    - Lossless with SHA-256 verification
    - File preview support
    - Compression history
    - SASADA Score for efficiency rating
    
    ================================================================
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)