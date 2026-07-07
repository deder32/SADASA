/**
 * Web Compress - Frontend JavaScript
 * Menangani upload, progress, result display, dan preview
 */

let currentResult = null;
let isUploading = false;

document.addEventListener('DOMContentLoaded', function() {
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');

    // ============================================================
    // CLICK TO UPLOAD
    // ============================================================
    uploadZone.addEventListener('click', function(e) {
        if (!isUploading) {
            fileInput.click();
        }
    });

    // ============================================================
    // DRAG & DROP
    // ============================================================
    uploadZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    // ============================================================
    // FILE INPUT CHANGE
    // ============================================================
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            handleFile(this.files[0]);
        }
    });

    // ============================================================
    // DOWNLOAD BUTTON
    // ============================================================
    document.getElementById('btnDownload').addEventListener('click', function() {
        if (currentResult && currentResult.download_url) {
            window.location.href = currentResult.download_url;
        }
    });
});


/**
 * Handle file upload
 */
function handleFile(file) {
    if (isUploading) return;
    
    // Validasi file size (100MB)
    if (file.size > 100 * 1024 * 1024) {
        alert('❌ File terlalu besar! Maksimal 100MB.');
        return;
    }

    isUploading = true;
    showProgress(true);
    updateProgress(10, '<i class="fas fa-upload"></i> Uploading...');

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        isUploading = false;
        showProgress(false);

        if (data.error) {
            alert('❌ Error: ' + data.error);
            return;
        }

        currentResult = data;
        displayResult(data);
    })
    .catch(error => {
        isUploading = false;
        showProgress(false);
        alert('❌ Error: ' + error.message);
    });
}


/**
 * Show/hide progress bar
 */
function showProgress(show) {
    const uploadZone = document.getElementById('uploadZone');
    const uploadContent = uploadZone.querySelector('.upload-content');
    const uploadProgress = document.getElementById('uploadProgress');

    if (show) {
        uploadContent.style.display = 'none';
        uploadProgress.style.display = 'block';
        uploadZone.style.cursor = 'default';
    } else {
        uploadContent.style.display = 'block';
        uploadProgress.style.display = 'none';
        uploadZone.style.cursor = 'pointer';
    }
}


/**
 * Update progress bar
 */
function updateProgress(percent, text) {
    document.getElementById('progressFill').style.width = Math.min(percent, 100) + '%';
    document.getElementById('progressText').innerHTML = text || `Compressing... ${percent}%`;
}


/**
 * Display compression result
 */
function displayResult(data) {
    const section = document.getElementById('resultSection');
    section.style.display = 'block';

    // ============================================================
    // FILE INFO
    // ============================================================
    document.getElementById('resultFilename').textContent = data.filename;
    document.getElementById('resultOriginalSize').textContent = data.original_size;
    document.getElementById('resultCompressedSize').textContent = data.compressed_size;
    document.getElementById('resultSpaceSaving').textContent = data.space_saving + '%';
    document.getElementById('resultRatio').textContent = data.compression_ratio + '%';
    
    // Lossless dengan icon
    const losslessEl = document.getElementById('resultLossless');
    if (data.is_lossless) {
        losslessEl.innerHTML = '<i class="fas fa-check-circle" style="color:#48bb78;"></i> Yes';
    } else {
        losslessEl.innerHTML = '<i class="fas fa-times-circle" style="color:#fc8181;"></i> No';
    }

    // ============================================================
    // ALGORITHM
    // ============================================================
    const algoBadge = document.getElementById('resultAlgorithm');
    algoBadge.textContent = data.algorithm;
    algoBadge.dataset.algo = data.algorithm;

    // ============================================================
    // LZW
    // ============================================================
    document.getElementById('resultLzwSize').textContent = data.lzw_size;
    document.getElementById('resultLzwStatus').innerHTML = data.lzw_lossless ? 
        '<i class="fas fa-check-circle" style="color:#48bb78;"></i>' : 
        '<i class="fas fa-times-circle" style="color:#fc8181;"></i>';

    // ============================================================
    // HUFFMAN
    // ============================================================
    document.getElementById('resultHuffSize').textContent = data.huffman_size;
    document.getElementById('resultHuffStatus').innerHTML = data.huffman_lossless ? 
        '<i class="fas fa-check-circle" style="color:#48bb78;"></i>' : 
        '<i class="fas fa-times-circle" style="color:#fc8181;"></i>';

    // ============================================================
    // SELECTED
    // ============================================================
    document.getElementById('resultSelectedAlgo').textContent = data.algorithm;

    // ============================================================
    // DOWNLOAD BUTTON
    // ============================================================
    const downloadBtn = document.getElementById('btnDownload');
    downloadBtn.innerHTML = `<i class="fas fa-download"></i> Download .${data.algorithm.toLowerCase()}`;

    // ============================================================
    // PREVIEW IMAGE
    // ============================================================
    const previewSection = document.getElementById('previewSection');
    if (data.is_image && data.preview_data) {
        previewSection.style.display = 'block';
        document.getElementById('previewImage').src = 'data:image/*;base64,' + data.preview_data;
    } else {
        previewSection.style.display = 'none';
    }

    // ============================================================
    // SCROLL TO RESULT
    // ============================================================
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Animate progress to 100%
    updateProgress(100, '<i class="fas fa-check-circle" style="color:#48bb78;"></i> Done!');
}


/**
 * Reset upload form
 */
function resetUpload() {
    document.getElementById('resultSection').style.display = 'none';
    document.getElementById('fileInput').value = '';
    currentResult = null;
    document.getElementById('uploadZone').scrollIntoView({ behavior: 'smooth' });
}