/**
 * LENSINT Forensic Web Application
 * Modular Client Script
 */

document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const spinner = document.getElementById('spinner');
  const resultsPanel = document.getElementById('results-panel');

  // Drag-and-drop event listeners
  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFiles(files);
    }
  });

  dropZone.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFiles(e.target.files);
    }
  });

  async function handleFiles(files) {
    if (files.length === 1) {
      await analyzeSingleFile(files[0]);
    } else {
      await analyzeBatchFiles(files);
    }
  }

  async function analyzeSingleFile(file) {
    spinner.classList.add('active');
    resultsPanel.classList.remove('active');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/analyze?generate_visuals=true&geo_lookup=true', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || err.error || 'Analysis failed');
      }

      const data = await response.json();
      renderForensicResults(data);
    } catch (err) {
      alert('Error during analysis: ' + err.message);
    } finally {
      spinner.classList.remove('active');
    }
  }

  async function analyzeBatchFiles(files) {
    spinner.classList.add('active');
    resultsPanel.classList.remove('active');

    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i]);
    }

    try {
      const response = await fetch('/api/analyze/batch', {
        method: 'POST',
        body: formData
      });

      const data = await response.json();
      if (data.results && data.results.length > 0) {
        renderForensicResults(data.results[0]);
        alert(`Batch analysis complete: Processed ${data.count} image(s). Displaying first result.`);
      }
    } catch (err) {
      alert('Batch upload failed: ' + err.message);
    } finally {
      spinner.classList.remove('active');
    }
  }

  function renderForensicResults(d) {
    resultsPanel.classList.add('active');

    // Verdict banner
    const banner = document.getElementById('verdict-banner');
    const title = document.getElementById('verdict-title');
    const score = document.getElementById('verdict-score');

    title.textContent = `VERDICT: ${d.overall_risk_level}`;
    score.textContent = `${d.overall_risk_score} / 100`;

    const colors = {
      'CLEAN': 'var(--verdict-clean)',
      'LOW': 'var(--accent-cyan)',
      'ELEVATED': 'var(--verdict-elevated)',
      'HIGH': 'var(--verdict-high)',
      'CRITICAL': 'var(--verdict-critical)'
    };
    banner.style.borderColor = colors[d.overall_risk_level] || '#fff';
    score.style.color = colors[d.overall_risk_level] || '#fff';

    // Populate metadata
    document.getElementById('m-name').textContent = d.integrity.file_name;
    document.getElementById('m-size').textContent = `${d.integrity.file_size_human} (${d.integrity.file_size_bytes} B)`;
    document.getElementById('m-mime').textContent = d.integrity.detected_mime;
    document.getElementById('m-sha256').textContent = d.integrity.sha256.substring(0, 24) + '...';

    // Metadata
    document.getElementById('meta-cam').textContent = (d.metadata.camera_make || 'N/A') + ' ' + (d.metadata.camera_model || '');
    document.getElementById('meta-soft').textContent = d.metadata.software || 'None';
    document.getElementById('meta-prov').textContent = d.metadata.social_media_provenance || 'None / Direct Device';
    document.getElementById('meta-ssim').textContent = d.metadata.thumbnail_mismatch_detected 
      ? `MISMATCH (${d.metadata.thumbnail_ssim_score})` 
      : (d.metadata.thumbnail_extracted ? `Verified (${d.metadata.thumbnail_ssim_score})` : 'N/A');

    // AI & Synthetic
    document.getElementById('ai-verdict').textContent = d.ai_detection.ai_verdict;
    document.getElementById('ai-score').textContent = `${d.ai_detection.ai_probability_score} / 100`;
    document.getElementById('ai-prnu').textContent = d.ai_detection.prnu_sensor_noise_detected ? 'Sensor Present' : 'Absent / Synthetic';
    document.getElementById('ai-fft').textContent = `${d.ai_detection.fft_spectral_score} / 100 (Ratio: ${d.ai_detection.fft_peak_ratio})`;

    // Tampering
    document.getElementById('tamp-ela').textContent = `${d.tampering.ela_suspicion_score} / 100`;
    document.getElementById('tamp-cm').textContent = d.tampering.copy_move_detected ? `DETECTED (${d.tampering.copy_move_match_count} pairs)` : 'Clean';
    document.getElementById('tamp-splice').textContent = d.tampering.splice_detected ? `DETECTED (${Math.round(d.tampering.splice_confidence)}% conf)` : 'Clean';
    document.getElementById('tamp-ghost').textContent = d.tampering.jpeg_ghosts_detected ? 'DETECTED' : 'Uniform';

    // Stego & Malware
    document.getElementById('stego-overlay').textContent = d.stego.has_overlay_data ? `DETECTED (${d.stego.overlay_size_bytes} B)` : 'Clean';
    document.getElementById('stego-rs').textContent = d.stego.rs_steganalysis_detected ? `DETECTED (${Math.round(d.stego.rs_estimated_embedding_rate * 100)}%)` : 'Natural';
    document.getElementById('mal-threat').textContent = d.malware.has_threats ? 'THREAT DETECTED' : 'Clean';
    document.getElementById('mal-yara').textContent = (d.malware.yara_matches && d.malware.yara_matches.length > 0) 
      ? d.malware.yara_matches.map(m => m.rule).join(', ') 
      : 'None';

    // Heatmaps
    const hmContainer = document.getElementById('heatmap-container');
    hmContainer.innerHTML = '';
    const visual = d.tampering.ela_b64_image || d.tampering.splice_b64_image || d.ai_detection.fft_b64_spectrum;
    if (visual) {
      const img = document.createElement('img');
      img.className = 'heatmap-img';
      img.src = 'data:image/png;base64,' + visual;
      hmContainer.appendChild(img);
    }
  }
});
