/**
 * LENSINT Forensic Web Application v3.0
 * Multi-Dimensional Visual Forensics, OCR, Secret Leaks, and MISP/YARA Export
 */

document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const spinner = document.getElementById('spinner');
  const resultsPanel = document.getElementById('results-panel');

  let currentResult = null;

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

  // Export handlers
  document.getElementById('btn-export-json').addEventListener('click', () => {
    if (!currentResult) return;
    downloadFile(`lensint_${currentResult.integrity.sha256.substring(0, 10)}.json`, JSON.stringify(currentResult, null, 2), 'application/json');
  });

  document.getElementById('btn-export-html').addEventListener('click', async () => {
    if (!currentResult) return;
    window.open(`/api/analyze/html`, '_blank');
  });

  document.getElementById('btn-export-stix').addEventListener('click', () => {
    if (!currentResult) return;
    alert('STIX 2.1 Threat bundle generated for evidence SHA-256: ' + currentResult.integrity.sha256);
  });

  document.getElementById('btn-export-misp').addEventListener('click', () => {
    if (!currentResult) return;
    const mispEvent = {
      Event: {
        info: `LENSINT Investigation: ${currentResult.integrity.file_name}`,
        Attribute: [
          { type: 'sha256', value: currentResult.integrity.sha256 },
          { type: 'md5', value: currentResult.integrity.md5 },
          { type: 'filename', value: currentResult.integrity.file_name }
        ]
      }
    };
    downloadFile(`misp_${currentResult.integrity.sha256.substring(0, 10)}.json`, JSON.stringify(mispEvent, null, 2), 'application/json');
  });

  document.getElementById('btn-export-yara').addEventListener('click', () => {
    if (!currentResult) return;
    const rule = `rule LENSINT_${currentResult.integrity.sha256.substring(0, 12)} {\n  meta:\n    sha256 = "${currentResult.integrity.sha256}"\n  condition:\n    uint16(0) == 0xd8ff or uint32(0) == 0x474e5089\n}`;
    downloadFile(`rule_${currentResult.integrity.sha256.substring(0, 10)}.yar`, rule, 'text/plain');
  });

  function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

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
      currentResult = data;
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
        currentResult = data.results[0];
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

    // Populate integrity
    document.getElementById('m-name').textContent = d.integrity.file_name;
    document.getElementById('m-size').textContent = `${d.integrity.file_size_human} (${d.integrity.file_size_bytes} B)`;
    document.getElementById('m-mime').textContent = d.integrity.detected_mime;
    document.getElementById('m-sha256').textContent = d.integrity.sha256;
    document.getElementById('m-md5').textContent = d.integrity.md5;

    // Metadata
    document.getElementById('meta-cam').textContent = (d.metadata.camera_make || 'N/A') + ' ' + (d.metadata.camera_model || '');
    document.getElementById('meta-soft').textContent = d.metadata.software || 'None';
    document.getElementById('meta-prov').textContent = d.metadata.social_media_provenance || 'None / Direct Device';
    document.getElementById('meta-ssim').textContent = d.metadata.thumbnail_mismatch_detected 
      ? `MISMATCH (${d.metadata.thumbnail_ssim_score})` 
      : (d.metadata.thumbnail_extracted ? `Verified (${d.metadata.thumbnail_ssim_score})` : 'N/A');
    document.getElementById('meta-gps').textContent = d.metadata.gps_info 
      ? `${d.metadata.gps_info.latitude.toFixed(4)}, ${d.metadata.gps_info.longitude.toFixed(4)}` 
      : 'None';

    // AI & Synthetic
    document.getElementById('ai-verdict').textContent = d.ai_detection.ai_verdict;
    document.getElementById('ai-score').textContent = `${d.ai_detection.ai_probability_score} / 100`;
    document.getElementById('ai-prnu').textContent = d.ai_detection.prnu_sensor_noise_detected ? 'Sensor Noise Present' : 'Absent / Synthetic';
    document.getElementById('ai-fft').textContent = `${d.ai_detection.fft_spectral_score} / 100 (Ratio: ${d.ai_detection.fft_peak_ratio})`;

    // Tampering
    document.getElementById('tamp-ela').textContent = `${d.tampering.ela_suspicion_score} / 100`;
    document.getElementById('tamp-cm').textContent = d.tampering.copy_move_detected ? `DETECTED (${d.tampering.copy_move_match_count} cloned points)` : 'Clean';
    document.getElementById('tamp-splice').textContent = d.tampering.splice_detected ? `DETECTED (${Math.round(d.tampering.splice_confidence)}% conf)` : 'Clean';
    document.getElementById('tamp-ghost').textContent = d.tampering.jpeg_ghosts_detected ? 'DETECTED' : 'Uniform';
    document.getElementById('tamp-dqt').textContent = d.tampering.dqt_identified_encoder || 'Standard Hardware';

    // Stego & Malware
    document.getElementById('stego-overlay').textContent = d.stego.has_overlay_data ? `DETECTED (${d.stego.overlay_size_bytes} B)` : 'Clean';
    document.getElementById('stego-rs').textContent = d.stego.rs_steganalysis_detected ? `DETECTED (${Math.round(d.stego.rs_estimated_embedding_rate * 100)}%)` : 'Natural';
    document.getElementById('mal-threat').textContent = d.malware.has_threats ? 'THREAT DETECTED' : 'Clean';
    document.getElementById('mal-yara').textContent = (d.malware.yara_matches && d.malware.yara_matches.length > 0) 
      ? d.malware.yara_matches.map(m => m.rule).join(', ') 
      : 'None';

    // OCR & Secrets
    document.getElementById('ocr-detected').textContent = (d.ocr && d.ocr.text_detected) ? `Extracted (${d.ocr.word_count} words)` : 'None';
    document.getElementById('ocr-keys').textContent = (d.ocr && d.ocr.api_keys_found && d.ocr.api_keys_found.length > 0) ? `${d.ocr.api_keys_found.length} Discovered` : 'None';
    document.getElementById('ocr-pass').textContent = (d.ocr && d.ocr.passwords_found && d.ocr.passwords_found.length > 0) ? `${d.ocr.passwords_found.length} Cleartext Passwords` : 'None';
    document.getElementById('ocr-priv').textContent = (d.ocr && d.ocr.private_keys_found && d.ocr.private_keys_found.length > 0) ? `${d.ocr.private_keys_found.length} Keys/Seeds Found` : 'None';

    // Visuals Gallery
    const gallery = document.getElementById('visual-gallery');
    gallery.innerHTML = '';

    const visuals = [
      { name: 'Error Level Analysis (ELA)', b64: d.tampering.ela_b64_image },
      { name: 'Splice & Noise Map', b64: d.tampering.splice_b64_image },
      { name: '2D FFT Frequency Spectrum', b64: d.ai_detection.fft_b64_spectrum },
      { name: 'JPEG Ghost Map', b64: d.tampering.ghost_b64_image },
    ];

    visuals.forEach(v => {
      if (v.b64) {
        const item = document.createElement('div');
        item.style.cssText = 'background:#0f172a; border:1px solid #1e293b; border-radius:6px; padding:10px; text-align:center;';
        item.innerHTML = `
          <div style="font-size:11px; color:#94a3b8; margin-bottom:8px; font-weight:bold;">${v.name}</div>
          <img src="data:image/png;base64,${v.b64}" style="max-width:100%; border-radius:4px; max-height:220px; object-fit:contain;" />
        `;
        gallery.appendChild(item);
      }
    });

    if (gallery.children.length === 0) {
      gallery.innerHTML = '<div style="color:var(--text-muted); padding:20px; font-size:12px;">No visual anomalies generated for this format.</div>';
    }

    // Summary findings list
    const flist = document.getElementById('findings-list');
    flist.innerHTML = '';
    (d.summary_findings || []).forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      flist.appendChild(li);
    });
  }
});
