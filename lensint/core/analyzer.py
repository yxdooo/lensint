from datetime import datetime, timezone
import os
import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from lensint.cache import get_cached, put_cache

from lensint.core.models import AnalysisResult
from lensint.modules.integrity import analyze_integrity
from lensint.modules.metadata import analyze_metadata
from lensint.modules.stego import analyze_stego
from lensint.modules.strings_scan import analyze_strings
from lensint.modules.tampering import analyze_tampering
from lensint.modules.ai_detect import analyze_ai_generation
from lensint.modules.malware_rules import analyze_malware_and_polyglots
from lensint.modules.threat_intel import generate_threat_intel_links, reverse_geocode
from lensint.utils.image_ops import load_image_safe


class ImageAnalyzer:
    def __init__(
        self,
        file_path: str,
        ela_quality: int = 90,
        min_string_len: int = 4,
        generate_visuals: bool = True,
        perform_geolookup: bool = False,
        use_cache: bool = True,
    ):
        self.file_path = os.path.abspath(file_path)
        self.ela_quality = ela_quality
        self.min_string_len = min_string_len
        self.generate_visuals = generate_visuals
        self.perform_geolookup = perform_geolookup
        self.use_cache = use_cache
    def _result_from_dict(self, d: dict) -> AnalysisResult:
        """Reconstruct AnalysisResult from a cached dict (best-effort)."""
        result = AnalysisResult()
        for key in ("target_path", "timestamp", "overall_risk_score", "overall_risk_level",
                    "summary_findings", "analysis_duration_seconds"):
            if key in d:
                setattr(result, key, d[key])
        result.cache_hit = True
        if "summary_findings" not in d or not result.summary_findings:
            result.summary_findings = []
        if "Result loaded from cache. Use --no-cache to force re-analysis." not in result.summary_findings:
            result.summary_findings.insert(0, "Result loaded from cache. Use --no-cache to force re-analysis.")

        def _fill(obj, src: dict):
            for k, v in src.items():
                try:
                    setattr(obj, k, v)
                except Exception:
                    pass

        if "integrity" in d:   _fill(result.integrity, d["integrity"])
        if "metadata" in d:    _fill(result.metadata, d["metadata"])
        if "tampering" in d:   _fill(result.tampering, d["tampering"])
        if "stego" in d:       _fill(result.stego, d["stego"])
        if "strings" in d:     _fill(result.strings, d["strings"])
        if "ai_detection" in d: _fill(result.ai_detection, d["ai_detection"])
        if "malware" in d:     _fill(result.malware, d["malware"])
        if "threat_intel" in d: _fill(result.threat_intel, d["threat_intel"])
        return result

    def analyze(self) -> AnalysisResult:
        start_time = time.monotonic()
        result = AnalysisResult()
        result.target_path = self.file_path
        result.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        pil_img, raw_bytes, load_err = load_image_safe(self.file_path)
        if raw_bytes is None:
            err_msg = load_err if load_err else "Unable to access target file."
            result.summary_findings.append(f"Fatal read error: {err_msg}")
            result.overall_risk_score = 100.0
            result.overall_risk_level = "CRITICAL"
            result.analysis_duration_seconds = time.monotonic() - start_time
            return result

        result.integrity = analyze_integrity(self.file_path, raw_bytes, pil_img)

        # Decompression Bomb / High-Resolution DoS protection:
        # Downsample extremely large images before heavy concurrent pixel operations.
        if pil_img is not None:
            from lensint.utils.image_ops import downsample_for_analysis
            pil_img, was_sampled = downsample_for_analysis(pil_img, max_pixels=4_000_000, max_side=2000)
            if was_sampled:
                result.summary_findings.append("Large image resolution downsampled for safe concurrent analysis.")

        try:
            from lensint import __version__
            version_str = __version__
        except ImportError:
            version_str = "unknown"
            
        # Model status check
        model_status = "no_model"
        model_manifest = os.path.expanduser("~/.lensint/models/manifest.json")
        if os.path.exists(model_manifest):
            try:
                import json
                with open(model_manifest, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                    model_status = manifest_data.get("model_sha256", str(os.path.getmtime(model_manifest)))
            except Exception:
                model_status = str(os.path.getmtime(model_manifest))
            
        cache_schema_ver = "v2"
        cache_key = f"{result.integrity.sha256}_{version_str}_{cache_schema_ver}_ela{self.ela_quality}_len{self.min_string_len}_vis{int(self.generate_visuals)}_geo{int(self.perform_geolookup)}_{model_status}"

        if self.use_cache:
            cached = get_cached(cache_key)
            if cached is not None:
                res = self._result_from_dict(cached)
                res.analysis_duration_seconds = time.monotonic() - start_time
                return res

        def _run_metadata():
            return analyze_metadata(raw_bytes, pil_img.copy() if pil_img else None)

        def _run_stego():
            return analyze_stego(raw_bytes, pil_img.copy() if pil_img else None, generate_visuals=self.generate_visuals)

        def _run_strings():
            return analyze_strings(raw_bytes, min_len=self.min_string_len)

        def _run_ai_detect():
            return analyze_ai_generation(raw_bytes, pil_img.copy() if pil_img else None, generate_visuals=self.generate_visuals)

        def _run_malware():
            return analyze_malware_and_polyglots(raw_bytes)

        def _run_ocr():
            from lensint.modules.ocr_scan import analyze_ocr
            return analyze_ocr(pil_img.copy() if pil_img else None)

        with ThreadPoolExecutor(max_workers=5) as executor:
            f_metadata = executor.submit(_run_metadata)
            f_stego = executor.submit(_run_stego)
            f_strings = executor.submit(_run_strings)
            f_ai = executor.submit(_run_ai_detect)
            f_malware = executor.submit(_run_malware)
            f_ocr = executor.submit(_run_ocr)

            result.metadata = f_metadata.result()
            result.stego = f_stego.result()
            result.strings = f_strings.result()
            result.ai_detection = f_ai.result()
            result.malware = f_malware.result()
            result.ocr = f_ocr.result()

        # If OCR text wasn't extracted via image OCR, cross-correlate with binary strings
        if not result.ocr.text_detected and result.strings.sample_strings:
            from lensint.modules.ocr_scan import scan_sensitive_leaks
            fallback_text = " ".join(result.strings.sample_strings[:200])
            fallback_leaks = scan_sensitive_leaks(fallback_text)
            if fallback_leaks["findings"]:
                result.ocr.sensitive_findings.extend(fallback_leaks["findings"])
                result.ocr.api_keys_found.extend(fallback_leaks["api_keys"])
                result.ocr.passwords_found.extend(fallback_leaks["passwords"])
                result.ocr.tokens_found.extend(fallback_leaks["tokens"])
                result.ocr.pii_found.extend(fallback_leaks["pii"])
                result.ocr.private_keys_found.extend(fallback_leaks["private_keys"])

        if self.perform_geolookup and result.metadata.gps_info:
            lat = result.metadata.gps_info["latitude"]
            lon = result.metadata.gps_info["longitude"]
            result.metadata.reverse_geocode = reverse_geocode(lat, lon)

        result.tampering = analyze_tampering(
            pil_img,
            raw_bytes=raw_bytes,
            ela_quality=self.ela_quality,
            generate_visuals=self.generate_visuals,
            is_screenshot=result.integrity.is_screenshot,
        )

        result.threat_intel = generate_threat_intel_links(
            sha256_hash=result.integrity.sha256,
            ips=result.strings.iocs_detected["ipv4"],
            domains=result.strings.iocs_detected["domains"],
            urls=result.strings.iocs_detected["urls"],
        )

        # C2 Steganography & Covert Channel Analysis
        try:
            from lensint.modules.c2_stego_decoders import C2StegoDetector
            png_covert = C2StegoDetector.analyze_png_chunks(raw_bytes)
            for f in png_covert.get("findings", []):
                result.stego.findings.append(f)
            freq_markers = C2StegoDetector.analyze_frequency_stego_markers(raw_bytes)
            for fm in freq_markers:
                result.stego.findings.append(f"C2 Stego Frequency Carrier: {fm['tool']} ({fm['confidence']}).")

            # Neural Prompt Injections in metadata / OCR
            from lensint.modules.neural_ai import scan_prompt_injections
            combined_text = result.ocr.extracted_text + " " + str(result.metadata.raw_tags)
            injections = scan_prompt_injections(combined_text)
            for inj in injections:
                result.summary_findings.append(f"Prompt Injection Alert: {inj['type']} ({inj['sample']}).")
        except Exception:
            pass

        self._calculate_verdict(result)
        result.analysis_duration_seconds = time.monotonic() - start_time
        if self.use_cache:
            put_cache(cache_key, result.to_dict())
        return result

    def _calculate_verdict(self, result: AnalysisResult) -> None:
        findings = []

        if result.integrity.is_screenshot:
            findings.append(f"Classified as {result.integrity.screen_capture_type or 'Digital Screen Capture'} (Camera sensor heuristics contextualized).")

        if result.malware.has_threats:
            for tf in result.malware.findings:
                findings.append(tf)

        if result.integrity.extension_mismatch:
            findings.append("Disguised file format / Extension spoofing detected.")

        if result.integrity.is_corrupt_or_truncated:
            findings.append("Image structure is damaged or truncated.")

        if result.stego.has_overlay_data:
            findings.append(f"Hidden trailing payload ({result.stego.overlay_size_bytes} bytes) found appended past image EOF.")

        suspicious_sigs = [s for s in result.stego.embedded_signatures if s["offset"] > 0]
        if suspicious_sigs:
            sig_names = ", ".join(list(set(s["signature"] for s in suspicious_sigs[:3])))
            findings.append(f"Embedded payload/archive signatures discovered: {sig_names}.")

        if result.stego.extracted_payload_type:
            findings.append(f"Carrier extraction: {result.stego.extracted_payload_type}.")

        if result.stego.lsb_stego_detected:
            findings.append("Abnormally high LSB entropy indicates active steganographic carrier.")

        if result.tampering.copy_move_detected:
            findings.append(f"Copy-Move cloning detected ({result.tampering.copy_move_match_count} cloned keypoints).")

        if result.tampering.jpeg_ghosts_detected:
            findings.append(f"JPEG Ghosts / Double compression detected (Quality variance: {result.tampering.jpeg_ghost_qualities}).")

        if result.tampering.cfa_tampering_detected:
            findings.append(f"CFA Bayer demosaicing anomaly detected (Score: {result.tampering.cfa_inconsistency_score}/100). Splicing suspected.")

        if result.tampering.block_grid_shifted:
            findings.append(f"8x8 DCT block grid phase shift detected (Offset: {result.tampering.block_grid_offset}). Pasted patch misaligned.")

        if result.tampering.chromatic_aberration_detected:
            findings.append(f"Chromatic aberration radial vector anomaly detected (Score: {result.tampering.chromatic_aberration_inconsistency}/100).")

        if result.tampering.median_filter_detected:
            findings.append(f"Median filter / Anti-forensic smoothing detected (Score: {result.tampering.median_filter_score}/100).")

        if result.tampering.illumination_conflict_detected:
            findings.append(f"Illumination & lighting angle conflict detected (Score: {result.tampering.illumination_variance_score}/100).")

        if result.tampering.dqt_found and result.tampering.dqt_identified_encoder:
            if "Adobe" in result.tampering.dqt_identified_encoder or "GIMP" in result.tampering.dqt_identified_encoder:
                findings.append(f"DQT Quantization fingerprint confirms software edit: {result.tampering.dqt_identified_encoder}.")

        if result.tampering.suspicion_level == "HIGH" and not result.tampering.copy_move_detected and not result.tampering.jpeg_ghosts_detected:
            findings.append("High tampering probability (ELA disparity & noise variance).")
        elif result.tampering.suspicion_level == "MEDIUM":
            findings.append("Moderate compression variance suggests localized editing.")

        if result.ai_detection.ai_verdict == "CONFIRMED_AI":
            findings.append(f"AI Generated / Synthetic image confirmed ({result.ai_detection.ai_generator_name}).")
        elif result.ai_detection.ai_verdict == "HIGH_PROBABILITY_AI":
            findings.append("AI Generation suspected (Characteristic diffusion FFT spectral grid spikes).")

        if result.metadata.software_footprint_findings:
            findings.append(f"Metadata confirms editing: {result.metadata.software_footprint_findings[0]}")

        if result.metadata.thumbnail_mismatch_detected:
            findings.append(f"EXIF Thumbnail Mismatch (SSIM: {result.metadata.thumbnail_ssim_score}): Deliberate selective editing detected.")

        if result.stego.rs_steganalysis_detected:
            findings.append(f"RS Steganalysis indicates potential LSB anomaly (Est. payload capacity: {int(result.stego.rs_estimated_embedding_rate*100)}%).")

        if result.malware.yara_matches:
            yara_names = ", ".join(m["rule"] for m in result.malware.yara_matches[:2])
            findings.append(f"YARA Rule match confirmed threat: {yara_names}.")

        if result.malware.deobfuscated_payloads:
            findings.append(f"Auto-Deobfuscator extracted {len(result.malware.deobfuscated_payloads)} hidden payload(s).")

        if result.strings.iocs_detected["shell_commands"]:
            cmds = ", ".join(result.strings.iocs_detected["shell_commands"][:3])
            findings.append(f"Dangerous shell execution keywords detected: {cmds}.")

        b64_count = len(result.strings.iocs_detected["base64_blobs"])
        if b64_count > 0:
            findings.append(f"{b64_count} encoded Base64 payload blob(s) discovered.")

        if result.ocr.sensitive_findings:
            leak_count = len(result.ocr.sensitive_findings)
            first_type = result.ocr.sensitive_findings[0]["type"]
            first_red = result.ocr.sensitive_findings[0]["redacted"]
            findings.append(f"Confidential Data Leak: {leak_count} secret(s) discovered including {first_type} ({first_red}).")

        try:
            # Bayesian Log-Odds Fusion (Uses literature-derived Likelihood Ratios)
            from lensint.modules.benchmarks import BayesianForensicFusionEngine
            
            has_c2_stego = any("C2 Stego" in f for f in result.stego.findings)
            has_prompt_injection = any("Prompt Injection Alert" in f for f in result.summary_findings)
            
            calibrated_score, calibrated_verdict, fusion_log = BayesianForensicFusionEngine.calculate_calibrated_risk(
                ela_score=result.tampering.ela_difference_max,
                copy_move_detected=result.tampering.copy_move_detected,
                dqt_anomaly=result.tampering.dqt_found,
                cfa_anomaly=result.tampering.cfa_tampering_detected,
                fft_ai_score=result.ai_detection.fft_spectral_score,
                rs_stego_detected=result.stego.rs_steganalysis_detected,
                chi_square_detected=result.stego.lsb_stego_detected,
                metadata_anomaly=result.metadata.thumbnail_mismatch_detected,
                malware_threat=result.malware.has_threats,
                confirmed_payload=bool(result.stego.has_overlay_data or result.stego.extracted_payload_type),
                c2_stego_detected=has_c2_stego,
                prompt_injection=has_prompt_injection
            )
            result.overall_risk_score = calibrated_score
            result.overall_risk_level = calibrated_verdict
            
            # Elevate explicitly if extreme threats bypass log-odds mapping limits
            if result.malware.has_threats or result.ocr.sensitive_findings:
                result.overall_risk_level = "CRITICAL"
                result.overall_risk_score = max(90.0, result.overall_risk_score)
                
        except Exception as e:
            import logging
            logging.getLogger("lensint.analyzer").error(f"Bayesian Fusion Error: {e}")
            # Safe fallback if fusion engine is unavailable
            result.overall_risk_score = 0.0
            result.overall_risk_level = "ANALYSIS_ERROR"

        if not findings:
            findings.append("No security threats, hidden payloads, or tampering indicators detected.")

        result.summary_findings = findings
