# LENSINT System Architecture, Data Flow, and Mathematical Foundations

## System Overview

LENSINT is architected as a modular, concurrent, and mathematically calibrated digital media forensics and threat intelligence platform. The system operates in both headless batch and single-file CLI modes, embedded forensic library integrations, and long-running REST API services.

The design emphasizes:
1. **Thread-Safe Memory Isolation**: Concurrent execution of analytical extractors on independent deep copies of raw media buffers.
2. **Denial-of-Service (DoS) and Decompression Bomb Mitigation**: Safe pre-allocation scaling, dimension validation, and streaming byte thresholds.
3. **Calibrated Multi-Modal Bayesian Fusion**: Mathematical integration of disparate heuristic and deterministic forensic indicators into an un-inflated posterior risk score.
4. **Cryptographic Traceability**: End-to-end evidence hash tracking, ISO/IEC 27037 chained ledger audit seals, and RFC 3161 Time-Stamp Authority (TSA) attestation.

---

## High-Level Component Architecture

```
                                  +-----------------------+
                                  | Digital Evidence File |
                                  +-----------+-----------+
                                              |
                                              v
                              +-------------------------------+
                              |    Safe Ingestion Pipeline    |
                              | - Format Magic Validation     |
                              | - Decompression Bomb Defense  |
                              | - SHA-256 Cache Query         |
                              +---------------+---------------+
                                              |
      +---------------------------------------+---------------------------------------+
      |                                       |                                       |
      v                                       v                                       v
+-------------------------------+   +-------------------------------+   +-------------------------------+
|  Structural & Metadata Layer  |   |   Physics & Tampering Layer   |   |   Stego & Frequency Layer     |
| - EXIF / XMP / IPTC IFD       |   | - Multi-Scale ELA (Q=80,90,95)|   | - Pure-Python Baseline DCT    |
| - Reverse Geocoding (OSM)     |   | - Copy-Move ORB + RANSAC      |   | - JSteg AC Coefficient Carver |
| - Thumbnail SSIM Divergence   |   | - JPEG Ghosts Scanning        |   | - F5 Matrix Capacity          |
| - Chronology Anomaly Tracker  |   | - DQT Hardware Fingerprints   |   | - OutGuess 0.2 Symmetry       |
| - Social Platform Artifacts   |   | - CFA Bayer Demosaicing       |   | - Westfeld Chi-Square (PoVs)  |
| - Container Atom Hierarchy    |   | - 8x8 DCT Block Grid Shift    |   | - Calibrated RS Steganalysis  |
+---------------+---------------+   | - Radial Chromatic Dispersion |   | - PNG Chunk & CRC32 Validator |
                |                   | - Surface Normal Illumination |   +---------------+---------------+
                |                   +---------------+---------------+                   |
                |                                   |                                   |
                +-----------------------------------+-----------------------------------+
                                                    |
      +---------------------------------------------+---------------------------------------------+
      |                                             |                                             |
      v                                             v                                             v
+-------------------------------+   +-------------------------------+   +-------------------------------+
|  Camera Identification (PRNU) |   | Perceptual Hash Triage (PDQ)  |   |  AI, Threat Intel & Memory    |
| - 2D Spatial Wiener Filter    |   | - 64x64 Resampling & Blur     |   | - ONNX Neural TruFor/CNN Pipe |
| - High-Pass MAD Sigma Est.    |   | - 16x16 2D-DCT Transformation |   | - 2D-FFT Spectral Spikes      |
| - 2D-FFT Circular Cross-Corr  |   | - Median Quantization (256-bit)|   | - YARA Engine & XOR Recovery  |
| - Peak-to-Correlation Energy  |   | - BK-Tree Metric Space Index  |   | - Tesseract OCR Regex Hunter  |
| - 1:N MLE Suspect Matcher     |   | - Triangle Inequality Pruning |   | - Volatility 3 VAD Stream Carve|
+---------------+---------------+   +---------------+---------------+   +---------------+---------------+
                |                                   |                                   |
                +-----------------------------------+-----------------------------------+
                                                    |
                                                    v
                                    +-------------------------------+
                                    | Calibrated Bayesian Fusion    |
                                    | - Prior Preset Initialization |
                                    | - Two-Sided Likelihood Ratios |
                                    | - Correlation Decay Factor    |
                                    | - Sigmoidal Posterior Score   |
                                    +---------------+---------------+
                                                    |
                                                    v
                                    +-------------------------------+
                                    | Cryptographic Custody Ledger  |
                                    | - ISO 27037 Chained SHA-256   |
                                    | - RFC 3161 DER Timestamp Seal |
                                    +---------------+---------------+
                                                    |
                +-----------------------------------+-----------------------------------+
                |                   |               |               |                   |
                v                   v               v               v                   v
        +---------------+   +---------------+   +-------+   +---------------+   +---------------+
        | FRE 702 PDF   |   | Dark-Mode HTML|   | JSON  |   | STIX 2.1 /    |   | Deployable    |
        | Expert Report |   | Interactive   |   | Data  |   | MISP Events   |   | YARA Rules    |
        +---------------+   +---------------+   +-------+   +---------------+   +---------------+
```

---

## Mathematical Foundations

### 1. Photo-Response Non-Uniformity (PRNU) Camera Attribution

PRNU represents the deterministic, physical silicon imperfection pattern unique to an individual camera sensor array.

#### Noise Residual Extraction
Given an input intensity matrix $I(x,y)$, the high-frequency sensor noise residual $W$ is obtained by subtracting a denoised estimate $F(I)$ generated via a local adaptive spatial Wiener filter:
$$W(x, y) = I(x, y) - F(I(x, y))$$

The local noise variance $\sigma_0^2$ is estimated robustly using the Median Absolute Deviation (MAD) of the Laplacian filtered image:
$$\sigma_0 = \frac{\text{median}(|\nabla^2 I|)}{0.6745}, \quad \sigma_0^2 = \max\left(1.0, \sigma_0^2\right)$$

The adaptive Wiener weight for local mean $\mu_L$ and local variance $\sigma_L^2$ within a $5 \times 5$ window is:
$$F(I) = \mu_L + \frac{\max(0, \sigma_L^2 - \sigma_0^2)}{\sigma_L^2 + \epsilon} \cdot (I - \mu_L)$$

Non-PRNU linear artifacts (such as CMOS readout lines and JPEG grid artifacts) are eliminated by subtracting column and row means:
$$W'(x, y) = W(x, y) - \frac{1}{N_x} \sum_{i=1}^{N_x} W(i, y) - \frac{1}{N_y} \sum_{j=1}^{N_y} W(x, j)$$

#### Circular Cross-Correlation and Peak-to-Correlation Energy (PCE)
The normalized circular cross-correlation between noise residual $W$ and reference sensor model $K$ is computed in the 2D frequency domain:
$$C = \mathcal{F}^{-1}\left( \frac{\mathcal{F}(W) \odot \mathcal{F}(K)^*}{\left|\mathcal{F}(W) \odot \mathcal{F}(K)^*\right|} \right)$$

Centering the correlation matrix $C(x,y)$ around spatial shifts, the PCE ratio quantifies peak distinctness relative to baseline cross-correlation noise:
$$\text{PCE} = \frac{C(x_{peak}, y_{peak})^2}{\frac{1}{|\Omega| - |\mathcal{N}|} \sum_{(x,y) \notin \mathcal{N}} C(x, y)^2}$$
where $\mathcal{N}$ represents an $11 \times 11$ exclusion zone centered on $(x_{peak}, y_{peak})$.

#### Theoretical False Alarm Rate (FAR)
Under Gaussian noise assumptions, the probability of false attribution given a measured PCE is:
$$\text{FAR} = \frac{1}{2} \text{erfc}\left( \sqrt{\frac{\text{PCE}}{2}} \right)$$
For $\text{PCE} \ge 60.0$, $\text{FAR} < 10^{-6}$, satisfying the Daubert standard for courtroom evidence attribution.

#### Maximum Likelihood Estimation (MLE) Reference Synthesis
For $M$ calibration images from a known suspect camera, the reference PRNU fingerprint $\hat{K}$ is synthesized by:
$$\hat{K} = \frac{\sum_{i=1}^M W_i \odot I_i}{\sum_{i=1}^M I_i^2}$$

---

### 2. Meta PDQ 256-Bit Perceptual Hashing and Metric Space Triage

Meta PDQ creates a 256-bit perceptual representation invariant under resizing, rotation adjustments ($<5^\circ$), compression, and luminance modification.

#### Transform Mechanics
1. **Preprocessing**: Convert image to grayscale $L$, resample to $64 \times 64$ using bilinear interpolation, and apply a $3 \times 3$ Box Blur to eliminate high-frequency aliasing.
2. **2D-DCT Projection**: A precomputed $16 \times 64$ orthonormal basis matrix $T$ projects the $64 \times 64$ spatial matrix $A$ into a $16 \times 16$ frequency domain matrix $D$:
   $$T(i, j) = \begin{cases} \frac{1}{\sqrt{64}} & i = 0 \\ \sqrt{\frac{2}{64}} \cos\left( \frac{(2j + 1) i \pi}{128} \right) & 1 \le i \le 15 \end{cases}$$
   $$D = T \cdot A \cdot T^T$$
3. **Median Thresholding**: Compute the median value $\tilde{m}$ of all AC coefficients ($D_{i,j}$ where $(i,j) \neq (0,0)$). The 256 binary hash bits $b_k$ are assigned:
   $$b_{16i + j} = \begin{cases} 1 & \text{if } D_{i, j} > \tilde{m} \\ 0 & \text{otherwise} \end{cases}$$

#### Burkhard-Keller Tree (BK-Tree) Similarity Search
BK-Trees organize metric spaces where distance satisfies non-negativity, symmetry, identity of indiscernibles, and the triangle inequality:
$$d(x, z) \le d(x, y) + d(y, z)$$

During a search with query hash $q$ and maximum Hamming distance $r$ ($r=31$ for standard PDQ matches), candidate evaluation is pruned. If the distance from query $q$ to current node $u$ is $d(u, q)$, child subtrees indexed by edge distance $k$ are traversed if and only if:
$$d(u, q) - r \le k \le d(u, q) + r$$
This reduces linear search complexity from $\mathcal{O}(N)$ to $\mathcal{O}(\log N)$, enabling sub-millisecond lookups across millions of threat hashes.

---

### 3. Calibrated Multi-Modal Bayesian Risk Fusion

Traditional forensic tools suffer from artificial probability inflation when multiple correlated indicators (e.g., ELA, DQT quantization, and DCT grid shift) fire simultaneously on a single compression artifact. LENSINT resolves this via Correlation Attenuation and Two-Sided Likelihood Ratios.

#### Mathematical Pipeline
1. **Prior Log-Odds**: Initialized from context-specific operational priors ($P_0$):
   $$\text{LLR}_0 = \ln\left( \frac{P_0}{1 - P_0} \right)$$
   Standard presets:
   - DFIR Incident Triage: $P_0 = 0.20$ ($\text{LLR}_0 = -1.386$)
   - Social Media OSINT: $P_0 = 0.05$ ($\text{LLR}_0 = -2.944$)
   - Courtroom Evidence: $P_0 = 0.50$ ($\text{LLR}_0 = 0.000$)
   - Malware Dropzone Sandbox: $P_0 = 0.75$ ($\text{LLR}_0 = 1.099$)

2. **Likelihood Ratio (LR) Weighting with Correlation Attenuation**:
   For each analytical indicator $i$ with True Positive Rate $\text{TPR}_i$, False Positive Rate $\text{FPR}_i$, and correlation group membership $g$:
   $$\text{LR}_i^+ = \frac{\text{TPR}_i}{\max(0.005, \text{FPR}_i)}, \quad \text{LR}_i^- = \frac{\max(0.05, 1 - \text{TPR}_i)}{\max(0.05, 1 - \text{FPR}_i)}$$
   The effective log-odds update is attenuated by the count of previously activated indicators in group $g$ ($c_g$):
   $$\alpha(c_g) = \frac{1}{1 + 1.5 \cdot c_g}$$
   $$\Delta \text{LLR}_i = \begin{cases} \ln(\text{LR}_i^+) \cdot \alpha(c_g) & \text{if indicator is positive} \\ \ln(\text{LR}_i^-) \cdot \alpha(c_g) \cdot 0.25 & \text{if indicator is negative} \end{cases}$$
   $$\text{LLR}_{k} = \text{LLR}_{k-1} + \Delta \text{LLR}_i$$

3. **Posterior Risk Mapping**:
   The final posterior probability $P(\text{Tampered} \mid \mathbf{E})$ is calculated via the logistic sigmoid:
   $$P(\text{Tampered} \mid \mathbf{E}) = \frac{1}{1 + e^{-\text{LLR}_{final}}}$$
   $$\text{Risk Score} = 100 \cdot P(\text{Tampered} \mid \mathbf{E})$$

---

### 4. Steganography Frequency Mechanics & Westfeld Chi-Square ($\chi^2$)

In standard baseline JPEG compression, spatial blocks undergo Discrete Cosine Transformation to yield 64 frequency coefficients. Steganographic tools modify the least significant bits of non-zero AC coefficients.

#### Pairs of Values (PoV) Goodness-of-Fit
LSB replacement pairs adjacent values ($2k \leftrightarrow 2k+1$). LSB overwriting equalizes the occurrence frequency of both values. Westfeld's $\chi^2$ test quantifies this equalization:
$$y_{2k}^* = \frac{y_{2k} + y_{2k+1}}{2}$$
$$\chi^2 = \sum_{k=1}^m \frac{(y_{2k} - y_{2k}^*)^2}{y_{2k}^*}$$
where $m$ is the count of distinct coefficient pairs and degrees of freedom $\nu = m - 1$. The $p$-value represents the probability that the observed distribution originated from natural unmodified pixels:
$$p = 1 - \int_0^{\chi^2} \frac{t^{\frac{\nu}{2} - 1} e^{-\frac{t}{2}}}{2^{\frac{\nu}{2}} \Gamma\left(\frac{\nu}{2}\right)} dt$$
Low $p$-values ($p < 0.01$) indicate active steganographic carrier modification.

---

## Data Flow & Concurrency Pipeline

The following sequence details how evidence traverses through memory allocation, concurrent worker threads, and report generation:

```
[Input Evidence] 
       │
       ▼
[ImageAnalyzer.__init__]
       │
       ├──> [load_image_safe] ───────> Validates dimensions, prevents Decompression Bombs
       │                                (Downsamples if pixels > 4M)
       │
       ├──> [analyze_integrity] ─────> Validates magic preambles, computes MD5/SHA1/SHA256/SHA512
       │
       ├──> [Cache Check] ───────────> Queries SHA-256 cache (returns on cache hit)
       │
       ├──> [ThreadPoolExecutor] ────> Spawns 5 concurrent worker threads:
       │        ├── Thread 1: analyze_metadata (EXIF, XMP, IPTC, Thumbnail SSIM)
       │        ├── Thread 2: analyze_stego (Overlay, LSB, Palette, RS Stego)
       │        ├── Thread 3: analyze_strings (ASCII/UTF-16 LE, IOC Regex)
       │        ├── Thread 4: analyze_ai_detect (2D-FFT, ONNX Runtime TruFor)
       │        ├── Thread 5: analyze_malware (YARA patterns, 1-byte XOR brute)
       │        └── (Sequential): analyze_ocr (Tesseract credential scanner)
       │
       ├──> [analyze_tampering] ─────> Physics ELA, Copy-Move ORB+RANSAC, DQT, CFA, Illumination
       │
       ├──> [C2StegoDetector] ───────> JSteg, F5, OutGuess, PNG chunk/CRC32 anomalies
       │
       ├──> [analyze_video] ─────────> ISOBMFF box hierarchy, GOP cadence break analysis
       │
       ├──> [analyze_pdq_triage] ────> 256-bit PDQ Hash, BK-Tree threat index search
       │
       ├──> [PRNU Engine] ───────────> 2D Wiener residual extraction, 1:N PCE device matching
       │
       ├──> [RFC 3161 TSP] ──────────> Generates ASN.1 DER TimeStampReq, queries accredited TSA
       │
       ├──> [Bayesian Fusion] ───────> Computes calibrated posterior risk score & verdict
       │
       └──> [Audit & Reporters] ─────> Writes chained ISO 27037 audit log entry
                                       Generates requested outputs:
                                       - FRE 702 PDF Expert Witness Report
                                       - Dark-Mode HTML Report
                                       - STIX 2.1 Threat Bundle
                                       - MISP JSON Threat Event
                                       - Deployable YARA Rule (.yar)
```

---

## Memory Safety & Security Guarantees

1. **Zero State Leakage**: Every analytical module accepts pure primitive byte buffers or isolated `PIL.Image` copies. No global mutable state is shared across worker threads.
2. **Decompression Bomb Guard**: Images exceeding 4 Megapixels are automatically downsampled using high-quality Lanczos resampling before heavy concurrent pixel transformations, eliminating memory allocation exhaustion.
3. **Execution Sandboxing**: Script and binary execution scanning is strictly non-invasive (static pattern extraction, disassembler parsing, and AST simulation); no untrusted code is dynamically executed outside sandboxed wrappers.
