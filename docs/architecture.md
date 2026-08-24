# LENSINT System Architecture, Data Flow, and Mathematical Foundations

## System Overview

LENSINT is architected as a modular, concurrent, and mathematically calibrated digital media forensics, network stream carving, and threat intelligence platform. The framework operates across headless batch and single-target CLI modes, volatile memory analysis plugins, network capture parsers, embedded forensic library integrations, and long-running REST API services.

The architectural principles emphasize:
1. **Thread-Safe Memory Isolation**: Concurrent execution of analytical extractors on independent deep copies of raw media buffers and packet payloads.
2. **Denial-of-Service (DoS) and Decompression Bomb Mitigation**: Safe pre-allocation scaling, dimension validation, and streaming byte thresholds.
3. **Calibrated Multi-Modal Bayesian Risk Fusion**: Mathematical integration of disparate heuristic and deterministic forensic indicators into an un-inflated posterior risk score.
4. **Cryptographic Traceability & Non-Repudiation**: End-to-end evidence hash tracking, ISO/IEC 27037 chained ledger audit seals, and RFC 3161 Time-Stamp Authority (TSA) attestation.

---

## High-Level Component Architecture

```
                                  +---------------------------------------+
                                  |         Digital Evidence Input        |
                                  | - Media Files (JPEG/PNG/WebP/MP4/RAW) |
                                  | - Memory Dumps (.raw, .dmp, .vmem)    |
                                  | - Network Captures (.pcap, .pcapng)   |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |        Safe Ingestion Pipeline        |
                                  | - Format Magic Signature Validation   |
                                  | - Decompression Bomb Defense (4 MP)   |
                                  | - SHA-256 Cache Query & Dedup         |
                                  +-------------------+-------------------+
                                                      |
         +--------------------------------------------+--------------------------------------------+
         |                                            |                                            |
         v                                            v                                            v
+-------------------------------+            +-------------------------------+            +-------------------------------+
|  Structural & Metadata Layer  |            |   Physics & Optical Layer     |            |   Stego & Frequency Layer     |
| - EXIF / XMP / IPTC Parsing   |            | - Multi-Scale ELA (Q=80,90,95)|            | - Pure Baseline JPEG DCT (SOF)|
| - Reverse Geocoding (OSM)     |            | - Copy-Move ORB + RANSAC      |            | - JSteg, F5 & OutGuess 0.2    |
| - Thumbnail SSIM Divergence   |            | - JPEG Ghost Surfaces         |            | - Westfeld Chi-Square (PoVs)  |
| - Temporal Chronology Tracker |            | - DQT Hardware Profiles       |            | - Calibrated RS Steganalysis  |
| - Container Atom Tree (ISOBMFF|            | - CFA Bayer Demosaicing       |            | - Spatial Rich Model (SRM 30) |
| - C2PA JUMBF Manifest Parser  |            | - PRNU Silicon Residuals (MLE)|            | - Steghide Symmetry Breaking  |
| - COSE Sign1 (RFC 9052) & X509|            | - Sensor Dust Invariant Map   |            | - OpenPuff Bitplane Entropy   |
| - Asset Binding Hash Validator|            | - Brown-Conrady Lens Curvature|            | - PNG Covert Chunks & CRC32   |
+---------------+---------------+            +---------------+---------------+            +---------------+---------------+
                |                                            |                                            |
                +--------------------------------------------+--------------------------------------------+
                                                             |
         +---------------------------------------------------+---------------------------------------------------+
         |                                                   |                                                   |
         v                                                   v                                                   v
+-------------------------------+           +-------------------------------+           +-------------------------------+
|  Biometrics & Deepfake Layer  |           | Perceptual Hash Triage (PDQ)  |           | Threat Intel, Memory & PCAP   |
| - rPPG CHROM & POS Pulse Wave |           | - 64x64 Resampling & Blur     |           | - Dual ASCII/UTF-16 & IOCs    |
| - 0.7-3.5 Hz Bandpass & SNR   |           | - 16x16 2D-DCT Transformation |           | - Static YARA & XOR Recovery  |
| - Multi-Region Phase Coherence|           | - 256-bit Median Quantization |           | - Tesseract OCR Secret Hunter |
| - EAR Poisson Blink Cadence   |           | - BK-Tree Metric Space Index  |           | - Volatility 3 VAD Carving    |
| - 3D Corneal Specular Glint   |           | - Triangle Inequality Pruning |           | - Live PCAP/PCAPNG Packet DPI |
| - ONNX Neural TruFor / CNN    |           +---------------+---------------+           | - TCP Reassembly & Carvers    |
+---------------+---------------+                           |                           +---------------+---------------+
                |                                           |                                           |
                +-------------------------------------------+-------------------------------------------+
                                                            |
                                                            v
                                            +-------------------------------+
                                            | Calibrated Bayesian Fusion    |
                                            | - Operational Prior Preset P0 |
                                            | - Two-Sided Likelihood Ratios |
                                            | - Correlation Group Decay a   |
                                            | - Sigmoidal Posterior Mapping |
                                            +---------------+---------------+
                                                            |
                                                            v
                                            +-------------------------------+
                                            | Cryptographic Custody Ledger  |
                                            | - ISO 27037 Chained SHA-256   |
                                            | - RFC 3161 DER Timestamp Seal |
                                            +---------------+---------------+
                                                            |
         +--------------------------------------------------+--------------------------------------------------+
         |                          |                               |                         |                |
         v                          v                               v                         v                v
+-----------------+        +-----------------+             +-----------------+       +-----------------+ +-------------+
| FRE 702 PDF     |        | Interactive     |             | Machine-Readable|       | STIX 2.1 Threat | | Deployable  |
| Expert Witness  |        | Dark-Mode HTML  |             | JSON Forensic   |       | Bundles & MISP  | | YARA Rule   |
| Court Report    |        | Forensic Report |             | Telemetry Stream|       | Threat Events   | | Sets (.yar) |
+-----------------+        +-----------------+             +-----------------+       +-----------------+ +-------------+
```

---

## Mathematical Foundations & Signal Mechanics

### 1. Photo-Response Non-Uniformity (PRNU) Camera Attribution

PRNU represents the deterministic physical silicon imperfection pattern unique to an individual camera sensor array.

#### Noise Residual Extraction
Given an input intensity matrix $I(x,y)$, the sensor noise residual $W$ is obtained by subtracting a denoised estimate $F(I)$ generated via a local adaptive spatial Wiener filter:
$$W(x, y) = I(x, y) - F(I(x, y))$$

The local noise variance $\sigma_0^2$ is estimated robustly using the Median Absolute Deviation (MAD) of the Laplacian filtered image:
$$\sigma_0 = \frac{\text{median}(|\nabla^2 I|)}{0.6745}, \quad \sigma_0^2 = \max\left(1.0, \sigma_0^2\right)$$

The adaptive Wiener weight for local mean $\mu_L$ and local variance $\sigma_L^2$ within a $5 \times 5$ window is:
$$F(I) = \mu_L + \frac{\max(0, \sigma_L^2 - \sigma_0^2)}{\sigma_L^2 + \epsilon} \cdot (I - \mu_L)$$

Non-PRNU linear artifacts (CMOS readout lines and JPEG grid artifacts) are eliminated by subtracting column and row means:
$$W'(x, y) = W(x, y) - \frac{1}{N_x} \sum_{i=1}^{N_x} W(i, y) - \frac{1}{N_y} \sum_{j=1}^{N_y} W(x, j)$$

#### Circular Cross-Correlation and Peak-to-Correlation Energy (PCE)
The normalized circular cross-correlation between noise residual $W$ and reference sensor model $K$ is computed in the 2D frequency domain:
$$C = \mathcal{F}^{-1}\left( \frac{\mathcal{F}(W) \odot \mathcal{F}(K)^*}{\left|\mathcal{F}(W) \odot \mathcal{F}(K)^*\right|} \right)$$

Centering the correlation matrix $C(x,y)$ around spatial shifts, the PCE ratio quantifies peak distinctness relative to baseline cross-correlation noise:
$$\text{PCE} = \frac{C(x_{\text{peak}}, y_{\text{peak}})^2}{\frac{1}{|\Omega| - |\mathcal{N}|} \sum_{(x,y) \notin \mathcal{N}} C(x, y)^2}$$
where $\mathcal{N}$ represents an $11 \times 11$ exclusion zone centered on $(x_{\text{peak}}, y_{\text{peak}})$.

#### Theoretical False Alarm Rate (FAR)
Under Gaussian noise assumptions, the probability of false attribution given a measured PCE is:
$$\text{FAR} = \frac{1}{2} \text{erfc}\left( \sqrt{\frac{\text{PCE}}{2}} \right)$$
For $\text{PCE} \ge 60.0$, $\text{FAR} < 10^{-6}$, satisfying the Daubert standard for courtroom evidence attribution.

#### Maximum Likelihood Estimation (MLE) Reference Synthesis
For $M$ calibration images from a known suspect camera, the reference PRNU fingerprint $\hat{K}$ is synthesized by:
$$\hat{K} = \frac{\sum_{i=1}^M W_i \odot I_i}{\sum_{i=1}^M I_i^2}$$

---

### 2. Sensor Dust Invariant Mapping & Optical Lens Curvature

Physical particles adhered to the camera sensor cover glass attenuate incident illumination according to a localized transmission model.

#### Optical Attenuation Modeling
$$\begin{aligned}
I_{\text{obs}}(x, y) &= I_{\text{scene}}(x, y) \cdot (1 - \Delta(x, y)) \\
\Delta(x, y) &\in [0.0, 1.0]
\end{aligned}$$
where $\Delta(x, y)$ represents the optical depth of the dust speck.

#### Multi-Scale Laplacian of Gaussian (LoG) Response
The scale-space representation is constructed via normalized 2D LoG kernels across scales $\sigma \in \{1.8, 2.8, 4.2\}$:
$$\text{LoG}_\sigma(x, y) = -\frac{1}{\pi \sigma^4} \left( 1 - \frac{x^2 + y^2}{2 \sigma^2} \right) \exp\left( -\frac{x^2 + y^2}{2 \sigma^2} \right)$$
$$\mathcal{R}(x, y, \sigma) = \sigma^2 \cdot \left( I \ast \text{LoG}_\sigma \right)(x, y)$$

Local maxima in scale-space identify candidate dust specks, which are filtered against high-pass Sobel scene texture gradients:
$$\|\nabla I(x, y)\| = \sqrt{G_x^2 + G_y^2} > \tau_{\text{edge}} \implies \text{Suppressed}$$

#### Minimum-Weight Bipartite Matching and Poisson Ballistics Coincidence
Between two candidate spot configurations $A = \{s_1^A, \dots, s_{N_A}^A\}$ and $B = \{s_1^B, \dots, s_{N_B}^B\}$, the assignment problem minimizes the spatial-depth cost:
$$\text{Cost}(s_i^A, s_j^B) = \|(x_i^A, y_i^A) - (x_j^B, y_j^B)\|_2 + 0.6 |r_i^A - r_j^B| + 15.0 |\Delta_i^A - \Delta_j^B|$$

The spatial coincidence probability under a 2D Poisson point process with sensor surface area $A_{\text{sensor}}$ and spatial matching radius $r_{\text{tol}}$ is:
$$\lambda = N_A N_B \frac{\pi r_{\text{tol}}^2}{A_{\text{sensor}}}$$
$$P_{\text{FA}} = P(X \ge k) = 1 - \sum_{i=0}^{k-1} \frac{\lambda^i e^{-\lambda}}{i!}$$
For $k \ge 5$ matched specks within $r_{\text{tol}} \le 4.0\text{ px}$, $P_{\text{FA}} < 10^{-5}$, providing definitive ballistic proof of common camera hardware origin.

#### Brown-Conrady Optical Lens Distortion Model
Physical camera lenses introduce radial and tangential geometric distortion:
$$\begin{aligned}
x_u &= x_d + (x_d - x_c)(k_1 r^2 + k_2 r^4) + [p_1(r^2 + 2(x_d - x_c)^2) + 2 p_2(x_d - x_c)(y_d - y_c)] \\
y_u &= y_d + (y_d - y_c)(k_1 r^2 + k_2 r^4) + [p_2(r^2 + 2(y_d - y_c)^2) + 2 p_1(x_d - x_c)(y_d - y_c)]
\end{aligned}$$
where $(x_c, y_c)$ is the optical principal point, $r^2 = (x_d - x_c)^2 + (y_d - y_c)^2$, $k_1, k_2$ are radial coefficients, and $p_1, p_2$ are tangential coefficients. Zero-distortion profiles ($|k_1| < 0.003$) combined with absence of sensor dust indicate synthetic rectilinear CGI or AI generation.

---

### 3. Biometric Remote Photoplethysmography (rPPG) & Video Deepfake Modeling

Human cardiac cycles modulate sub-visual micro-chrominance variations across facial capillary beds due to hemoglobin absorption of incident green/red light.

#### CHROM Chrominance Projection Mechanics
Given normalized temporal color traces $R_n(t), G_n(t), B_n(t)$ averaged over facial skin ROIs:
$$\begin{aligned}
X_s(t) &= 3 R_n(t) - 2 G_n(t) \\
Y_s(t) &= 1.5 R_n(t) + G_n(t) - 1.5 B_n(t) \\
\alpha(t) &= \frac{\sigma(X_s(t \pm \Delta t))}{\sigma(Y_s(t \pm \Delta t))} \\
S_{\text{CHROM}}(t) &= X_s(t) - \alpha(t) Y_s(t)
\end{aligned}$$

#### POS (Plane-Orthogonal-to-Skin) Subspace Projection
$$\begin{aligned}
P_1(t) &= G_n(t) - B_n(t) \\
P_2(t) &= -2 R_n(t) + G_n(t) + B_n(t) \\
\alpha(t) &= \frac{\sigma(P_1(t \pm \Delta t))}{\sigma(P_2(t \pm \Delta t))} \\
S_{\text{POS}}(t) &= P_1(t) + \alpha(t) P_2(t)
\end{aligned}$$

#### FFT Power Spectral Density (PSD) and Signal-to-Noise Ratio (SNR)
The extracted pulse waveform $S(t)$ is filtered in $[0.7\text{ Hz}, 3.5\text{ Hz}]$ ($42 - 210\text{ BPM}$). The SNR is calculated over the fundamental peak $f_1$ and harmonic $f_2 = 2 f_1$:
$$\text{SNR}_{\text{dB}} = 10 \log_{10}\left( \frac{\int_{f_1 - \delta}^{f_1 + \delta} \text{PSD}(f) df + \int_{f_2 - \delta}^{f_2 + \delta} \text{PSD}(f) df}{\int_{\text{band} \setminus \{f_1, f_2\}} \text{PSD}(f) df} \right)$$
Authentic human video exhibits $\text{SNR} > +2.0\text{ dB}$; synthetic generative deepfakes exhibit $\text{SNR} < -3.0\text{ dB}$.

#### Cross-Region Phase Coherence
The Pearson correlation between forehead pulse $S_{\text{FH}}(t)$ and cheek pulses $S_{\text{LC}}(t), S_{\text{RC}}(t)$ evaluates biological synchronization:
$$\gamma = \frac{1}{3} \left[ \rho(S_{\text{FH}}, S_{\text{LC}}) + \rho(S_{\text{FH}}, S_{\text{RC}}) + \rho(S_{\text{LC}}, S_{\text{RC}}) \right]$$
Biological blood flow produces $\gamma > 0.65$; synthetic face swaps exhibit regional phase desynchronization ($\gamma < 0.35$).

#### Eye Aspect Ratio (EAR) Poisson Process Modeling
Inter-Blink Intervals (IBI) for natural human blinking follow an exponential distribution corresponding to a Poisson arrival process:
$$f(t; \lambda) = \lambda e^{-\lambda t}, \quad t \ge 0$$
$$\text{Fano Factor} = \frac{\text{Var}(\text{IBI})}{\mathbb{E}[\text{IBI}]^2} \approx 1.0$$
Deepfake face generators exhibit deterministic periodic blinking ($\text{Var} < 0.05$), high-frequency flicker ($\text{Fano} > 15.0$), or complete blink suppression over extended duration.

---

### 4. Spatial Rich Model (SRM) & Content-Adaptive Steganalysis

Content-adaptive steganography algorithms (S-UNIWARD, WOW, HILL, MiPOD) minimize embedding distortion in high-pass spatial textures.

#### SRM Directional Residual Convolutions
The Spatial Rich Model applies 30 linear and non-linear convolution kernels $K_m$ to isolate directional image residuals:
$$R_m(x, y) = (I \ast K_m)(x, y)$$

Kernels include 1st-order gradients, 2nd-order Laplacians, 3rd-order directional derivatives, and non-linear min/max operations:
$$R_{\min}(x, y) = \min(|R_{\text{horiz}}(x, y)|, |R_{\text{vert}}(x, y)|)$$
$$R_{\max}(x, y) = \max(|R_{\text{horiz}}(x, y)|, |R_{\text{vert}}(x, y)|)$$

#### Quantized-Truncated 4D Co-occurrence Matrices
Residuals are quantized with step $q = 1.5$ and truncated at threshold $T = 2$:
$$r(x, y) = \text{clip}\left( \text{round}\left( \frac{R_m(x, y)}{q} \right), -T, T \right)$$

The horizontal transition probability matrix $P(u, v)$ over adjacent bins $u, v \in \{-T, \dots, T\}$ computes the transition entropy:
$$H_T = -\sum_{u=-T}^T \sum_{v=-T}^T P(u, v) \log_2 P(u, v)$$
Adaptive steganographic embedding increases residual transition entropy beyond natural baseline thresholds ($H_T > 0.78$), providing a direct metric to estimate embedding rate in bits per pixel (bpp).

---

### 5. Meta PDQ 256-Bit Perceptual Hashing & Metric Space Triage

Meta PDQ creates a 256-bit perceptual representation invariant under resizing, moderate rotation, compression, and luminance modification.

#### Transform Mechanics
1. **Preprocessing**: Grayscale conversion, $64 \times 64$ bilinear downsampling, and $3 \times 3$ Box Blur anti-aliasing.
2. **2D-DCT Projection**: A precomputed $16 \times 64$ orthonormal basis matrix $T$ projects the spatial matrix $A$ into a $16 \times 16$ frequency domain matrix $D$:
   $$T(i, j) = \begin{cases} \frac{1}{\sqrt{64}} & i = 0 \\ \sqrt{\frac{2}{64}} \cos\left( \frac{(2j + 1) i \pi}{128} \right) & 1 \le i \le 15 \end{cases}$$
   $$D = T \cdot A \cdot T^T$$
3. **Median Quantization**: Compute median $\tilde{m}$ of all non-DC coefficients ($D_{i,j}, (i,j) \neq (0,0)$). Binary bits $b_k$ are assigned:
   $$b_{16i + j} = \begin{cases} 1 & \text{if } D_{i, j} > \tilde{m} \\ 0 & \text{otherwise} \end{cases}$$

#### Burkhard-Keller Tree (BK-Tree) Metric Space Search
BK-Trees organize metric spaces where distance satisfies the triangle inequality:
$$d(x, z) \le d(x, y) + d(y, z)$$

For query hash $q$ with maximum Hamming distance $r=31$, candidate branches at node $u$ are traversed if and only if edge distance $k$ satisfies:
$$d(u, q) - r \le k \le d(u, q) + r$$
This reduces linear search complexity from $\mathcal{O}(N)$ to $\mathcal{O}(\log N)$, enabling sub-millisecond similarity lookups across millions of threat hashes.

---

### 6. Calibrated Multi-Modal Bayesian Risk Fusion

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
   $$P(\text{Tampered} \mid \mathbf{E}) = \frac{1}{1 + e^{-\text{LLR}_{\text{final}}}}$$
   $$\text{Risk Score} = 100 \cdot P(\text{Tampered} \mid \mathbf{E})$$

---

## Data Flow & Concurrency Pipeline

```
[Input Evidence (Image, Video, Memory Dump, PCAP)]
       │
       ▼
[ImageAnalyzer.__init__]
       │
       ├──> [load_image_safe] ───────> Validates dimensions, prevents Decompression Bombs
       │                                (Downsamples if pixels > 4 Megapixels)
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
       ├──> [C2PA Engine] ───────────> ISO/IEC 19566-5 JUMBF boxes, CBOR, COSE Sign1 (RFC 9052)
       │
       ├──> [Biometric rPPG] ────────> Video CHROM/POS pulse waveforms, SNR, EAR Poisson blinks
       │
       ├──> [Optics & Dust Engine] ──> Multi-scale LoG dust maps, Brown-Conrady lens distortion
       │
       ├──> [Neural Stego (SRM)] ────> 30 directional residual convolutions, Steghide & OpenPuff
       │
       ├──> [PCAP Stream Carver] ────> Live packet parser, TCP stream reassembler, HTTP/SMB carving
       │
       ├──> [C2StegoDetector] ───────> Baseline JPEG SOF0 DCT, JSteg, F5, OutGuess, PNG chunks
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
                                       - Dark-Mode Interactive HTML Report
                                       - Machine-Readable JSON Forensic Stream
                                       - STIX 2.1 Threat Intelligence Bundle
                                       - MISP JSON Threat Event
                                       - Deployable YARA Detection Rules (.yar)
```

---

## Memory Safety & Security Guarantees

1. **Zero State Leakage**: Every analytical module accepts pure primitive byte buffers or isolated `PIL.Image` copies. No global mutable state is shared across worker threads.
2. **Decompression Bomb Guard**: Images exceeding 4 Megapixels are automatically downsampled using high-quality Lanczos resampling before heavy concurrent pixel transformations, eliminating memory allocation exhaustion.
3. **Execution Sandboxing**: Script and binary execution scanning is strictly non-invasive (static pattern extraction, disassembler parsing, and AST simulation); no untrusted code is dynamically executed outside sandboxed wrappers.
4. **Packet Stream Bounded Allocation**: The PCAP TCP reassembly engine enforces sequence window bounds and maximum carved asset count limits to prevent memory exhaustion during gigabyte packet capture ingestion.
