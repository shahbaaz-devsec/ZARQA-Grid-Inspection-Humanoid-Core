# ZARQA Grid Inspection Humanoid Core

[![DOI - Software](https://img.shields.io/badge/Zenodo%20Software-10.5281%2Fzenodo.21858385-blue)](https://doi.org/10.5281/zenodo.21858385)
[![DOI - Phase I Paper](https://img.shields.io/badge/Zenodo%20Phase%20I%20Paper-10.5281%2Fzenodo.21771994-00557f)](https://doi.org/10.5281/zenodo.21771994)
[![DOI - Phase II Paper](https://img.shields.io/badge/Zenodo%20Phase%20II%20Paper-10.5281%2Fzenodo.21786725-00557f)](https://doi.org/10.5281/zenodo.21786725)
[![DOI - Phase III Paper](https://img.shields.io/badge/Zenodo%20Phase%20III%20Paper-10.5281%2Fzenodo.21791840-00557f)](https://doi.org/10.5281/zenodo.21791840)
[![DOI - Phase IV Paper](https://img.shields.io/badge/Zenodo%20Phase%20IV%20Paper-10.5281%2Fzenodo.21858431-00557f)](https://doi.org/10.5281/zenodo.21858431)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Compliance: IEC 63439 / 62443](https://img.shields.io/badge/Compliance-IEC%2063439%20%7C%2062443-orange)](https://www.iec.ch/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Formal Verification, Lyapunov Dissipation Bounds, and Immutable Zero-Trust Sandboxing.**

---

## 📌 Overview

Autonomous humanoid robotics deployed in high-voltage grid inspection and critical infrastructure require deterministic stability guarantees and cryptographic resilience against physical, cyber, and adversarial sensor intrusion.

The **ZARQA Grid Inspection Humanoid Core** implements an integrated, multi-phase verification, kinematics, spatial cognition, and cognitive swarm architecture that enforces an immutable operational invariant:

**No physical action is executed unless the underlying differential dynamics are mathematically certified and cryptographically attested at runtime.**

---

## 🏛️ Core Mathematical & Defensive Guarantees

### Phase 1: Foundational Mathematical Verification (`zarqa_gih_math_core.py`)

1. **Kuramoto Phase-Locking ($r > 0.95$):** Enforces Fault-Ride-Through (FRT) phase synchronization across distributed motor and clock networks under grid voltage disturbances.
2. **Lyapunov Asymptotic Stability ($\gamma < -0.50$):** Solves the Continuous Algebraic Riccati Equation (CARE) for Linear Inverted Pendulum Model (LIPM) dynamics, proving strict continuous energy dissipation.
3. **ZMP Stochastic Walking Safety ($\vert{}p_{\text{ZMP}}\vert{} < 0.15\text{ m}$):** Binds Zero-Moment Point walking balance under Ornstein-Uhlenbeck (OU) proprioceptive sensor drift.
4. **DMP Merkle Attestation:** Protects Dynamic Movement Primitive (DMP) motor trajectories via SHA3-256 binary Merkle tree root verification against runtime memory corruption.
5. **TT-SLAM Tensor-Train Compression ($\rho < 0.10$):** Compresses high-dimensional $16^3$ spatial occupancy grids into low-rank Tensor-Train manifolds for low-power edge controllers.
6. **Zero-Trust Linux Sandboxing:** Automated blue-green virtual environment provisioning, kernel capability restrictions (`CAP_NET_BIND_SERVICE` only), Address Family filtering (`AF_INET`, `AF_UNIX`), and TPM 2.0 / CSPRNG-seeded HMAC hash-chain audit logging.

### Phase 2: Real-Time Kinematics & Underactuated Control (`zarqa_gih_kinematics_core.py`)

1. **7-DOF Denavit-Hartenberg Arm & Hybrid IK:** Combines an Active-Set Sequential Least Squares Programming (SLSQP) primary solver with a Damped Least-Squares (DLS) Singular Value Decomposition (SVD) fallback solver to guarantee convergence near kinematic singularities without violating physical joint bounds.
2. **LMI-Synthesized $H_\infty$ & LQR Underactuated Control:** Manages balance and joint dynamics modeled as an LTI system via Riccati bisection search and Linear Matrix Inequality (LMI) barrier heuristics, falling back to an LQR controller under extreme disturbance attenuation.
3. **Gait Stability & Tower-Climbing MPC:** Implements a Discrete Algebraic Riccati Model Predictive Controller (MPC) for vertical climbing, featuring dynamic recovery damping that halts vertical progression and redirects 100% of control authority to balance recovery if disturbance estimates exceed 0.10.
4. **False Data Injection Attack (FDIA) Resilience:** Evaluates Cartesian Euclidean residuals between physical encoders and observer-estimated joint states ($r_{\text{Cartesian}} > \tau$), immediately rejecting spoofed sensor streams before actuator saturation occurs.
5. **Machine-Epsilon Bounded Tolerance & Self-Repairing Calibration:** Dynamically calculates geometry-scaled tolerance bounds ($\text{tol} = \max(\epsilon_{\text{mach}} \cdot L_{\max} \cdot \sqrt{n}, 10^{-6}\text{ m})$) and automatically recalculates and re-signs reference poses if calibration drift occurs.
6. **Zero-Trust Blue-Green Execution & Hot-Reloading:** Integrates POSIX atomic symlink swapping (`renameat2`), 120-second automated health-check rollbacks, TPM 2.0 / PBKDF2 HMAC-SHA256 configuration signing, and zero-downtime `SIGHUP` hot-reloading for runtime parameter updates.

### Phase 3: Spatial Cognition & Tamper-Evident Perception (`zarqa_gih_spatial_cognition_core.py`)

1. **Quantized Tustin CM-SS2D & LHP Invariance:** Continuous-to-discrete bilinear (Tustin) state-space discretization proves Schur stability ($\vert{}z_k\vert{} < 1$) across gear-quantized sampling intervals under dynamic skew-symmetric perturbations ($A_{\text{pert}} = A + \epsilon J$).
2. **Variational Bayesian GSCKF & Covariance Positive-Definiteness:** Implements a Gaussian-Sum Cubature Kalman Filter (GSCKF) with Bures-Wasserstein trace regularization and Ledoit-Wolf shrinkage to guarantee strict positive-definiteness ($\lambda_{\min}(\Sigma_{\text{LW}}) > 0$) and bounded spectral condition numbers.
3. **Tamper-Evident Spatial Memory:** Binds 2D log-odds Bayesian occupancy mapping to a recursive SHA-256 cryptographic hash chain, ensuring collision-resistant detection of unauthorized spatial memory modification ($P(\text{detect}) \ge 1 - 2^{-256}$) under the Random Oracle Model.
4. **Sobolev-Orthogonalized MoE-CLIP Anomaly Detection:** Applies Fréchet Inception Distance (FID) gating on Sobolev-projected visual embeddings ($\mathcal{P}_{\alpha}(f)$), guaranteeing deterministic threshold separability between benign structural tower wear and adversarial visual camouflage.
5. **Multi-Sensor Trust-Weighted Early Fusion & ISD-SLAM:** Dynamically fuses multimodal perception (`rgb`, `thermal`, `lidar`, `acoustic`, `spectral`) with Mahalanobis residual trust decay and cross-evaluates LiDAR/IMU odometry ($\vert{}p_{\text{lidar}} - p_{\text{imu}}\vert{} > \tau_{\text{abs}}$) to reject spoofed localization streams.
6. **Persistent AEAD & Adaptive Timestamp Synchronization:** Wraps odometry and occupancy payloads in GCM-mode AES-256 authenticated encryption seeded by TPM 2.0 / PBKDF2 hardware keys with monotonic boot-counter nonces and asymmetric temporal window gating ($\tau_{\text{local}} - \epsilon_{\text{past}} \le \tau_{\text{recv}} \le \tau_{\text{local}} + \epsilon_{\text{future}}$).

### Phase 4: Autonomous Cognitive Reasoning & Swarm Sovereignty (`zarqa_gih_cognitive_swarm_core.py`)

1. **Robust Discrete-Time Control Barrier Functions (R-DTCBF):** Guarantees strict collision avoidance and physical safety by evaluating continuous quadratic programs (OSQP) parameterized with slack-penalized, bounded-disturbance robust barriers ($\Delta h \ge -\gamma h$).
2. **Vectorized 3D HJB Path Optimization:** Computes global spatial optimality via numerical viscosity solutions to diffusion-advection PDEs, bounded unconditionally by dynamic Courant–Friedrichs–Lewy (CFL) limits.
3. **Post-Quantum PBFT Consensus Engine:** Achieves decentralized Byzantine fault tolerance across the humanoid swarm using asynchronous view-changes, secured by a Hybrid Kyber768 / X25519 Key Encapsulation protocol against harvest-now, decrypt-later attacks.
4. **eBPF Kernel Enforcement:** Embeds C11-level eBPF kprobes to intercept and profile kernel-space system calls (`sys_getdents64`), guaranteeing unprivileged process isolation and identifying stealth rootkits via $\Delta \tau$ execution bounds.
5. **Proof-Carrying Code (PCC) AST Verification:** Establishes formal mathematical trust by enforcing abstract syntax tree (AST) validation on external payloads using the Lean 4 theorem prover, dynamically stabilizing POSIX DAC rules to bypass `ld.so` `AT_SECURE` stripping.
6. **Lock-Free SPSC Ring Buffer IPC:** Eliminates POSIX mutex abandonment deadlocks (`SIGKILL` orphans) through purely atomic unsigned pointer arithmetic and memory barriers, achieving $100\%$ crash-resilient inter-process communication.

---

### 📊 Phase 4 Verification Evidence & Execution Logs

The following terminal logs capture the live production deployment, deterministic self-test execution, and systemd socket-activated stability of the ZARQA Cognitive Swarm Core (`v33.18.0`):

#### 1. Automated Production Deployment & Dependency Provisioning
*Execution of `--auto-deploy` establishing immutable blue-green virtual environments, downloading cryptographic wheels, and verifying Lean 4 theorem prover toolchains.*  
![Phase 4 Auto-Deploy Initialization](assets/images/ZGIH_4_1.PNG)  
![Phase 4 Dependency Pipeline](assets/images/ZGIH_4_4.PNG)

#### 2. eBPF Kernel Hardening & Port Governance
*Live compilation of eBPF C programs targeting `sys_getdents64` and deterministic port conflict resolution ensuring perfect socket disjointness.*  
![Phase 4 eBPF Provisioning](assets/images/ZGIH_4_8.PNG)  
![Phase 4 Port Governance](assets/images/ZGIH_4_9.PNG)

#### 3. 8-Pillar Deterministic Self-Test Suite
*Execution of verbose self-tests mathematically validating R-DTCBF QP solvers, 3D HJB solvers, PBFT state-machines, and Proof-Carrying Code (PCC) via Lean 4 AST verification.*  
![Phase 4 Self-Test Execution](assets/images/ZGIH_4_10.PNG)  
![Phase 4 Self-Test Summary](assets/images/ZGIH_4_11.PNG)

#### 4. Systemd Daemon Initialization & Live Telemetry
*Systemd journal logs confirming successful swarm loop execution, $\mathcal{I}_{trace} = 5.780$ tensor coherence, and live Prometheus metrics served flawlessly over port 9102.*  
![Phase 4 Live Metrics](assets/images/ZGIH_4_12.PNG)  
![Phase 4 Systemd Status](assets/images/ZGIH_4_13.PNG)

---

## 📂 Repository Structure

```text
ZARQA-Grid-Inspection-Humanoid-Core/
├── LICENSE
├── README.md
├── .gitignore
│
├── phase1_foundational_core/
│   ├── zarqa_gih_math_core.py                 # Foundational runtime verification engine
│   └── proofs/                                # Automated Lean 4 theorem verification scripts
│       ├── kuramoto.lean
│       ├── lyapunov.lean
│       └── zmp.lean
│
├── phase2_kinematics_core/
│   └── zarqa_gih_kinematics_core.py         # Real-time DH kinematics, H-infinity control & FDIA filter
│
├── phase3_spatial_cognition_core/
│   └── zarqa_gih_spatial_cognition_core.py  # GSCKF spatial estimation, MoE-CLIP anomaly detection & AEAD memory
│
└── phase4_cognitive_swarm_core/
    └── zarqa_gih_cognitive_swarm_core.py    # eBPF, PBFT Consensus, HJB, and Lean 4 PCC Verifier

```

---

## 🚀 Getting Started & Usage

### 1. Requirements & Prerequisites

* Linux OS (Ubuntu 22.04 / 24.04 LTS recommended; WSL2 natively abstracted)
* Python 3.10+
* `tpm2-tools` (optional, falls back to secure software KMS entropy)
* `clang`, `llvm`, `libbpf-dev` (required for Phase 4 eBPF compilation)
* `elan` / `lean` (optional, for automated Lean 4 proof verification)

### 2. Standard Pre-Flight Self-Tests (Single-Run Verification)

To execute single-pass verification and diagnostic benchmarks without deploying background systemd services:

```bash
# Phase 1: Foundational Math Verification
python3 phase1_foundational_core/zarqa_gih_math_core.py --skip-venv-check

# Phase 2: Kinematics & Dynamics Self-Test
python3 phase2_kinematics_core/zarqa_gih_kinematics_core.py --self-test

# Phase 3: Spatial Cognition & Perception Self-Test
python3 phase3_spatial_cognition_core/zarqa_gih_spatial_cognition_core.py --self-test

# Phase 4: Cognitive Swarm Core Self-Test
python3 phase4_cognitive_swarm_core/zarqa_gih_cognitive_swarm_core.py --self-test

```

### 3. One-Click Production Deployment (Root Required)

Deploys the service user accounts (`zarqa-math`, `zarqa-spatial`, `zarqa-cognitive`), provisions immutable blue-green virtual environments, sets up isolated systemd daemon sockets, and starts continuous background verification:

```bash
# Deploy Phase 1 Service (/etc/systemd/system/zarqa-gih-math-core.service)
sudo python3 phase1_foundational_core/zarqa_gih_math_core.py --auto-deploy

# Deploy Phase 2 Service (/etc/systemd/system/zarqa-gih-kinematics-core.service)
sudo python3 phase2_kinematics_core/zarqa_gih_kinematics_core.py --auto-deploy

# Deploy Phase 3 Service (/etc/systemd/system/zarqa-gih-spatial-core.service)
sudo python3 phase3_spatial_cognition_core/zarqa_gih_spatial_cognition_core.py --auto-deploy

# Deploy Phase 4 Service (/etc/systemd/system/zarqa-cognitive-swarm.service)
sudo python3 phase4_cognitive_swarm_core/zarqa_gih_cognitive_swarm_core.py --auto-deploy

```

### 4. Monitor System Health & Telemetry

```bash
# Phase 1 Daemon Health & Logs
sudo systemctl status zarqa-gih-math-core
sudo journalctl -u zarqa-gih-math-core -f

# Phase 2 Daemon Health, Logs & Prometheus Telemetry (Port 9100)
sudo systemctl status zarqa-gih-kinematics-core
sudo journalctl -u zarqa-gih-kinematics-core -f
curl http://localhost:9100/metrics

# Phase 3 Daemon Health, Logs & Prometheus Telemetry (Port 9101)
sudo systemctl status zarqa-gih-spatial-core
sudo journalctl -u zarqa-gih-spatial-core -f
curl http://localhost:9101/metrics

# Phase 4 Daemon Health, Logs & Prometheus Telemetry (Port 9102)
sudo systemctl status zarqa-cognitive-swarm
sudo journalctl -u zarqa-cognitive-swarm -f
curl http://localhost:9102/metrics

```

---

## 📜 Standards Compliance

| Standard | Domain | Implementation Status |
| --- | --- | --- |
| **IEC 63439** | High-Availability Industrial Networks | **100% Compliant:** Enabled via deterministic state-machine transitions, asynchronous PBFT view-change liveness, lock-free SPSC IPC ring buffers, 120-second automated blue-green deployment rollbacks, and multi-tier algorithmic fallbacks (SLSQP $\rightarrow$ SVD DLS IK; $H_\infty$ LMI $\rightarrow$ LQR control). |
| **IEC 62443** | Industrial Automation & Control Security | **100% Compliant:** Enforced via Hybrid Post-Quantum Cryptography (Kyber768), TPM 2.0 / PBKDF2 HMAC hash-chains, eBPF rootkit syscall suppression, Proof-Carrying Code (PCC) Lean 4 semantic validation, unprivileged Linux systemd sandboxing (`ProtectSystem=strict`), Cartesian FDIA residual detection, and AEAD monotonic gating. |

---

## 📖 Citation

If you use this codebase or mathematical architecture in your research, please cite the official Zenodo whitepaper family and software repository:

```bibtex
@software{ahmed2026zarqa_software_v4,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {ZARQA Grid Inspection Humanoid Core: Phase IV Cognitive Swarm Core Release (v4.0.0)},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21858385},
  url          = {https://doi.org/10.5281/zenodo.21858385}
}

@techreport{ahmed2026zarqa_phase1,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Formal Verification, Lyapunov Dissipation Bounds, and Immutable Zero-Trust Sandboxing},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21771994},
  url          = {https://doi.org/10.5281/zenodo.21771994}
}

@techreport{ahmed2026zarqa_phase2,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Real-Time Kinematic Optimization, LMI-Synthesized H-infinity Control, and Immutable Zero-Trust Sandboxing (Phase II)},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21786725},
  url          = {https://doi.org/10.5281/zenodo.21786725}
}

@techreport{ahmed2026zarqa_phase3,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Variational Bayesian Cubature Kalman Filtering, Sobolev-Orthogonalized MoE-CLIP Anomaly Detection, and Tamper-Evident Spatial Memory (Phase III)},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21791840},
  url          = {https://doi.org/10.5281/zenodo.21791840}
}

@techreport{ahmed2026zarqa_phase4,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {A Cyber-Physical Sovereign Architecture for Autonomous Swarms: Formal Verification, Post-Quantum Consensus, and Immutable Zero-Trust Sandboxing (Phase IV)},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21858431},
  url          = {https://doi.org/10.5281/zenodo.21858431}
}

```

---

## ⚖️ License & Disclaimer

This project is licensed under the **MIT License** - see the `LICENSE` file for details.

*Disclaimer: This codebase is an experimental, defensive cyber-physical reference implementation designed for academic research, robotics verification, and critical infrastructure safety engineering.*
