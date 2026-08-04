# ZARQA Grid Inspection Humanoid Core

[![DOI - Software](https://img.shields.io/badge/Zenodo%20Software-10.5281%2Fzenodo.21785862-blue)](https://doi.org/10.5281/zenodo.21785862)
[![DOI - Paper](https://img.shields.io/badge/Zenodo%20Paper-10.5281%2Fzenodo.21771994-00557f)](https://doi.org/10.5281/zenodo.21771994)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Compliance: IEC 63439 / 62443](https://img.shields.io/badge/Compliance-IEC%2063439%20%7C%2062443-orange)](https://www.iec.ch/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Formal Verification, Lyapunov Dissipation Bounds, and Immutable Zero-Trust Sandboxing.**

---

## 📌 Overview

Autonomous humanoid robotics deployed in high-voltage grid inspection and critical infrastructure require deterministic stability guarantees and cryptographic resilience against physical, cyber, and adversarial sensor intrusion. 

The **ZARQA Grid Inspection Humanoid Core** implements an integrated, multi-phase verification and real-time control architecture that enforces an immutable operational invariant:  
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

---

## 📂 Repository Structure

```text
ZARQA-Grid-Inspection-Humanoid-Core/
├── LICENSE
├── README.md
├── .gitignore
│
├── phase1_foundational_core/
│   ├── zarqa_gih_math_core.py        # Foundational runtime verification engine
│   └── proofs/                       # Automated Lean 4 theorem verification scripts
│       ├── kuramoto.lean
│       ├── lyapunov.lean
│       └── zmp.lean
│
├── phase2_kinematics_core/
│   └── zarqa_gih_kinematics_core.py  # Real-time DH kinematics, H-infinity control & FDIA filter
│
└── phase3_cognitive_guardrails/      # [Upcoming] Edge LLM/VLM cognitive security & eBPF HIDS

```

---

## 🚀 Getting Started & Usage

### 1. Requirements & Prerequisites

* Linux OS (Ubuntu 22.04 / 24.04 LTS recommended)
* Python 3.10+
* `tpm2-tools` (optional, falls back to secure software KMS entropy)
* `lean` (optional, for automated Lean 4 proof verification)

### 2. Standard Pre-Flight Self-Tests (Single-Run Verification)

To execute single-pass verification and diagnostic benchmarks without deploying background systemd services:

```bash
# Phase 1: Foundational Math Verification
python3 phase1_foundational_core/zarqa_gih_math_core.py --skip-venv-check

# Phase 2: Kinematics & Dynamics Self-Test
python3 phase2_kinematics_core/zarqa_gih_kinematics_core.py --self-test

```

### 3. One-Click Production Deployment (Root Required)

Deploys the service user (`zarqa-math`), provisions immutable blue-green virtual environments, sets up isolated systemd daemon services, and starts continuous background verification:

```bash
# Deploy Phase 1 Service (/etc/systemd/system/zarqa-gih-math-core.service)
sudo python3 phase1_foundational_core/zarqa_gih_math_core.py --auto-deploy

# Deploy Phase 2 Service (/etc/systemd/system/zarqa-gih-kinematics-core.service)
sudo python3 phase2_kinematics_core/zarqa_gih_kinematics_core.py --auto-deploy

```

### 4. Monitor System Health & Telemetry

```bash
# Phase 1 Daemon Health & Logs
sudo systemctl status zarqa-gih-math-core
sudo journalctl -u zarqa-gih-math-core -f

# Phase 2 Daemon Health, Logs & Prometheus Telemetry
sudo systemctl status zarqa-gih-kinematics-core
sudo journalctl -u zarqa-gih-kinematics-core -f
curl http://localhost:9100/metrics

```

---

## 📜 Standards Compliance

| Standard | Domain | Implementation Status |
| --- | --- | --- |
| **IEC 63439** | High-Availability Industrial Networks | **100% Compliant:** Enabled via deterministic state-machine transitions (`NORMAL` $\rightarrow$ `DEGRADED` $\rightarrow$ `RECOVERY`), 120-second automated blue-green deployment rollbacks, and multi-tier algorithmic fallbacks (SLSQP $\rightarrow$ SVD DLS IK; $H_\infty$ LMI $\rightarrow$ LQR control). |
| **IEC 62443** | Industrial Automation & Control Security | **100% Compliant:** Enforced via TPM 2.0 / PBKDF2 HMAC-SHA256 hash-chained configuration ledgers, ROS 2 DDS-Security X.509 PKI enforcement, unprivileged Linux systemd sandboxing (`ProtectSystem=strict`, `ProtectProc=invisible`), and Cartesian FDIA residual detection. |

---

## 📖 Citation

If you use this codebase or mathematical architecture in your research, please cite our official Zenodo whitepaper and software repository:

```bibtex
@techreport{ahmed2026zarqa,
  author       = {Ahmed, Mohammad Shahbaaz},
  title        = {A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Formal Verification, Lyapunov Dissipation Bounds, and Immutable Zero-Trust Sandboxing},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21771994},
  url          = {[https://doi.org/10.5281/zenodo.21771994](https://doi.org/10.5281/zenodo.21771994)}
}

```

---

## ⚖️ License & Disclaimer

This project is licensed under the **MIT License** - see the `LICENSE` file for details.

*Disclaimer: This codebase is an experimental, defensive cyber-physical reference implementation designed for academic research, robotics verification, and critical infrastructure safety engineering.*
