# ZARQA Grid Inspection Humanoid Core

[![DOI - Software](https://img.shields.io/badge/Zenodo%20Software-10.5281%2Fzenodo.21772641-blue)](https://doi.org/10.5281/zenodo.21772641)
[![DOI - Paper](https://img.shields.io/badge/Zenodo%20Paper-10.5281%2Fzenodo.21771994-00557f)](https://doi.org/10.5281/zenodo.21771994)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Compliance: IEC 63439 / 62443](https://img.shields.io/badge/Compliance-IEC%2063439%20%7C%2062443-orange)](https://www.iec.ch/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **A Cyber-Physical Sovereign Architecture for Autonomous Grid-Inspection Humanoids: Formal Verification, Lyapunov Dissipation Bounds, and Immutable Zero-Trust Sandboxing.**

---

## 📌 Overview

Autonomous humanoid robotics deployed in high-voltage grid inspection and critical infrastructure require deterministic stability guarantees and cryptographic resilience against physical, cyber, and adversarial AI intrusion. 

The **ZARQA Grid Inspection Humanoid Core** implements a real-time verification and deployment engine that enforces an immutable operational invariant:  
**No physical action is executed unless the underlying differential dynamics are mathematically certified and cryptographically attested at runtime.**

---

## 🏛️ Core Mathematical & Defensive Guarantees (Phase 1)

This repository houses the Phase 1 foundational engine (`zarqa_gih_math_core.py`), unifying five distinct mathematical proofs and zero-trust OS sandboxing:

1. **Kuramoto Phase-Locking ($r > 0.95$):** Enforces Fault-Ride-Through (FRT) phase synchronization across distributed motor and clock networks under grid voltage disturbances.
2. **Lyapunov Asymptotic Stability ($\gamma < -0.50$):** Solves the Continuous Algebraic Riccati Equation (CARE) for Linear Inverted Pendulum Model (LIPM) dynamics, proving strict energy dissipation.
3. **ZMP Stochastic Walking Safety ($\vert{}p_{\text{ZMP}}\vert{} < 0.15\text{ m}$):** Binds Zero-Moment Point walking balance under Ornstein-Uhlenbeck (OU) proprioceptive sensor drift.
4. **DMP Merkle Attestation:** Protects Dynamic Movement Primitive (DMP) motor trajectories via SHA3-256 binary Merkle tree root verification against runtime memory corruption.
5. **TT-SLAM Tensor-Train Compression ($\rho < 0.10$):** Compresses high-dimensional $16^3$ spatial occupancy grids into low-rank Tensor-Train manifolds for low-power edge controllers.
6. **Zero-Trust Linux Sandboxing:** Automated blue-green virtual environment provisioning, kernel capability restrictions (`CAP_NET_BIND_SERVICE` only), Address Family filtering (`AF_INET`, `AF_UNIX`), and TPM 2.0 / CSPRNG-seeded HMAC hash-chain audit logging.

---

## 📂 Repository Structure

```text
ZARQA-Grid-Inspection-Humanoid-Core/
├── LICENSE
├── README.md
├── .gitignore
│
├── phase1_foundational_core/
│   ├── zarqa_gih_math_core.py        # Main runtime verification & deployment engine
│   └── proofs/                       # Automated Lean 4 theorem verification scripts
│       ├── kuramoto.lean
│       ├── lyapunov.lean
│       └── zmp.lean
│
├── phase2_network_teleop/            # [Upcoming] WebRTC/mTLS low-latency teleoperation & OTA
└── phase3_cognitive_guardrails/      # [Upcoming] Edge LLM/VLM cognitive security & eBPF HIDS

```

---

## 🚀 Getting Started & Usage

### 1. Requirements & Prerequisites

* Linux OS (Ubuntu 22.04 / 24.04 LTS recommended)
* Python 3.10+
* `tpm2-tools` (optional, falls back to secure software KMS entropy)
* `lean` (optional, for automated Lean 4 proof verification)

### 2. Standard Pre-Flight Test (Single-Run Verification)

To execute a single-pass verification benchmark without deploying systemd services:

```bash
python3 phase1_foundational_core/zarqa_gih_math_core.py --skip-venv-check

```

### 3. One-Click Production Deployment (Root Required)

Deploys the service user (`zarqa-math`), provisions an immutable blue-green virtual environment, sets up `/etc/systemd/system/zarqa-gih-math-core.service`, and starts continuous background verification:

```bash
sudo python3 phase1_foundational_core/zarqa_gih_math_core.py --auto-deploy

```

### 4. Monitor System Health

```bash
sudo systemctl status zarqa-gih-math-core
sudo journalctl -u zarqa-gih-math-core -f

```

---

## 📜 Standards Compliance

| Standard | Domain | Implementation Status |
| --- | --- | --- |
| **IEC 63439** | High-Availability Industrial Networks | Enabled via deterministic state-machine transitions (`NORMAL` $\rightarrow$ `DEGRADED` $\rightarrow$ `RECOVER`) and double-redundant fault-injection checks. |
| **IEC 62443** | Industrial Automation & Control Security | Enforced via TPM 2.0 hash-chained audit ledgers, ROS 2 DDS-Security X.509 PKI enforcement, and egress network filtering. |

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
