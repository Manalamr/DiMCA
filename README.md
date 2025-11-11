# 🛡️ DiMCA: Distributed Multi-Contextual Architecture for Secure SD-IoT

> **DiMCA** is a distributed, adaptive, and P4-powered security framework designed to defend **Software-Defined IoT (SD-IoT)** networks against **coordinated ARP spoofing and DDoS attacks**. It features real-time detection, line-rate packet inspection, multi-controller resilience, and context-aware mitigation.

---

## 🧠 Key Features

* **P4-based Data Plane Stateful Inspection (DPSI)**
  Enables in-switch ARP and traffic anomaly detection at line rate.

* **Multi-Control Plane Architecture (MCPA)**
  Supports distributed SDN controllers with secure coordination and high fault-tolerance.

* **Control Plane Intrusion Analysis (CPIA)**
  An ensemble ML engine for multi-class attack classification (Normal / ARP / DDoS / Combined).

* **Coordinated Multi-Layer Mitigation (CMLM)**
  Orchestrates adaptive defense across data and control planes using dynamic rules.

* **High Accuracy, Low Latency**
  Achieves 99.22% binary and up to 98.92% multi-class detection accuracy with sub-250ms response latency.

---

## 📁 Project Structure

```
DMCA/
├── controller/
│   ├── DiMCA_mcp_agent.py          # Main MCPA logic (controllers, CPIA, CMLM)
│   ├── DiMCA_model.pkl             # Pretrained CPIA ensemble model
│   ├── config/
│   │   ├── controller_policy.json
│   │   ├── ml_config.json
│   │   ├── block_policy.json
│
├── topology/
│   ├── DiMCA_topo.py               # Mininet topology with 4 IoT domains, 2 aggregator switches, LC1/LC2
│
├── p4src/
│   ├── dpsimodule.p4             # DPSI logic (parsers, tables, register logic for ARP & DDoS detection)
│
├── attack_simulator/
│   ├── attack_launcher.py         # Scripts to launch coordinated ARP & DDoS attacks using Scapy/hping
│
├── runtime_config/
│   ├── p4runtime_controller.py    # Communicates with P4 switches using P4Runtime API
│   ├── forwarding_rules.json      # Base rules for flows and MAC-IP validation
│   ├── mitigation_rules.json      # Dynamic mitigation actions (rate limits, ARP filtering, blacklists)
│
├── logs/                          # Runtime logs (detected events, controller actions, digests)
│
└── README.md                      # (This file)
```

---

## 🏗️ Requirements

* **Python ≥ 3.8**
* **Mininet-WiFi ≥ 2.3.0**
* **BMv2 with P4Runtime support**
* **Scapy**, **hping3**, **pandas**, **sklearn**, **joblib**, **grpcio**
* **ONOS / Ryu (optional for hybrid tests)**

---

## 🚀 Quick Start

### 1. Set up the environment

Install P4 tools and dependencies:

```bash
sudo apt install bmv2 p4c mininet-wifi hping3
pip install -r requirements.txt
```

### 2. Start the P4 switches and deploy topology

```bash
sudo python3 topology/dmca_topo.py
```

### 3. Launch multi-controller agents

```bash
python3 controller/dmca_mcp_agent.py --controller_id LC1
python3 controller/dmca_mcp_agent.py --controller_id LC2
```

### 4. Start the runtime interface

```bash
python3 runtime_config/p4runtime_controller.py
```

### 5. Simulate attacks

```bash
python3 attack_simulator/attack_launcher.py --type combined --target 10.0.0.5
```

---

## 📊 Evaluation Datasets

DMCA has been tested and validated using:

* [CICIoMT2024](https://www.unb.ca/cic/datasets/iomt2024.html)
* [Edge-IIoTset](https://www.kaggle.com/datasets/iotnet/edgeiiotset)
* [TON\_IoT](https://research.unsw.edu.au/projects/toniot-datasets)
* [IoTID20](https://www.kaggle.com/datasets/devendra8/iot-network-intrusion-dataset)
* [CICIoT2023](https://www.unb.ca/cic/datasets/iot2023.html)

Results show:

* **Binary classification accuracy**: 99.22%
* **Multi-class classification accuracy**: 94.77%–98.92%
* **Latency reduction**: 4.3s → 0.21s
* **Controller CPU drop**: 31%
* **Bandwidth overhead cut**: 36%
* **Failover uptime accuracy**: ≥96.6%

---

## 🧬 CPIA Model (Ensemble ML)

The detection engine uses:

* **Base Classifiers**: Decision Trees, Random Forests, SVM, KNN
* **Meta Learner**: ANN
* **Feature set**: 21 fields from DPSI (e.g., ArpConf, PktRateS, IPMacChg)

Use `DiMCA_model.pkl` in your controller as:

```python
from joblib import load
model = load('DiMCA_model.pkl')
```

---

## 🧪 Performance Metrics

| Metric                        | Value                      |
| ----------------------------- | -------------------------- |
| Binary Detection Accuracy     | 99.22%                     |
| Multi-class Accuracy          | Up to 98.92%               |
| Detection Latency             | 0.21s                      |
| MFRR (Mitigation Flow Recall) | > 88%                      |
| EMP (Effective Mitigation %)  | > 96.9%                    |
| Failover Accuracy             | ≥ 96.6%                    |
| Controller Overhead Reduction | CPU: -31%, Bandwidth: -36% |

---

## 🔐 Attack Types Detected

| Attack Type       | Layer(s) | Description                                  |
| ----------------- | -------- | -------------------------------------------- |
| Isolated ARP      | L2       | Spoofing MAC/IP binding via fake ARP replies |
| Isolated DDoS     | L3/L4    | High-rate SYN, UDP, ICMP, or HTTP floods     |
| Combined ARP+DDoS | L2 + L3  | Coordinated ARP spoofing during DDoS attacks |

---

Enjoy Testing :)
  
---
