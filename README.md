# Mini SOC - Project 2 (Fresh Build)

This repository contains the fresh, from-scratch build of the Mini SOC lab environment for the FYP.

## Structure
- `scripts/`: Python correlation engine and test scripts.
- `rules/`: Custom Suricata rules.
- `configs/`: Wazuh and network configurations.

## Setup
1. Create virtual environment: `python3 -m venv venv`
2. Activate: `source venv/bin/activate`
3. Install: `pip install -r requirements.txt`
4. Add password to `.env` (copy from `.env.example`)
