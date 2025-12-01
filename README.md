# Privacy-Preserving Threat Intelligence Overlap (PP-TIO)

A prototype system that enables two ISPs to compute overlap in their Indicators of Compromise (IoC) lists without revealing the actual lists, using Homomorphic Encryption (BFV scheme) and Bloom filters.

## Overview

Organizations maintain private feeds of IoCs (IP addresses, domains, URLs, malware hashes) but hesitate to share them due to business sensitivity and privacy concerns. This system allows organizations to:

- **Compute overlap** between IoC lists without exposing raw data
- **Calculate similarity metrics** (Jaccard similarity) on encrypted data
- **Preserve privacy** while enabling collaborative threat intelligence

## Features

- ✅ BFV Homomorphic Encryption for privacy-preserving computation
- ✅ Bloom filter encoding for efficient set representation
- ✅ Two-party protocol simulation
- ✅ Command-line interface for easy usage
- ✅ **Web Dashboard** with real-time visualizations (NEW)
- ✅ REST API for programmatic access
- ✅ Comprehensive testing and benchmarking

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or navigate to the project directory:
```bash
cd "/Users/mitanshubhoot/Documents/Semester 3/SNS/Mini Project"
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

### Option 1: Web Dashboard (Recommended)

```bash
# Make startup script executable (first time only)
chmod +x start_web.sh

# Launch the web dashboard
./start_web.sh
```

Then open your browser to **http://localhost:5000**

**Features:**
-  Modern dark theme (ProjectDiscovery-inspired)
-  Real-time simulation updates
-  Interactive Chart.js visualizations
-  Terminal-style log output
-  Responsive design

### Option 2: Command Line

### Generate Keys

```bash
python -m src.cli.main generate-keys --output keys/
```

### Run Simulation

```bash
python -m src.cli.main simulate \
  --dataset1-size 1000 \
  --dataset2-size 1000 \
  --overlap-percentage 50 \
  --output results.json
```

### Run Tests

```bash
pytest tests/ -v
```

### Run Benchmarks

```bash
python benchmarks/performance_test.py
```

## Project Structure

```
.
├── src/
│   ├── crypto/          # Homomorphic encryption engine
│   ├── data/            # Bloom filters and IoC models
│   ├── computation/     # Overlap calculation logic
│   ├── cli/             # Command-line interface
│   └── api/             # REST API (optional)
├── tests/               # Unit and integration tests
├── benchmarks/          # Performance benchmarks
├── docs/                # Documentation
├── config/              # Configuration files
└── keys/                # Cryptographic keys (gitignored)
```

## How It Works

1. **Encoding**: Each ISP encodes their IoC list into a Bloom filter
2. **Encryption**: Bloom filters are encrypted using BFV homomorphic encryption
3. **Computation**: Homomorphic AND operation computes overlap on encrypted data
4. **Decryption**: Only aggregate results (overlap count, similarity) are revealed
5. **Privacy**: Individual IoCs remain confidential throughout the process

## Documentation

- [Implementation Plan](docs/implementation_plan.md)
- [API Documentation](docs/api_documentation.md)
- [Usage Guide](docs/usage_guide.md)
- [Project Report](docs/project_report.md)

## Security & Privacy

- **Confidentiality**: Raw IoC lists never transmitted in plaintext
- **Selective Disclosure**: Only aggregate statistics revealed
- **Honest-but-Curious Security**: Secure against passive adversaries
- **No Inference**: Individual IoCs cannot be deduced from results

## Performance

Typical performance on modern hardware:
- Encryption: ~100-500ms for 1000 IoCs
- Computation: ~200-1000ms for overlap detection
- Memory: ~50-200MB depending on dataset size

See [benchmarks/](benchmarks/) for detailed performance analysis.

## License

This is an academic project for educational purposes.

## Authors

Mitanshu Bhoot  
Security for Networked Systems  

## Acknowledgments

- Microsoft SEAL / TenSEAL for homomorphic encryption library
- Public blocklists from abuse.ch and similar sources
