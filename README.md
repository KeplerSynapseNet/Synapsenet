# SynapseNet 0.1.0-alpha

**A Decentralized Intelligence Network**

> "Satoshi gave us money without banks. I will give you brains without corporations."  
> — Kepler

SynapseNet is a decentralized peer-to-peer network for collective intelligence. It is to **KNOWLEDGE** what Bitcoin is to **MONEY**. Mine with intelligence using Proof of Emergence (PoE).

## What is SynapseNet?

SynapseNet is a local-first AI network where nodes contribute and validate knowledge using deterministic consensus (PoE). The network is designed to be censorship-resistant, decentralized, and community-driven, with optional local AI chat and Web 4.0 context injection (clearnet/onion).

## Screenshots

![KeplerSynapseNet](pictures/KeplerSynapseNet.png)
![SynapseNet](pictures/Synapsenet.png)
![Global Network](pictures/synapsenet_global.png)
![AI Agent](pictures/synapsenet_ai_agent.png)
![Kepler](pictures/kepler.png)

## Links

- **GitHub:** https://github.com/KeplerSynapseNet
- **Official:** https://synapsenetai.org
- **Onion:** http://dc4p33qjalqqpk6ggy2p7axv57rdj53lrlgeq3bfto3laoiifzh5odad.onion

## Quick Start

```bash
TERM=xterm-256color ./KeplerSynapseNet/build/synapsed
```

## Build

Common requirements:
- CMake 3.16+
- C++17 compiler
- ncurses (required)
- SQLite3 (optional but recommended)
- Go (optional, only if you want the terminal Synapse IDE)

### Linux

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git libncurses-dev sqlite3

cd KeplerSynapseNet
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUSE_LLAMA_CPP=OFF -DBUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### macOS

```bash
brew install cmake ncurses sqlite3

cd KeplerSynapseNet
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUSE_LLAMA_CPP=OFF -DBUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Windows (WSL2 recommended)

1. Install WSL2 + Ubuntu.
2. Open Ubuntu and follow the Linux build steps above.

### Docker (Windows/macOS/Linux fallback)

This builds **Linux** binaries inside a container (useful on Windows when WSL2 is not available or fails).

```bash
cd KeplerSynapseNet
docker build -t keplersynapsenet:local .
# or multi-arch
# docker buildx build --platform linux/amd64,linux/arm64 -t keplersynapsenet:local --load .

docker run --rm -it -p 8332:8332 keplersynapsenet:local
```

## Project Structure

| Directory | Description |
|-----------|-------------|
| `KeplerSynapseNet/` | Core daemon, TUI, AI model integration, P2P network |
| `ide/synapsenet-vscode/` | VS Code extension for Synapse IDE |
| `interfaces txt/` | Architecture specs, design documents |
| `pictures/` | Project assets |

## Features

- **Local AI Chat** — Run GGUF models locally, stream tokens in real time
- **Proof of Emergence (PoE)** — Contribute knowledge, validate, earn NGT
- **Web 4.0** — Optional clearnet/onion search injection (F5/F6/F7)
- **Quantum-resistant crypto** — CRYSTALS-Dilithium, Kyber, SPHINCS+
- **Synapse IDE** — Terminal IDE + VS Code extension for AI-assisted coding

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

Everyone is welcome to contribute and improve SynapseNet. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and consensus rules.
