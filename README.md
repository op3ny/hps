# Hsyst Peer-to-Peer Service (HPS)

> **[Leia em Português (Brasil)](README.pt-BR.md)**

---

> A decentralized P2P infrastructure for publishing, digital contracts, identity, decentralized DNS, and native economy — with no central authority.

---

## Screenshots

<table>
  <tr>
    <td><img src="docs/images/image1.png" alt="Screenshot 1" width="400"></td>
    <td><img src="docs/images/image2.png" alt="Screenshot 2" width="400"></td>
  </tr>
  <tr>
    <td><img src="docs/images/image3.png" alt="Screenshot 3" width="400"></td>
    <td><img src="docs/images/image4.png" alt="Screenshot 4" width="400"></td>
  </tr>
</table>

---

## ⚠️ WARNING

- This project **is not fully open-source**. Please review the [license](LICENSE.md) before running or replicating.
- First time using it? Our official servers are:

  | Priority | Server | Protocol |
  |----------|--------|----------|
  | Primary | `server2.hps.hsyst.org` | HTTPS/TLS |
  | Backup 1 | `server1.hps.hsyst.org` | HTTP (Backup of HTTPS/TLS) |
  | Backup 2 | `server3.hps.hsyst.org` | HTTP (Backup of Backup) |

---

## On a Linux Distribution?

We have a compiled version of the software — just download and run!

**[Download Latest Release](https://github.com/Hsyst-Eleuthery/hps/releases)**

---

## Technical Manual

Want to dive deeper into the project internals?
**[Read the Technical Documentation](docs/tecnico.md)**

---

## Table of Contents

- [Overview](#overview)
- [Goals](#goals)
- [Architecture](#architecture)
- [Network Model](#network-model)
- [Security Model](#security-model)
- [Contract System](#contract-system)
- [Distributed Content](#distributed-content)
- [Decentralized DNS](#decentralized-dns-hps)
- [Reputation System](#reputation-system)
- [HPS Economy (Vouchers)](#hps-economy-vouchers)
- [Browser Interface](#browser-interface)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Philosophy](#philosophy)
- [Status](#status)
- [License & Credits](#license--credits)

---

## Overview

**HPS (Hsyst Peer-to-Peer Service)** is a **decentralized peer-to-peer platform** written in **Python**, designed to let users publish, transfer, and validate digital content in an **auditable, verifiable, and censorship-resistant** way.

The system combines concepts from:

- Peer-to-peer networks
- Asymmetric cryptography
- Signed digital contracts
- Decentralized DNS
- Distributed reputation
- Internal economy based on cryptographic effort

All of this **without relying on central servers, external authorities, or implicit trust**.

---

## Goals

HPS was designed to solve real problems found in centralized systems:

| Problem | HPS Approach |
|---------|-------------|
| Lack of content sovereignty | User-owned, cryptographically signed content |
| Dependency on intermediaries | Direct peer-to-peer communication |
| Arbitrary censorship | Transparent, contract-based moderation |
| Lack of transparency | Auditable contract history |
| Difficulty of auditing | Immutable hashes and signatures |
| Spam and automation abuse | Proof-of-work and voucher economy |

The goal is **not to replace the traditional internet**, but to **offer an alternative layer** where rules are explicit, recorded, and verifiable.

---

## Architecture

HPS is composed of **two main components**:

### Server

Responsible for:

- Distributed storage
- Contract validation
- Node synchronization
- User and reputation management
- Domain registration
- HPS economy (vouchers)

### Client / Browser

Responsible for:

- Graphical interface
- Content publishing and consumption
- Contract signing
- Visual security verification
- Navigation via `hps://`

Both are written in Python and communicate via **Socket.IO + HTTP**.

---

## Network Model

- There is **no master server**
- Any server can join or leave the network
- Servers synchronize data between themselves
- Clients can switch servers without losing identity
- Network state emerges from the sum of valid contracts

The network prioritizes **verifiable consistency**, not authority.

---

## Security Model

### Identity

Each user has:

- A **public key**
- A **private key**

Identity **does not depend on email, IP, or external providers**.

### Digital Signatures

The following are cryptographically signed:

- Content
- Domains
- Contracts
- Transfers
- Economic operations

Any subsequent modification **invalidates the signature**.

### Verification

The HPS client:

- Validates hashes
- Checks signatures
- Detects tampering
- Automatically blocks invalid content

Security is **active**, not optional.

---

## Contract System

The **contract** is the central unit of trust in HPS.

A contract defines:

| Field | Description |
|-------|-------------|
| **Who** | The actor that performed the action |
| **What** | The action performed |
| **Target** | Content, domain, app, or value affected |
| **Context** | Under which circumstances |
| **When** | Timestamp of the action |
| **Signature** | Cryptographic proof of authenticity |

### Contract Examples

- Content upload
- Domain transfer
- Ownership change
- Material certification
- Voucher issuance or transfer

If an action **does not have a valid contract**, it **is not trustworthy**.

### Contract Violations

When a contract is violated:

- Content may be blocked
- Domain loses its guarantee
- The interface alerts the user
- A new contract may be required
- A certifier may intervene

Nothing is silently deleted.
**Everything leaves a trail.**

---

## Distributed Content

HPS supports any file type:

- Text, Image, Video, Audio, Binaries

Each piece of content has:

- Immutable hash
- Author
- Owner
- Signature
- History
- Associated reputation

Trust doesn't come from the file — it comes from the **contractual context**.

---

## Decentralized DNS (`hps://`)

HPS implements its own naming system.

```
hps://myproject.docs
```

Characteristics:

- Domains have an owner
- Transfers require a contract
- History is preserved
- Does not depend on ICANN or registrars

A domain is simply a **contract pointing to a hash**.

---

## Reputation System

Each user has a dynamic reputation score.

It influences:

- Publishing capacity
- Reporting power
- Network priority
- HPS economy

Reputation is: **transparent, adjustable, recorded, and auditable**.

---

## HPS Economy (Vouchers)

HPS has a simple but robust internal economy.

### HPS Vouchers

- Signed digital credits
- Transferable
- Traceable
- Used for sensitive operations

### Uses

| Operation | Description |
|-----------|-------------|
| Uploads | Cost to publish content |
| DNS Registration | Cost to register a domain |
| Contracts | Cost to create a contract |
| Spam Protection | Economic barrier against abuse |
| Proof of Work | Cryptographic effort validation |

This is not a speculative system — it is **functional**.

---

## Browser Interface

The HPS Browser offers:

- Visual navigation
- Clear alerts
- Contract analysis
- Version comparison
- Explicit confirmations

The idea is simple:

> The user **understands what they are signing**.

---

## Getting Started

### Requirements

- Python 3.10+
- Linux, Windows, or macOS

### Install Dependencies

```bash
pip install aiohttp python-socketio cryptography pillow qrcode aiofiles tkinter
```

### Start the Server

```bash
python hps/hps_server.py
```

> ⚠️ Before running your HPS server, edit **line 926** of the file, replacing `127.0.0.1` with your server's public address (domain, public IP, etc.).

### Start the Browser

```bash
python hps/hps_browser.py
```

---

## Project Structure

```
hps/
├── docs/
│   ├── images/           # Screenshots and visual assets
│   └── tecnico.md        # Technical documentation
├── hps/
│   ├── hps_browser.py    # Client / Browser application
│   └── hps_server.py     # Server application
├── LICENSE.md             # Project license
├── README.md              # Documentation (English)
└── README.pt-BR.md        # Documentation (Português)
```

---

## Philosophy

HPS is built on three principles:

1. **Nothing is trusted by default.**
2. **Everything must be verifiable.**
3. **Authority must be explicit, never implicit.**

This is not a platform of promises.
It is a platform of **proof**.

---

## Status

| Component | Status |
|-----------|--------|
| Architecture | Functional |
| Contract system | Complete |
| Cryptographic security | Mature |
| Graphical interface | Operational |
| Internal economy | Active |
| Community readiness | Ready for testing, forks, and experimentation |

---

## License & Credits

Project created by [Thaís](https://github.com/op3ny) for **Hsyst Eleuthery**.

Review the full license at [LICENSE.md](LICENSE.md).

---

<p align="center">
  <strong>HPS — Hsyst Peer-to-Peer Service</strong><br>
  Decentralized. Verifiable. Sovereign.
</p>
