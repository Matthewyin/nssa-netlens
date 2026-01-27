# NetLens

NetLens is a professional-grade, AI-ready network traffic analysis and visualization tool built with Electron, React, and Python (Tshark).

## 🌟 Key Features

- **High-Performance Analysis**: Powered by a pure Tshark backend with streaming capabilities, capable of handling large PCAP files.
- **Master-Detail Visualization**: Explore flows with an interactive Master-Detail split view across HTTP, DNS, and TLS.
- **TCP Sequence Diagrams**: Visualize packet flows with beautiful, interactive sequence diagrams.
- **Advanced Diagnostics**: Automatic detection of TCP anomalies (Retransmissions, Zero Windows, Lost Segments, Resets) with expert troubleshooting advice.
- **Security Scanning**: Built-in detection for common threats like SQL Injection, XSS, Plaintext Credentials, and Port Scanning.
- **Multi-File Correlation**: Match and correlate packets between two different capture points to identify packet loss and latency (NAT-aware).
- **AI-Ready (MCP)**: Built-in Model Context Protocol (MCP) server, allowing AI agents to interact directly with your network data.
- **Modern UI**: Clean, theme-aware interface with global search, collapsible drawer sidebar, and customizable reports directory.

## 🚀 Architecture

- **Frontend**: Electron, React, Vite.
- **Backend**: Python 3.11+, Tshark (Wireshark CLI).
- **Packaging**: PyInstaller (Backend) and Electron Builder (DMG).

## 🛠 Installation & Usage

### Prerequisites
- [Wireshark/Tshark](https://www.wireshark.org/) installed on your system.
- [uv](https://github.com/astral-sh/uv) for Python dependency management.

### Development
1. Clone the repository.
2. Install frontend dependencies: `cd frontend && npm install`.
3. Install backend dependencies: `cd backend && uv sync`.
4. Run in dev mode: `cd frontend && npm run dev`.

### Build (macOS)
1. Build backend binary: `bash backend/build_backend.sh`.
2. Build DMG: `cd frontend && npm run build:mac`.

## 🤖 AI Integration (MCP)

NetLens includes an MCP server. You can connect it to Claude Desktop or other MCP clients:

```json
{
  "mcpServers": {
    "netlens": {
      "command": "/path/to/uv",
      "args": ["run", "pcap-mcp"],
      "cwd": "/path/to/netlens/backend"
    }
  }
}
```

## ⚖️ License

MIT
