# Vishu - Model Context Protocol (MCP) Suite 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Replace with your actual license -->
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

**Vishu MCP is an advanced, AI-driven suite for reconnaissance, security analysis, and automated task orchestration. It leverages the power of Large Language Models (LLMs) like Google's Gemini to intelligently plan and execute a wide array of security and information-gathering tools.**

---

## ✨ Table of Contents

*   [Introduction](#-introduction)
*   [Key Features](#-key-features)
*   [Architecture Overview](#-architecture-overview)
*   [Tech Stack](#-tech-stack)
*   [Getting Started: Step-by-Step Setup & Launch](#-getting-started-step-by-step-setup--launch)
    *   [Prerequisites](#prerequisites)
    *   [Step 1: Clone the Repository](#step-1-clone-the-repository)
    *   [Step 2: Configure Environment Variables](#step-2-configure-environment-variables)
    *   [Step 3: X11 Forwarding Setup (Platform Specific)](#step-3-x11-forwarding-setup-platform-specific)
        *   [Linux](#linux)
        *   [macOS (using XQuartz)](#macos-using-xquartz)
        *   [Windows (using VcXsrv or WSLg)](#windows-using-vcxsrv-or-wslg)
    *   [Step 4: Build and Run with Docker Compose](#step-4-build-and-run-with-docker-compose)
    *   [Accessing the Application GUI](#accessing-the-application-gui)
    *   [Troubleshooting X11](#troubleshooting-x11)
*   [Usage](#-usage)
*   [Important Notes](#-important-notes)
*   [Contributing](#-contributing)
*   [License](#-license)

---

## 🌟 Introduction

In the rapidly evolving landscape of cybersecurity and information gathering, automation and intelligent decision-making are paramount. The Vishu MCP Suite is designed to address this need by providing a powerful platform where an LLM acts as the "Master Control Program," orchestrating a variety of backend tools to perform complex tasks.

Whether you're a security researcher, penetration tester, or a developer looking to automate information gathering, Vishu MCP offers a flexible and extensible framework. The intuitive GUI client allows you to interact with the LLM, define objectives, and monitor the execution of multi-step "plans" in real-time.

---

## 🎯 Key Features

*   🧠 **LLM-Driven Orchestration:** Utilizes Google Gemini (configurable) to understand user queries, formulate plans, and decide which tools to use.
*   🛠️ **Modular & Extensible Toolset:**
    *   **Port Scanning:** Comprehensive Nmap-based scanning for open ports, services, versions, and OS detection.
    *   **Subdomain Enumeration:** Multi-method discovery (brute-force, SearXNG, crt.sh, DNS).
    *   **DNS Enumeration:** Detailed DNS record analysis, CNAME chaining, zone transfer attempts.
    *   **Web Content Fetching:** Retrieves and processes web page content, respecting `robots.txt`.
    *   **Advanced Web Crawling & Analysis:** Selenium-based crawler with:
        *   Technology fingerprinting (Wappalyzer-like).
        *   Passive vulnerability scanning using customizable templates.
        *   Integration with a suite of active vulnerability scanners.
    *   **Active Vulnerability Scanning:** A rich set of rules for common vulnerabilities (SQLi, XSS, LFI, RCE, Code/Command Injection, XXE, SSRF, Log4Shell, specific CVEs, and more).
    *   **Vector Database:** Stores and queries reconnaissance data using FAISS and sentence-transformer embeddings for contextual retrieval.
    *   **PDF Report Generation:** Creates detailed reports from gathered and summarized information.
*   🖥️ **Interactive GUI Client:** Built with Dear PyGui for a rich user experience, featuring:
    *   Real-time interaction log.
    *   LLM model selection.
    *   Tabbed display for managing multiple ongoing "plans".
    *   Detailed views for conversation history, LLM thoughts, tool logs, and live tool output streams.
    *   Easy file downloads for generated artifacts (e.g., PDF reports).
*   🌊 **Streaming Results:** Long-running tools stream their progress and findings back to the client in real-time.
*   🌐 **SearXNG Integration:** Leverages a local SearXNG instance for privacy-respecting web searches.
*   🐳 **Dockerized:** Easy setup and deployment using Docker and Docker Compose.

---

## 🏗️ Architecture Overview

The Vishu MCP Suite follows a client-server architecture:

1.  **MCP Client (GUI - `rizzler_client`):**
    *   The user interface where you interact with the LLM.
    *   Manages the conversation, sends requests to the LLM, and interprets its responses (including tool call requests).
    *   Communicates with the MCP Server to execute tools.

2.  **MCP Server (Backend - `rizzler_server`):**
    *   A FastAPI application that exposes the reconnaissance and analysis tools as API endpoints.
    *   Handles the execution of tools, often using Server-Sent Events (SSE) for streaming output.
    *   Manages the FAISS vector database for storing and retrieving recon data.
    *   Interacts with the SearXNG service.

3.  **SearXNG Service (`searxng`):**
    *   A private meta-search engine instance used by the MCP Server for web search capabilities.

```mermaid
graph TD
    User -->|Query| ClientGUI[MCP Client GUI (Dear PyGui, Langchain, Gemini LLM)]
    ClientGUI -->|Tool Execution Request (SSE)| MCPServer[MCP Server (FastAPI, Recon Tools, FAISS DB)]
    MCPServer -->|Tool Output (SSE)| ClientGUI
    MCPServer -->|Search Query| SearXNG[SearXNG Service]
    SearXNG -->|Search Results| MCPServer
    MCPServer -->|Data Storage/Retrieval| FAISS_DB[(FAISS Vector DB)]

💻 Tech Stack

Backend (MCP Server):

Python 3.12

FastAPI, Uvicorn

Nmap (via python-nmap)

Selenium, Google Chrome (for web crawling & analysis)

FAISS (for vector database)

sentence-transformers/all-mpnet-base-v2 (for text embeddings)

Various Python libraries for networking, web interaction, data processing.

Client (MCP Client GUI):

Python 3.12

Dear PyGui

Langchain, langchain-google-genai (for Google Gemini LLM interaction)

httpx (for server communication)

Orchestration & Search:

Docker, Docker Compose

SearXNG

🚀 Getting Started: Step-by-Step Setup & Launch

Follow these steps to get the Vishu MCP Suite up and running on your local machine.

Prerequisites

Git: To clone the repository.

Docker & Docker Compose: Ensure you have the latest versions installed. Visit Docker's official website for installation instructions.

X11 Server (for GUI): This is required to display the client GUI from the Docker container.

Linux: Usually available by default.

macOS: Install XQuartz.

Windows: Install an X server like VcXsrv or use WSLg if using WSL2.
(Detailed X11 setup instructions are in Step 3).

Google Cloud Project & API Key:

A Google Cloud Project with the Vertex AI API enabled.

A Google API Key with permissions to use the Vertex AI API (specifically for Gemini models).

Step 1: Clone the Repository

Open your terminal or command prompt and run:

git clone <your-repository-url> # Replace <your-repository-url> with the actual URL
cd <repository-name>             # Replace <repository-name> with the cloned folder name
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END
Step 2: Configure Environment Variables

The client application needs your Google API Key to interact with the Gemini LLM.

Navigate to the rizzler_client folder within the cloned repository:

cd rizzler_client
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Create or edit the .env file in this rizzler_client directory. If an .env.example file exists, you can copy it to .env.

Add the following lines to your .env file, replacing the placeholder with your actual Google API Key:

# In <repository-name>/rizzler_client/.env
GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY"
MCP_SERVER_BASE_URL="http://rizzler_server:8000" # Default, works with Docker Compose

# Optional, if your LLM or other services require them:
# GOOGLE_PROJECT_ID="YOUR_GOOGLE_CLOUD_PROJECT_ID"
# GOOGLE_LOCATION="YOUR_GOOGLE_CLOUD_PROJECT_LOCATION" # e.g., us-central1
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Env
IGNORE_WHEN_COPYING_END

Important: The MCP_SERVER_BASE_URL is pre-configured to work within the Docker network. Do not change it unless you understand the implications for inter-container communication.

The GOOGLE_PROJECT_ID and GOOGLE_LOCATION might be required by some Google Cloud services or specific Langchain configurations for Vertex AI. Add them if your setup needs them.

Navigate back to the root directory of the cloned repository:

cd ..
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END
Step 3: X11 Forwarding Setup (Platform Specific)

This step is crucial for the GUI client to display on your host machine. Perform these steps on your host machine, before running docker-compose up.

🐧 Linux:

Your DISPLAY environment variable (e.g., :0) should typically be set correctly by your desktop environment.

Open a terminal on your host and run the following command to allow local Docker containers to connect to your X server:

xhost +local:docker
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Note: This command grants access to any local Docker container. You can revoke this permission after you're done with xhost -local:docker.

🍎 macOS (using XQuartz):

Install XQuartz: If you haven't already, download and install XQuartz from their official website.

Enable Network Connections in XQuartz:

Open XQuartz.

Go to XQuartz > Preferences (or Settings).

Navigate to the "Security" tab.

Ensure that "Allow connections from network clients" is checked.

Restart XQuartz (quit and reopen) for this setting to take effect.

Set DISPLAY Environment Variable (if needed):
In your macOS terminal (the one you'll use to run docker-compose), execute:

export DISPLAY=$(ipconfig getifaddr en0):0
# If en0 (Wi-Fi) is not your active interface, try en1, etc.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

This setting is for the current terminal session.

🪟 Windows (using VcXsrv or WSLg):

Option 1: Using VcXsrv (Recommended for most Docker Desktop on Windows setups):

Install VcXsrv: Download and install VcXsrv.

Launch VcXsrv (XLaunch):

Choose "Multiple windows" or "Fullscreen" for the display setting.

For "Client startup," select "Start no client."

Crucially, in "Extra settings," ensure "Disable access control" is checked.

You can also add -ac to the "Additional parameters for VcXsrv" field.

Finish the VcXsrv setup. VcXsrv should now be running in your system tray.

Set DISPLAY Environment Variable for Docker:
The docker-compose.yml file for the rizzler_client service includes DISPLAY=${DISPLAY}. For VcXsrv, this often needs to point to your host's IP. You can try using host.docker.internal which Docker often resolves to the host IP. If that doesn't work, find your host's IP address on your local network (e.g., 192.168.1.100) and set it in the rizzler_client/.env file:

# In <repository-name>/rizzler_client/.env (add or modify this line)
DISPLAY=host.docker.internal:0.0
# OR, if the above doesn't work:
# DISPLAY=YOUR_WINDOWS_HOST_IP:0.0
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Env
IGNORE_WHEN_COPYING_END

Firewall: Ensure your Windows Firewall allows connections for VcXsrv. You might get a prompt when VcXsrv first runs; allow it.

Option 2: Using WSL2 with WSLg (Windows Subsystem for Linux GUI):

Prerequisites: Windows 10 version 21H2+ or Windows 11. WSLg is built-in.

Ensure WSLg is Working: Test by running a simple Linux GUI app from your WSL2 terminal (e.g., xeyes).

Docker Desktop with WSL2 Backend: Ensure Docker Desktop is configured to use the WSL2 backend.

Run docker-compose from WSL2: When using WSLg, you should run docker-compose up --build from within your WSL2 terminal. WSLg typically handles the DISPLAY variable automatically in this context.

Step 4: Build and Run with Docker Compose

Ensure Docker Desktop (or Docker daemon) is running. From the root directory of the cloned repository (where docker-compose.yml is located), run:

docker-compose up --build
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

This command will:

Build the Docker images for the rizzler_server and rizzler_client services. This step can take some time on the first run, especially for the server image which downloads Nmap, Chrome, and the sentence-transformer model.

Start all defined services (rizzler_server, rizzler_client, searxng).

The --build flag ensures images are rebuilt if their Dockerfiles or contexts have changed.

You will see interleaved logs from all services in your terminal. Wait until you see messages indicating the services have started successfully (e.g., rizzler_server healthcheck passes, rizzler_client attempts to launch GUI).

Accessing the Application GUI

If all previous steps were successful, the MCP Client GUI window should appear on your host machine's desktop shortly after the rizzler_client container starts.

Troubleshooting X11

GUI Doesn't Appear: Check the logs of the rizzler_client container:

docker logs mcp_client_gui
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Look for errors like "cannot open display", "Client is not authorized to connect to Server", or "GLX version mismatch".

DISPLAY Variable: Double-check that the DISPLAY variable is correctly set in the environment where docker-compose is running (for macOS/Linux) or in the .env file / docker-compose.yml (for Windows/VcXsrv).

X Server Settings:

XQuartz (macOS): Verify "Allow connections from network clients" is enabled and XQuartz was restarted.

VcXsrv (Windows): Ensure "Disable access control" was checked during VcXsrv launch. Try restarting VcXsrv with this option.

Firewall: Ensure your host machine's firewall is not blocking connections to your X server.

xhost (Linux): Make sure you ran xhost +local:docker before docker-compose up.

🛠️ Usage

Launch the Application: After running docker-compose up --build and successfully setting up X11, the MCP Client GUI will start.

Select LLM Model: In the left panel of the GUI, you can select your preferred Google Gemini model from the dropdown.

Enter Your Query: Type your reconnaissance objective or question into the input field at the bottom of the left panel (e.g., "Perform a port scan on example.com and then enumerate its subdomains").

Initiate Plan: Press Enter or click "Send Command / Start Plan".

Monitor Execution:

The LLM will formulate a plan, potentially involving multiple steps and tool calls.

A new tab will open in the center panel for this "plan".

You can monitor the LLM's thoughts, the conversation history, tool calls being made, and live streaming output from tools within this tab.

The left panel will show a high-level interaction log.

The right panel lists the tools available to the LLM.

Interact Further: The LLM may ask for clarifications or present results. You can continue the conversation by typing in the query input.

Download Artifacts: If a tool generates a downloadable file (like a PDF report), a download button will appear in the tool log or last tool result section. Clicking it will open a file dialog defaulting to the mcp_client_downloads folder on your host machine (as configured in docker-compose.yml).

⚠️ Important Notes

🛡️ Ethical Use: This suite includes powerful reconnaissance and scanning tools. Always ensure you have explicit, written permission from the target system's owner before conducting any scanning or analysis. Use this tool responsibly and ethically.

💻 Resource Consumption: Running multiple services, including a web browser (Selenium via Chrome in the server) and potentially intensive Nmap scans, can be resource-heavy. Ensure your system has adequate CPU, RAM, and network bandwidth.

💾 Vector DB Persistence: The FAISS vector database used by the rizzler_server is currently stored within its Docker container. If the rizzler_server container is removed, this data will be lost. For persistent storage, you should modify docker-compose.yml to mount a host volume for the /app/db/faiss_db directory inside the rizzler_server container.
Example (add this under the volumes: section for the rizzler_server service in docker-compose.yml):

# In docker-compose.yml, under rizzler_server:
volumes:
  - ./mcp_server_db_data:/app/db/faiss_db # Creates ./mcp_server_db_data on your host
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Yaml
IGNORE_WHEN_COPYING_END

🔑 API Keys: Your GOOGLE_API_KEY is sensitive. Keep it secure and do not commit it directly into public repositories. The .env file is typically gitignored; ensure this is the case for your project.

🌐 Network Configuration: The application relies on network communication between containers and to external services (Google AI, target systems). Ensure your Docker networking and host firewall are configured appropriately.

🤝 Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

<!-- Add your contribution guidelines here -->


Fork the repository.

Create a new branch (git checkout -b feature/YourFeature).

Make your changes.

Commit your changes (git commit -m 'Add some feature').

Push to the branch (git push origin feature/YourFeature).

Open a Pull Request.

Please make sure to update tests as appropriate.

📜 License

This project is licensed under the MIT License - see the LICENSE.md file for details.
