<div align="center">
  <img src="icones/icone128.png" alt="AgentShield Logo" width="128" height="128" />
  <h1>AgentShield</h1>
</div>


AgentShield is a robust, lightweight, and privacy-focused Chrome Extension designed to detect and mitigate AI prompt injection attacks, malicious hidden text, and data exfiltration attempts in real-time while browsing the web. 

Built specifically to protect users interacting with AI assistants or extensions, AgentShield acts as a proactive defense layer against emerging forms of social engineering targeting Large Language Models (LLMs).

## Features

- **Advanced Hidden Directive Detection**
  Scans the Document Object Model (DOM) for text intentionally hidden from the user (via CSS techniques like zero opacity, off-screen positioning, or microscopic fonts) that contains suspicious directives targeting AI behavior.

- **Smart Performance Optimization**
  Unlike traditional DOM scanners that cause severe browser lag, AgentShield uses a highly optimized logic flow. It only computes layout styles natively if the inspected text explicitly matches known malicious patterns, reducing CPU footprint by over 90% on heavy pages like YouTube or Facebook.

- **Obfuscation & Meta-Data Analysis**
  Detects modern evasion techniques including Base64 encoding blocks, Right-to-Left Unicode overrides, and malicious payloads hidden within HTML comments (`<!-- -->`), `iframe` sandboxes, and data attributes.

- **Network Exfiltration Monitoring**
  Leverages a Service Worker (`background.js`) to monitor outbound network requests, comparing them against the page's behavior to identify potential data exfiltration vectors or silent background beacons.

- **Scoring Algorithm**
  Evaluates the page's threat level based on a weighted scoring system (0-100) and provides a clear breakdown of deductions within the extension popup.

## Architecture

The extension is structured around Manifest V3 and operates entirely client-side, ensuring that no user browsing data is ever sent to a third-party server.

- **`manifest.json`**: Defines strict permissions (`scripting`, `storage`, `webRequest`) required to alter document context and monitor network anomalies without redundant privileges.
- **`content.js`**: The core analysis engine injected into web pages. It utilizes a `TreeWalker` to efficiently traverse text nodes, scoring the page based on sophisticated heuristic models and customized RegEx filters.
- **`background.js`**: A persistent Service Worker that listens for network events (`onBeforeSendHeaders`) and acts as a central state manager, retaining the last analysis report for instantaneous popup rendering.
- **`popup/`**: The user interface. It displays the security score, detailed telemetry (hidden text, suspicious comments, external scripts), and allows the user to force a clean re-scan without re-injecting scripts.

## Installation for Development

To install and test AgentShield locally:

1. Clone this repository or download the source code.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle switch in the top right corner.
4. Click on **Load unpacked** and select the root directory containing the `manifest.json` file.
5. The AgentShield icon will appear in your extension toolbar, ready to analyze web pages.

## Usage

Simply browse the web as usual. When you encounter a webpage you want to audit:
1. Click the AgentShield icon in the Chrome extension menu.
2. The popup will immediately display the security score for the active tab.
3. Navigate between the "Details", "Stats", and "History" tabs to review specific threats, including hidden text snippets, unsandboxed iframes, and background network requests.
4. If the page content changes dynamically (e.g., Infinite Scroll), click the "Analyser" button to trigger a fresh scan matrix.

## Contributing

Contributions are welcome. Please ensure that any pull requests maintain the strict performance optimizations within the DOM walker algorithm and adhere to standard Javascript formatting.

## License

This project is open-source. Please see the LICENSE file for more details.
