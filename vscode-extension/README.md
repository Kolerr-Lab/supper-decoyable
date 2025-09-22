# DECOYABLE VS Code Extension

AI-powered cybersecurity scanning and automated remediation for VS Code.

## Features

- 🔍 **Real-time Security Scanning**: Automatically scan files as you edit and save
- 🤖 **AI-Powered Fixes**: Intelligent code remediation using DECOYABLE's LLM router
- 🛡️ **Multi-Modal Analysis**: Secrets detection, dependency scanning, SAST, and code quality
- ⚡ **Quick Fixes**: Code actions for instant security issue resolution
- 📊 **Rich Results View**: Detailed security reports with severity categorization
- 🔧 **Enterprise Ready**: Configurable settings and CI/CD integration

## Installation

### From VS Code Marketplace
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "DECOYABLE Security Scanner"
4. Click Install

### From Source
1. Clone the repository
2. Run `npm install` in the `vscode-extension` directory
3. Press F5 to launch extension development host
4. Test the extension in the new window

## Usage

### Scanning Your Codebase

#### Scan Entire Workspace
- Command Palette: `DECOYABLE: Scan Workspace`
- Keyboard: `Ctrl+Shift+S` (when no file is open)

#### Scan Current File
- Command Palette: `DECOYABLE: Scan Current File`
- Right-click in editor: `Scan with DECOYABLE`
- Keyboard: `Ctrl+Shift+S` (when file is open)

#### Automatic Scanning
Configure auto-scanning in settings:
- `decoyable.scanOnSave`: Scan files when saved
- `decoyable.scanOnOpen`: Scan files when opened

### Fixing Security Issues

#### Fix All Issues
- Command Palette: `DECOYABLE: Fix All Issues`
- Keyboard: `Ctrl+Shift+F`

#### Fix Individual Issues
- Click the lightbulb 💡 next to a security warning
- Select "Fix with DECOYABLE" from the quick actions
- Or use the Problems panel to navigate to issues

### Viewing Results

#### Security Issues Panel
- View: `Explorer > Security Issues`
- Shows all detected vulnerabilities categorized by severity
- Click any issue to jump to the code location

#### Detailed Results
- Command: `DECOYABLE: Show Scan Results`
- Opens a webview with comprehensive scan report
- Includes recommendations and fix suggestions

## Configuration

Access settings through `Preferences: Open Settings (UI)` or edit `settings.json`:

```json
{
  "decoyable.pythonPath": "python",
  "decoyable.cliPath": "",
  "decoyable.scanOnSave": true,
  "decoyable.scanOnOpen": false,
  "decoyable.autoFix": false,
  "decoyable.showNotifications": true,
  "decoyable.severityFilter": ["critical", "high", "medium"],
  "decoyable.scanTypes": ["all"]
}
```

### Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `pythonPath` | Path to Python executable | `"python"` |
| `cliPath` | Path to DECOYABLE CLI (leave empty for bundled) | `""` |
| `scanOnSave` | Auto-scan files when saved | `true` |
| `scanOnOpen` | Auto-scan files when opened | `false` |
| `autoFix` | Automatically apply safe fixes | `false` |
| `showNotifications` | Show scan result notifications | `true` |
| `severityFilter` | Filter issues by severity | `["critical", "high", "medium"]` |
| `scanTypes` | Types of scans to perform | `["all"]` |

## Supported Languages

- Python 🐍
- JavaScript/TypeScript 🌐
- Java ☕
- C/C++ ⚙️
- PHP 🐘
- Ruby 💎
- Go 🏃
- Rust 🦀

## Commands

| Command | Description | Keybinding |
|---------|-------------|------------|
| `decoyable.scanWorkspace` | Scan entire workspace | - |
| `decoyable.scanFile` | Scan current file | `Ctrl+Shift+S` |
| `decoyable.fixAll` | Fix all issues | `Ctrl+Shift+F` |
| `decoyable.fixIssue` | Fix selected issue | - |
| `decoyable.showResults` | Show detailed results | - |
| `decoyable.configure` | Open settings | - |
| `decoyable.refreshResults` | Refresh results view | - |

## Architecture

```
DECOYABLE Extension
├── Core Engine (extension.ts)
│   ├── Command Registration
│   ├── File Watching
│   └── State Management
├── Results Provider (tree view)
├── Diagnostics Integration
├── Code Actions Provider
└── AI Fix Integration
```

## Development

### Prerequisites
- Node.js 16+
- VS Code 1.74+
- Python 3.8+ (for DECOYABLE core)

### Building
```bash
npm install
npm run compile
```

### Testing
```bash
npm run test
```

### Debugging
1. Open in VS Code
2. Press F5 to launch extension development host
3. Test in new window

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Security

This extension integrates with DECOYABLE's security scanning capabilities. All scans are performed locally on your machine. No code or sensitive data is transmitted to external servers unless you configure external LLM providers.

## License

MIT License - see LICENSE file for details.

## Support

- 📖 [Documentation](https://github.com/Kolerr-Lab/supper-decoyable)
- 🐛 [Issues](https://github.com/Kolerr-Lab/supper-decoyable/issues)
- 💬 [Discussions](https://github.com/Kolerr-Lab/supper-decoyable/discussions)

---

**DECOYABLE**: Making security scanning as easy as saving a file. 🔒✨