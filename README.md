# 🌟 kptm-tools/common

Welcome to the **common** repository for the `kptm-tools` organization!  
This Go module provides shared resources to standardize communication and data handling across microservices.

## 📖 Overview

The `common` module includes:
- 📦 **Event Payloads**: Standardized JSON structures for the EventBus communication.
- ⚙️ **Utilities**: Shared helpers and constants.
- 📋 **Documentation**: A single source of truth for payload structures.

## 🚀 Getting Started

### 1️⃣ Install the Module
Add the `common` module to your Go project:

```bash
go get github.com/kptm-tools/common
```

### 2️⃣ Import and Use

Import the necessary structures or utilities in your Go code:

```go
import "github.com/kptm-tools/common/events"

// Example usage
event := events.ScanStarted{
    ScanID:   "1234",
    Target:   "example.com",
    ScanType: "nmap",
}
```

### 📚 Resources

* **Documentation:** All payloads are documented in the events package.
* **Contribution Guide:** See CONTRIBUTING.md for details.

### ❤️ Contributions

We welcome contributions! Open an issue or create a pull request to suggest improvements or report bugs.

---

Happy coding! 🎉
