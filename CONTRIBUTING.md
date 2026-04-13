# Contributing to NEXUS SPECTER PRO

**by OPTIMIUM NEXUS LLC** | contact@optimiumnexus.com

Thank you for your interest in contributing to NEXUS SPECTER PRO. This document covers contribution guidelines, code standards, and the development workflow.

---

## ⚠️ Legal & Ethics

By contributing, you confirm that:

1. All contributions are for **authorized security testing** use cases only
2. You will not add exploit code that facilitates unauthorized access
3. You agree to the project's commercial license terms
4. All submissions must include scope validation hooks

---

## 🔧 Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/NEXUS-SPECTER-PRO.git
cd NEXUS-SPECTER-PRO

# 2. Install dev dependencies
make dev

# 3. Verify setup
make qa
```

---

## 🌿 Branching Strategy

```
main          ← Production releases only (tagged vX.Y.Z-SPECTER)
develop       ← Integration branch — all PRs target here
feature/XXX   ← Feature branches (from develop)
fix/XXX       ← Bug fix branches (from develop)
hotfix/XXX    ← Critical fixes (from main)
```

**Branch naming:**
```
feature/nuclei-template-manager
fix/session-encryption-key-rotation
docs/api-websocket-reference
test/cvss-scorer-edge-cases
```

---

## 📋 Pull Request Process

### 1. Before opening a PR

```bash
# Run full QA suite
make qa

# Verify tests pass
make test

# Check formatting
make format
make lint
make typecheck
```

### 2. PR requirements

- [ ] All existing tests pass (`make test`)
- [ ] New code has unit tests (min 70% coverage for new modules)
- [ ] Code formatted with Black (`make format`)
- [ ] Ruff linting passes (`make lint`)
- [ ] Type hints on all public functions
- [ ] Docstring on all public classes and functions
- [ ] CHANGELOG.md entry added
- [ ] No secrets or credentials committed

### 3. PR template

```markdown
## Summary
Brief description of what this PR does.

## Type
- [ ] Feature
- [ ] Bug fix
- [ ] Documentation
- [ ] Refactoring
- [ ] Tests

## Phase affected
- [ ] Core
- [ ] Recon
- [ ] Enumeration
- [ ] Vuln Scan
- [ ] Exploitation
- [ ] Post-Exploitation
- [ ] Reporting
- [ ] Dashboard
- [ ] Infrastructure

## Testing
Describe how you tested this change.

## Checklist
- [ ] Tests added/updated
- [ ] Docs updated
- [ ] CHANGELOG entry added
- [ ] No hardcoded credentials
```

---

## 🐍 Code Standards

### Python style

We follow PEP 8 with Black formatting (100 char line length):

```python
# ✅ Good
class NucleiRunner:
    """
    Nuclei scanning engine for NEXUS SPECTER PRO.
    Manages template discovery, scan execution, and result parsing.
    by OPTIMIUM NEXUS LLC
    """

    def run(self, target: str, config: dict = None) -> dict:
        """
        Execute Nuclei scan against target.

        Args:
            target: URL or IP to scan
            config: Optional scan configuration overrides

        Returns:
            dict with keys: total, by_severity, targets
        """
        config = config or {}
        ...

# ❌ Bad — missing types, docstring, inconsistent naming
def runnuclei(t, c=None):
    pass
```

### Module structure

Every module must follow this pattern:

```python
"""
NEXUS SPECTER PRO — Module Name
One-line description of what this module does.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import ...
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.phase.module_name")


@dataclass
class ResultType:
    """Structured output from this module."""
    field: str
    ...


class ModuleName:
    """
    Class description. What it does, what tools it wraps,
    what it returns.
    """

    def __init__(self, target: str, ...):
        ...

    def run(self) -> dict:
        """
        Main entry point. Always returns a JSON-serializable dict.
        """
        ...
```

### Required elements

| Element | Required | Notes |
|---------|----------|-------|
| Module docstring | ✅ | With OPTIMIUM NEXUS LLC attribution |
| Class docstring | ✅ | Describe purpose and behavior |
| Method docstring | ✅ on public methods | Args + Returns |
| Type hints | ✅ | All function signatures |
| `run() -> dict` | ✅ | Every scan class needs this |
| Rich console output | ✅ | Use purple `#7B00FF` + cyan `#00FFD4` |
| Logging | ✅ | `log.info/warning/error` not `print()` |
| Error handling | ✅ | Catch and log, never crash |

### Rich output conventions

```python
# Phase start
console.print(f"[bold #7B00FF]  🎯 Module starting — {target}[/bold #7B00FF]")

# Progress/info
console.print(f"[#00FFD4]  → Doing thing: {detail}[/#00FFD4]")

# Critical finding
console.print(f"[bold #FF003C]  ⚡ CRITICAL FOUND: {name}[/bold #FF003C]")

# High finding
console.print(f"[bold #FF8C00]  ⚠ HIGH: {name}[/bold #FF8C00]")

# Success / completion
console.print(f"[bold #00FFD4]  ✅ Complete — {count} results[/bold #00FFD4]")
```

---

## 🔌 Writing a Plugin

The fastest way to contribute a new scan capability is via the plugin system:

```python
# plugins/my_custom_recon.py
"""
My Custom Recon Plugin
Adds XYZ intelligence gathering.
Author: Your Name
"""

NSP_PLUGIN = {
    "name":        "my_custom_recon",
    "version":     "1.0.0",
    "author":      "Your Name <you@example.com>",
    "phase":       "recon",
    "description": "Gathers XYZ intelligence from public sources",
    "api_version": "1.0",
    "tags":        ["recon", "osint", "passive"],
    "requires":    ["requests"],   # pip dependencies
}


def run(target: str, config: dict = None, session=None) -> dict:
    """
    Plugin entry point.
    Returns dict with findings to merge into the NSP report.
    """
    config  = config or {}
    results = {"plugin": "my_custom_recon", "target": target, "findings": []}

    # Your implementation here
    try:
        import requests
        r = requests.get(f"https://api.example.com/{target}", timeout=10)
        if r.ok:
            results["findings"].append({
                "name":     "Custom Finding",
                "severity": "info",
                "detail":   r.json(),
            })
    except Exception as e:
        results["error"] = str(e)

    return results
```

Drop it in `plugins/` and NSP auto-discovers it at the next run.

---

## 🧪 Writing Tests

### Unit test template

```python
"""
NEXUS SPECTER PRO — MyModule Unit Tests
by OPTIMIUM NEXUS LLC
"""
import pytest
from nsp.phase.my_module import MyModule


class TestMyModule:

    @pytest.fixture
    def module(self):
        return MyModule(target="example.com")

    def test_basic_run(self, module):
        result = module.run()
        assert isinstance(result, dict)
        assert "target" in result

    def test_error_handling(self):
        m = MyModule(target="invalid:::target")
        result = m.run()
        # Should not raise — should return error dict
        assert "error" in result or isinstance(result, dict)

    def test_empty_target(self):
        m = MyModule(target="")
        result = m.run()
        assert isinstance(result, dict)
```

### Test organization

```
tests/
├── unit/
│   ├── test_cvss_scorer.py       # Per-module unit tests
│   ├── test_scope_validator.py
│   └── test_session_manager.py
└── integration/
    ├── test_api.py               # API endpoint tests
    └── test_mission_flow.py      # End-to-end mission tests
```

---

## 📝 Documentation

### Where to document

| What | Where |
|------|-------|
| New CLI flags | `nsp_cli.py` argparse + `docs/QUICKSTART.md` |
| New REST endpoints | `docs/API_REFERENCE.md` |
| Architecture changes | `docs/ARCHITECTURE.md` |
| New modules | Module docstring + `docs/MODULES.md` |
| Version changes | `CHANGELOG.md` |

### CHANGELOG format

```markdown
## [X.Y.Z-SPECTER] — YYYY-MM-DD

### ⚡ Category Name

#### Subcategory
- `module_name.py` — Description of what was added/changed
```

---

## 🚀 Release Process

1. All PRs merged to `develop`
2. QA run on `develop` (`make test`)
3. Version bumped in `pyproject.toml`, `nsp/__init__.py`
4. CHANGELOG.md updated
5. PR: `develop` → `main`
6. Tag created: `git tag v1.3.0-SPECTER`
7. Docker image published: `make docker-push`
8. GitHub Release created with CHANGELOG notes

---

## 📬 Contact

- **Email:** contact@optimiumnexus.com
- **Website:** https://www.optimiumnexus.com
- **Issues:** GitHub Issues tab
- **Security disclosures:** contact@optimiumnexus.com (please encrypt with our PGP key)

---

*NEXUS SPECTER PRO — by OPTIMIUM NEXUS LLC*
*"Invisible. Inevitable. Unstoppable."*
