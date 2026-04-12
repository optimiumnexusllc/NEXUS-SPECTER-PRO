"""
NEXUS SPECTER PRO — Plugin Loader
Modular plugin system: discover, validate, and hot-load custom NSP modules.
Plugin authors can extend any phase (recon/enum/vuln_scan/reporting) without
modifying core code.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import importlib.util, inspect, logging, os, json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Optional
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.core.plugins")

PLUGIN_API_VERSION = "1.0"

VALID_PHASES = {
    "recon", "enumeration", "vuln_scan",
    "exploitation", "post_exploitation", "reporting", "ai",
}


@dataclass
class PluginMeta:
    name:        str
    version:     str
    author:      str
    phase:       str
    description: str
    api_version: str     = PLUGIN_API_VERSION
    enabled:     bool    = True
    tags:        list    = field(default_factory=list)
    requires:    list    = field(default_factory=list)   # pip deps


@dataclass
class LoadedPlugin:
    meta:     PluginMeta
    path:     Path
    module:   object
    run_fn:   Optional[Callable] = None
    error:    str = ""


NSP_PLUGIN_TEMPLATE = '''"""
NEXUS SPECTER PRO — Custom Plugin Template
Copy this file to plugins/ and implement the run() function.
by OPTIMIUM NEXUS LLC
"""

NSP_PLUGIN = {
    "name":        "my_custom_plugin",
    "version":     "1.0.0",
    "author":      "Your Name",
    "phase":       "recon",          # recon|enumeration|vuln_scan|reporting|...
    "description": "What this plugin does",
    "api_version": "1.0",
    "tags":        ["custom"],
    "requires":    [],               # pip packages required
}


def run(target: str, config: dict = None, session=None) -> dict:
    """
    Main plugin entry point.
    Args:
        target:  The scan target (IP, domain, URL)
        config:  Plugin-specific config dict
        session: NSP session object (for storing results)
    Returns:
        dict with findings/results to merge into the NSP report
    """
    config = config or {}
    results = {
        "plugin":   NSP_PLUGIN["name"],
        "target":   target,
        "findings": [],
    }

    # --- YOUR CODE HERE ---

    return results
'''


class PluginLoader:
    """
    NSP Plugin Loader — discovers and manages custom plugins.
    Plugins are .py files in the configured plugin directories
    that export an NSP_PLUGIN dict and a run() function.
    """

    DEFAULT_PLUGIN_DIRS = [
        Path("plugins"),
        Path(os.path.expanduser("~/.nsp/plugins")),
        Path("/opt/nsp/plugins"),
    ]

    def __init__(self, plugin_dirs: list = None):
        self.plugin_dirs  = [Path(d) for d in (plugin_dirs or [])] + self.DEFAULT_PLUGIN_DIRS
        self.plugins:     dict[str, LoadedPlugin] = {}
        self._discovered: list[Path] = []

    def discover(self) -> list:
        """Scan plugin directories and return list of plugin paths found."""
        found = []
        for d in self.plugin_dirs:
            if not d.exists():
                continue
            for f in d.glob("*.py"):
                if not f.name.startswith("_"):
                    found.append(f)
                    log.debug(f"[PLUGINS] Discovered: {f}")
        self._discovered = found
        log.info(f"[PLUGINS] {len(found)} plugin files discovered")
        return found

    def _validate_meta(self, meta_dict: dict) -> Optional[PluginMeta]:
        required = {"name","version","author","phase","description"}
        missing  = required - set(meta_dict.keys())
        if missing:
            log.error(f"[PLUGINS] Missing metadata fields: {missing}")
            return None
        if meta_dict["phase"] not in VALID_PHASES:
            log.error(f"[PLUGINS] Invalid phase '{meta_dict['phase']}' — "
                      f"valid: {VALID_PHASES}")
            return None
        return PluginMeta(**{k: v for k, v in meta_dict.items()
                             if k in PluginMeta.__dataclass_fields__})

    def _check_requirements(self, requires: list) -> bool:
        """Verify pip dependencies are installed."""
        missing = []
        for pkg in requires:
            try:
                importlib.import_module(pkg.split(">=")[0].split("==")[0].replace("-","_"))
            except ImportError:
                missing.append(pkg)
        if missing:
            log.warning(f"[PLUGINS] Missing requirements: {missing} — "
                        f"run: pip install {' '.join(missing)}")
            return False
        return True

    def load(self, path: Path) -> Optional[LoadedPlugin]:
        """Load a single plugin file."""
        try:
            spec   = importlib.util.spec_from_file_location(path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            raw_meta = getattr(module, "NSP_PLUGIN", None)
            if not raw_meta:
                log.error(f"[PLUGINS] {path.name}: missing NSP_PLUGIN dict")
                return None

            meta = self._validate_meta(raw_meta)
            if not meta:
                return None

            run_fn = getattr(module, "run", None)
            if not callable(run_fn):
                log.error(f"[PLUGINS] {path.name}: missing run() function")
                return None

            if meta.requires and not self._check_requirements(meta.requires):
                log.warning(f"[PLUGINS] {meta.name}: requirements not met — loading anyway")

            plugin = LoadedPlugin(meta=meta, path=path, module=module, run_fn=run_fn)
            self.plugins[meta.name] = plugin
            log.info(f"[PLUGINS] Loaded: {meta.name} v{meta.version} [{meta.phase}]")
            return plugin

        except Exception as e:
            log.error(f"[PLUGINS] Failed to load {path.name}: {e}")
            return LoadedPlugin(
                meta=PluginMeta(name=path.stem, version="?", author="?",
                                phase="?", description=""),
                path=path, module=None, error=str(e)
            )

    def load_all(self) -> dict:
        """Discover and load all plugins."""
        if not self._discovered:
            self.discover()
        for path in self._discovered:
            self.load(path)
        console.print(f"[bold #00FFD4]  ✅ {len(self.plugins)} plugins loaded[/bold #00FFD4]")
        return self.plugins

    def get_by_phase(self, phase: str) -> list:
        """Return all enabled plugins for a specific phase."""
        return [p for p in self.plugins.values()
                if p.meta.phase == phase and p.meta.enabled and not p.error]

    def run_phase_plugins(self, phase: str, target: str,
                           config: dict = None, session=None) -> dict:
        """Execute all plugins registered for a phase and aggregate results."""
        plugins = self.get_by_phase(phase)
        if not plugins:
            return {}
        console.print(f"[bold #7B00FF]  🔌 Running {len(plugins)} plugin(s) for phase: {phase}[/bold #7B00FF]")
        aggregated = {"phase": phase, "plugin_results": []}
        for plugin in plugins:
            console.print(f"[#00FFD4]  → Plugin: {plugin.meta.name} v{plugin.meta.version}[/#00FFD4]")
            try:
                result = plugin.run_fn(target=target, config=config, session=session)
                aggregated["plugin_results"].append({
                    "plugin": plugin.meta.name,
                    "result": result,
                })
                log.info(f"[PLUGINS] {plugin.meta.name} completed OK")
            except Exception as e:
                log.error(f"[PLUGINS] {plugin.meta.name} raised: {e}")
                aggregated["plugin_results"].append({
                    "plugin": plugin.meta.name,
                    "error":  str(e),
                })
        return aggregated

    def print_registry(self):
        table = Table(
            title="[bold #7B00FF]🔌 NSP PLUGIN REGISTRY[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Name",        style="#00FFD4", width=25)
        table.add_column("Version",     width=10)
        table.add_column("Phase",       width=16)
        table.add_column("Author",      width=22)
        table.add_column("Status",      width=12)
        table.add_column("Description", width=35)
        for p in self.plugins.values():
            status = "[bold #FF003C]ERROR[/bold #FF003C]" if p.error \
                else ("[bold #00FFD4]✅ OK[/bold #00FFD4]" if p.meta.enabled else "[dim]DISABLED[/dim]")
            table.add_row(p.meta.name, p.meta.version, p.meta.phase,
                          p.meta.author, status, p.meta.description[:35])
        console.print(table)

    def create_template(self, output_path: str = "plugins/my_plugin.py"):
        """Write the plugin template to a file for plugin authors."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(NSP_PLUGIN_TEMPLATE)
        console.print(f"[bold #00FFD4]  ✅ Plugin template created: {path}[/bold #00FFD4]")
