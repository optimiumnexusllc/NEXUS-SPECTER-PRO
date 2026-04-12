"""
NEXUS SPECTER PRO — API Enumerator
Discovers and maps REST, GraphQL, gRPC, and SOAP endpoints.
Probes: OpenAPI/Swagger specs, GraphQL introspection, wsdl, common API paths.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import requests, logging, json, re
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.enum.api")
requests.packages.urllib3.disable_warnings()

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/v1", "/v2", "/v3",
    "/graphql", "/graphiql", "/playground", "/altair",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi",
    "/api-docs", "/api/docs", "/docs",
    "/wsdl", "/service.wsdl", "/api.wsdl",
    "/.well-known/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env",
    "/admin/api", "/internal/api", "/private/api",
    "/api/swagger-ui.html",
]

GRAPHQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name type { name kind } }
    }
  }
}
"""


@dataclass
class APIEndpoint:
    url:      str
    api_type: str    # rest | graphql | grpc | soap | unknown
    method:   str = "GET"
    status:   int = 0
    auth:     str = ""    # none | bearer | apikey | basic | oauth
    version:  str = ""
    paths:    list = field(default_factory=list)
    schemas:  dict = field(default_factory=dict)
    issues:   list = field(default_factory=list)


class APIEnumerator:
    """
    Enumerates APIs exposed by the target.
    Discovers OpenAPI specs, performs GraphQL introspection,
    probes common API paths, and identifies auth mechanisms.
    """

    def __init__(self, base_url: str, cookies: str = None,
                 headers: dict = None, proxy: str = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.proxies  = {"http": proxy, "https": proxy} if proxy else {}
        self.session  = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (NSP-SPECTER)",
            "Accept": "application/json, */*",
            **(headers or {}),
        })
        if cookies:
            self.session.headers["Cookie"] = cookies
        self.endpoints: list[APIEndpoint] = []

    def _get(self, path: str) -> requests.Response | None:
        try:
            return self.session.get(f"{self.base_url}{path}", timeout=self.timeout,
                                     proxies=self.proxies, verify=False,
                                     allow_redirects=True)
        except Exception:
            return None

    def _post(self, path: str, json_body: dict) -> requests.Response | None:
        try:
            return self.session.post(f"{self.base_url}{path}", json=json_body,
                                      timeout=self.timeout, proxies=self.proxies,
                                      verify=False)
        except Exception:
            return None

    def probe_common_paths(self) -> list:
        """Probe common API paths and return live endpoints."""
        found = []
        console.print(f"[#00FFD4]  [API] Probing {len(COMMON_API_PATHS)} common API paths...[/#00FFD4]")
        for path in COMMON_API_PATHS:
            r = self._get(path)
            if r and r.status_code in (200, 201, 204, 401, 403):
                ct = r.headers.get("Content-Type","")
                found.append({
                    "path":    path,
                    "status":  r.status_code,
                    "ct":      ct,
                    "size":    len(r.content),
                    "auth_required": r.status_code in (401, 403),
                })
                console.print(f"  [bold #FF003C]→ {r.status_code}[/bold #FF003C] "
                               f"[#00FFD4]{path}[/#00FFD4] [{ct[:30]}]")
        return found

    def discover_openapi(self) -> dict:
        """Attempt to retrieve OpenAPI/Swagger spec."""
        spec_paths = ["/openapi.json","/swagger.json","/api-docs",
                      "/v2/api-docs","/v3/api-docs","/swagger.yaml","/openapi.yaml"]
        for path in spec_paths:
            r = self._get(path)
            if r and r.status_code == 200:
                try:
                    spec = r.json()
                    if "openapi" in spec or "swagger" in spec or "paths" in spec:
                        console.print(f"[bold #FF003C]  ⚡ OpenAPI spec found: {path}[/bold #FF003C]")
                        paths     = list(spec.get("paths", {}).keys())
                        version   = spec.get("openapi") or spec.get("swagger","")
                        info      = spec.get("info", {})
                        servers   = spec.get("servers", [])
                        sec_defs  = spec.get("securityDefinitions") or spec.get("components",{}).get("securitySchemes",{})

                        console.print(f"  [#00FFD4]API: {info.get('title','')} v{info.get('version','')} "
                                       f"| {len(paths)} paths | spec: OpenAPI {version}[/#00FFD4]")

                        return {
                            "found":     True,
                            "path":      path,
                            "spec_path": path,
                            "title":     info.get("title",""),
                            "version":   info.get("version",""),
                            "spec_ver":  version,
                            "paths":     paths[:100],
                            "servers":   servers,
                            "security":  list(sec_defs.keys()),
                            "endpoints_count": len(paths),
                        }
                except Exception:
                    pass
        return {"found": False}

    def graphql_introspection(self) -> dict:
        """Probe for GraphQL endpoint and run introspection."""
        gql_paths = ["/graphql","/graphiql","/api/graphql","/v1/graphql","/query"]
        for path in gql_paths:
            r = self._post(path, {"query": GRAPHQL_INTROSPECTION})
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        schema   = data["data"]["__schema"]
                        types    = [t["name"] for t in schema.get("types",[])
                                    if not t["name"].startswith("__")]
                        console.print(f"[bold #FF003C]  ⚡ GraphQL introspection enabled: {path}[/bold #FF003C]")
                        console.print(f"  [#00FFD4]Types: {', '.join(types[:8])}...[/#00FFD4]")
                        return {
                            "found":       True,
                            "path":        path,
                            "introspection_enabled": True,
                            "types":       types,
                            "query_type":  (schema.get("queryType") or {}).get("name"),
                            "mutation_type": (schema.get("mutationType") or {}).get("name"),
                            "issue":       "GraphQL introspection is enabled in production — disable it.",
                        }
                    elif "errors" in data:
                        console.print(f"[#00FFD4]  → GraphQL endpoint at {path} (introspection disabled)[/#00FFD4]")
                        return {"found": True, "path": path,
                                "introspection_enabled": False}
                except Exception:
                    pass
        return {"found": False}

    def detect_auth_mechanism(self) -> dict:
        """Probe authentication headers on discovered API paths."""
        auth_info = {"mechanisms": [], "issues": []}
        test_path = self.endpoints[0].url.replace(self.base_url,"") if self.endpoints else "/api"
        r = self._get(test_path)
        if not r:
            return auth_info
        wwwauth = r.headers.get("WWW-Authenticate","")
        if "Bearer" in wwwauth or "bearer" in r.text.lower()[:200]:
            auth_info["mechanisms"].append("Bearer Token (JWT/OAuth)")
        if "Basic" in wwwauth:
            auth_info["mechanisms"].append("HTTP Basic Auth")
        if "ApiKey" in wwwauth or "api_key" in r.text.lower()[:200]:
            auth_info["mechanisms"].append("API Key")
        if r.status_code == 200 and not wwwauth:
            auth_info["issues"].append("API responds 200 with no authentication — possible unauthenticated access")
        cors = r.headers.get("Access-Control-Allow-Origin","")
        if cors == "*":
            auth_info["issues"].append("CORS: Access-Control-Allow-Origin: * — overly permissive")
        return auth_info

    def _print_results(self):
        table = Table(
            title=f"[bold #7B00FF]🔌 API ENUMERATION RESULTS[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Type",   style="#7B00FF", width=10)
        table.add_column("URL",    style="#00FFD4", width=45)
        table.add_column("Status", width=8)
        table.add_column("Auth",   width=12)
        table.add_column("Paths",  width=8, justify="right")
        for ep in self.endpoints:
            table.add_row(ep.api_type, ep.url[:45], str(ep.status),
                          ep.auth, str(len(ep.paths)))
        console.print(table)

    def run(self) -> dict:
        console.print(f"[bold #7B00FF]  🔌 API Enumerator — {self.base_url}[/bold #7B00FF]")
        result = {"target": self.base_url, "apis": {}}

        common_paths = self.probe_common_paths()
        result["common_paths"] = common_paths

        openapi = self.discover_openapi()
        result["apis"]["openapi"] = openapi
        if openapi["found"]:
            self.endpoints.append(APIEndpoint(
                url=f"{self.base_url}{openapi['path']}",
                api_type="rest", status=200,
                paths=openapi.get("paths",[]),
            ))

        graphql = self.graphql_introspection()
        result["apis"]["graphql"] = graphql
        if graphql["found"]:
            self.endpoints.append(APIEndpoint(
                url=f"{self.base_url}{graphql['path']}",
                api_type="graphql", status=200,
            ))

        auth_info = self.detect_auth_mechanism()
        result["auth"] = auth_info

        if self.endpoints:
            self._print_results()

        result["total_endpoints"] = len(self.endpoints)
        console.print(f"[bold #00FFD4]  ✅ API enum complete — {len(self.endpoints)} APIs | "
                       f"{len(common_paths)} paths[/bold #00FFD4]")
        return result
