import subprocess
import json
import shutil
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml

class ToolManager:
    def __init__(self, db_session):
        self.db = db_session
        self.tools_config_path = "config/tools.yaml"
        self.install_base_path = "/opt/inseclabs/tools"
        self.tools = self.load_tools_config()
    
    def load_tools_config(self) -> Dict:
        """Load tools configuration from YAML"""
        with open(self.tools_config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def get_all_tools(self) -> List[Dict]:
        """Get all tools with their status"""
        tools = []
        for tool_name, config in self.tools.items():
            tool_status = self.get_tool_status(tool_name)
            tools.append({
                "name": tool_name,
                **config,
                **tool_status
            })
        return tools
    
    def get_tool_status(self, tool_name: str) -> Dict:
        """Check if tool is installed and healthy"""
        if tool_name not in self.tools:
            return {"is_installed": False, "health_status": "unknown"}
        
        config = self.tools[tool_name]
        install_path = Path(self.install_base_path) / config.get("install_path", "")
        
        status = {
            "is_installed": False,
            "health_status": "unknown",
            "version": None,
            "last_checked": None
        }
        
        # Check if tool exists
        if install_path.exists():
            status["is_installed"] = True
            
            # Check version
            version = self.check_tool_version(tool_name, config)
            status["version"] = version
            
            # Run health check
            health_ok = self.run_health_check(tool_name, config)
            status["health_status"] = "healthy" if health_ok else "unhealthy"
        
        status["last_checked"] = datetime.utcnow().isoformat()
        return status
    
    def check_tool_version(self, tool_name: str, config: Dict) -> Optional[str]:
        """Get tool version"""
        try:
            if config["install_method"] == "apt":
                cmd = f"{tool_name} --version"
            elif config["install_method"] == "go":
                cmd = f"{config['bin_path']} -version"
            elif config["install_method"] == "pip":
                cmd = f"python -m {tool_name} --version"
            else:
                return None
            
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip().split('\n')[0]
        except:
            return None
    
    def run_health_check(self, tool_name: str, config: Dict) -> bool:
        """Run tool health check"""
        try:
            if "health_check" not in config:
                return True
            
            health_cmd = config["health_check"]
            result = subprocess.run(
                health_cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            return result.returncode == 0
        except:
            return False
    
    def install_tool(self, tool_name: str) -> Dict:
        """Install a tool"""
        if tool_name not in self.tools:
            return {"success": False, "error": "Tool not in registry"}
        
        config = self.tools[tool_name]
        install_log = []
        
        try:
            # Create installation directory
            install_dir = Path(self.install_base_path) / config.get("install_path", "")
            install_dir.mkdir(parents=True, exist_ok=True)
            
            # Install dependencies
            for dep in config.get("dependencies", []):
                install_log.append(f"Installing dependency: {dep}")
                result = subprocess.run(
                    f"apt-get install -y {dep}",
                    shell=True, capture_output=True, text=True
                )
                if result.returncode != 0:
                    return {"success": False, "error": f"Dependency failed: {dep}"}
            
            # Install tool
            install_method = config["install_method"]
            install_log.append(f"Installing using {install_method}")
            
            if install_method == "apt":
                cmd = f"apt-get install -y {tool_name}"
            elif install_method == "go":
                cmd = f"go install {config['go_package']}@{config.get('version', 'latest')}"
            elif install_method == "pip":
                cmd = f"pip install {tool_name}{config.get('version', '')}"
            elif install_method == "git":
                cmd = f"git clone {config['repo_url']} {install_dir}"
            else:
                return {"success": False, "error": f"Unknown install method: {install_method}"}
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            install_log.append(result.stdout)
            
            if result.returncode != 0:
                return {"success": False, "error": result.stderr, "log": install_log}
            
            # Verify installation
            if not self.get_tool_status(tool_name)["is_installed"]:
                return {"success": False, "error": "Installation verification failed"}
            
            # Update database
            self.update_tool_config(tool_name, {
                "is_installed": True,
                "install_path": str(install_dir),
                "last_health_check": datetime.utcnow()
            })
            
            return {"success": True, "log": install_log}
            
        except Exception as e:
            return {"success": False, "error": str(e), "log": install_log}
    
    def update_tool_config(self, tool_name: str, updates: Dict):
        """Update tool configuration in database"""
        # This would update tool_configurations table
        pass

# Tools configuration YAML
TOOLS_YAML = """
# File: config/tools.yaml

subfinder:
  category: subdomain_discovery
  official_link: "https://github.com/projectdiscovery/subfinder"
  install_method: "go"
  go_package: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  bin_path: "/go/bin/subfinder"
  version_check: "subfinder -version"
  health_check: "subfinder -version"
  default_args: ["-silent", "-timeout 30"]
  output_format: "text"
  parser_id: "subfinder_parser"
  tables_written: ["subdomains"]
  risk_level: "passive"

amass:
  category: subdomain_discovery
  official_link: "https://github.com/OWASP/Amass"
  install_method: "go"
  go_package: "github.com/OWASP/Amass/v3/..."
  bin_path: "/go/bin/amass"
  version_check: "amass -version"
  health_check: "amass -version"
  default_args: ["-passive"]
  output_format: "json"
  parser_id: "amass_parser"
  tables_written: ["subdomains"]
  risk_level: "passive"

dnsx:
  category: dns_resolution
  official_link: "https://github.com/projectdiscovery/dnsx"
  install_method: "go"
  go_package: "github.com/projectdiscovery/dnsx/cmd/dnsx"
  bin_path: "/go/bin/dnsx"
  version_check: "dnsx -version"
  health_check: "echo 'google.com' | dnsx -silent"
  default_args: ["-a", "-aaaa", "-json"]
  output_format: "json"
  parser_id: "dnsx_parser"
  tables_written: ["subdomains"]
  risk_level: "passive"

httpx:
  category: http_probing
  official_link: "https://github.com/projectdiscovery/httpx"
  install_method: "go"
  go_package: "github.com/projectdiscovery/httpx/cmd/httpx"
  bin_path: "/go/bin/httpx"
  version_check: "httpx -version"
  health_check: "echo 'https://google.com' | httpx -silent"
  default_args: ["-title", "-status-code", "-tech-detect", "-json"]
  output_format: "json"
  parser_id: "httpx_parser"
  tables_written: ["subdomain_history", "urls"]
  risk_level: "passive"

naabu:
  category: port_scanning
  official_link: "https://github.com/projectdiscovery/naabu"
  install_method: "go"
  go_package: "github.com/projectdiscovery/naabu/v2/cmd/naabu"
  bin_path: "/go/bin/naabu"
  version_check: "naabu -version"
  health_check: "naabu -host scanme.nmap.org -p 80 -silent"
  default_args: ["-silent", "-rate 1000"]
  output_format: "json"
  parser_id: "naabu_parser"
  tables_written: ["ports"]
  risk_level: "active"

nmap:
  category: service_detection
  official_link: "https://nmap.org"
  install_method: "apt"
  dependencies: ["nmap"]
  bin_path: "/usr/bin/nmap"
  version_check: "nmap --version"
  health_check: "nmap --version"
  default_args: ["-sV", "-sC", "-T4"]
  output_format: "xml"
  parser_id: "nmap_parser"
  tables_written: ["ports", "service_details"]
  risk_level: "active"

katana:
  category: crawling
  official_link: "https://github.com/projectdiscovery/katana"
  install_method: "go"
  go_package: "github.com/projectdiscovery/katana/cmd/katana"
  bin_path: "/go/bin/katana"
  version_check: "katana -version"
  health_check: "katana -u https://google.com -silent"
  default_args: ["-js-crawl", "-json"]
  output_format: "json"
  parser_id: "katana_parser"
  tables_written: ["urls"]
  risk_level: "active"

dirsearch:
  category: directory_discovery
  official_link: "https://github.com/maurosoria/dirsearch"
  install_method: "git"
  repo_url: "https://github.com/maurosoria/dirsearch.git"
  install_path: "dirsearch"
  bin_path: "/opt/inseclabs/tools/dirsearch/dirsearch.py"
  version_check: "python3 /opt/inseclabs/tools/dirsearch/dirsearch.py --version"
  health_check: "python3 /opt/inseclabs/tools/dirsearch/dirsearch.py -u https://google.com -e txt --max-time 5"
  default_args: ["-e php,html,js,json", "--format=json"]
  output_format: "json"
  parser_id: "dirsearch_parser"
  tables_written: ["urls"]
  risk_level: "active"

nuclei:
  category: vulnerability_scanning
  official_link: "https://github.com/projectdiscovery/nuclei"
  install_method: "go"
  go_package: "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
  bin_path: "/go/bin/nuclei"
  version_check: "nuclei -version"
  health_check: "nuclei -version"
  default_args: ["-severity critical,high,medium", "-json"]
  output_format: "json"
  parser_id: "nuclei_parser"
  tables_written: ["vulnerabilities", "vulnerability_details"]
  risk_level: "active"

gowitness:
  category: screenshot
  official_link: "https://github.com/sensepost/gowitness"
  install_method: "go"
  go_package: "github.com/sensepost/gowitness"
  bin_path: "/go/bin/gowitness"
  version_check: "gowitness --version"
  health_check: "gowitness --version"
  default_args: ["--disable-db", "--screenshot-timeout 10"]
  output_format: "files"
  parser_id: "screenshot_parser"
  tables_written: ["subdomain_history"]
  risk_level: "passive"
"""
