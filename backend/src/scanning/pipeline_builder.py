from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass
import json

class ToolCategory(Enum):
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    DNS_RESOLUTION = "dns_resolution"
    HTTP_PROBING = "http_probing"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    CRAWLING = "crawling"
    DIRECTORY_DISCOVERY = "directory_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    SCREENSHOT = "screenshot"
    FINGERPRINTING = "fingerprinting"

@dataclass
class PipelineStage:
    name: str
    category: ToolCategory
    tools: List[str]
    depends_on: List[str]
    condition: Optional[str] = None
    parallel: bool = False
    timeout: int = 300
    retries: int = 1

class WorkflowPlanner:
    def __init__(self, config_path: str = "config/pipelines.yaml"):
        self.config = self.load_config(config_path)
        self.tool_registry = self.load_tool_registry()
    
    def load_config(self, path: str) -> Dict:
        """Load pipeline configuration"""
        # This would load from YAML file
        return {
            "profiles": {
                "quick": ["subdomain_discovery", "dns_resolution", "http_probing"],
                "standard": ["subdomain_discovery", "dns_resolution", "http_probing", 
                           "port_scanning", "crawling", "vulnerability_scanning"],
                "deep": ["subdomain_discovery", "dns_resolution", "http_probing", 
                        "port_scanning", "service_detection", "crawling", 
                        "directory_discovery", "parameter_discovery", 
                        "vulnerability_scanning", "screenshot", "fingerprinting"],
                "passive": ["subdomain_discovery", "dns_resolution", "http_probing"]
            },
            "stages": {
                "subdomain_discovery": {
                    "tools": ["subfinder", "assetfinder", "amass_passive"],
                    "parallel": True,
                    "depends_on": []
                },
                "dns_resolution": {
                    "tools": ["dnsx"],
                    "depends_on": ["subdomain_discovery"],
                    "condition": "subdomains_found > 0"
                },
                # ... other stages
            }
        }
    
    def load_tool_registry(self) -> Dict:
        """Load tool configurations from database"""
        # This would query tool_configurations table
        return {
            "subfinder": {
                "category": ToolCategory.SUBDOMAIN_DISCOVERY,
                "input_type": ["domain"],
                "output_format": "text",
                "parser": "subfinder_parser",
                "tables_written": ["subdomains"],
                "default_args": ["-silent"],
                "risk_level": "passive"
            },
            # ... other tools
        }
    
    def build_pipeline(self, target_type: str, profile: str, input_value: str) -> List[Dict]:
        """Build pipeline stages for given input and profile"""
        pipeline = []
        
        # Determine pipeline based on input type
        if target_type == "domain":
            pipeline = self.build_domain_pipeline(profile, input_value)
        elif target_type == "url":
            pipeline = self.build_url_pipeline(profile, input_value)
        elif target_type == "ip":
            pipeline = self.build_ip_pipeline(profile, input_value)
        elif target_type == "cidr":
            pipeline = self.build_cidr_pipeline(profile, input_value)
        
        return pipeline
    
    def build_domain_pipeline(self, profile: str, domain: str) -> List[Dict]:
        """Build pipeline for domain scanning"""
        stages = []
        profile_stages = self.config["profiles"][profile]
        
        for stage_name in profile_stages:
            stage_config = self.config["stages"][stage_name]
            
            stage = {
                "name": stage_name,
                "tools": stage_config["tools"],
                "depends_on": stage_config.get("depends_on", []),
                "parallel": stage_config.get("parallel", False),
                "condition": stage_config.get("condition"),
                "timeout": stage_config.get("timeout", 300),
                "retries": stage_config.get("retries", 1)
            }
            
            # Add tool-specific configurations
            stage["tool_configs"] = []
            for tool in stage["tools"]:
                if tool in self.tool_registry:
                    tool_config = self.tool_registry[tool].copy()
                    tool_config["command_template"] = self.build_command_template(
                        tool, domain, profile
                    )
                    stage["tool_configs"].append(tool_config)
            
            stages.append(stage)
        
        return stages
    
    def build_command_template(self, tool: str, target: str, profile: str) -> str:
        """Build command template for a tool"""
        templates = {
            "subfinder": f"subfinder -d {target} -silent -o {{output_path}}",
            "dnsx": f"dnsx -l {{input_path}} -a -aaaa -cname -ns -txt -json -o {{output_path}}",
            "httpx": f"httpx -l {{input_path}} -title -status-code -content-length -tech-detect -json -o {{output_path}}",
            "naabu": f"naabu -host {{input_path}} -top-ports 100 -json -o {{output_path}}",
            "nmap": f"nmap -sV -sC -oX {{output_path}} {{targets}}",
            "katana": f"katana -u {{input_path}} -json -o {{output_path}}",
            "dirsearch": f"dirsearch -u {{target}} -e php,html,js,json -o {{output_path}} --format=json",
            "nuclei": f"nuclei -l {{input_path}} -t ~/nuclei-templates/ -severity critical,high,medium -json -o {{output_path}}"
        }
        
        return templates.get(tool, "")
    
    def validate_pipeline(self, pipeline: List[Dict]) -> bool:
        """Validate pipeline dependencies and cycles"""
        visited = set()
        stack = set()
        
        def dfs(stage_name: str) -> bool:
            if stage_name in stack:
                return False  # Cycle detected
            if stage_name in visited:
                return True
            
            stack.add(stage_name)
            stage = next((s for s in pipeline if s["name"] == stage_name), None)
            if not stage:
                stack.remove(stage_name)
                return True
            
            for dep in stage.get("depends_on", []):
                if not dfs(dep):
                    return False
            
            stack.remove(stage_name)
            visited.add(stage_name)
            return True
        
        for stage in pipeline:
            if not dfs(stage["name"]):
                return False
        
        return True
