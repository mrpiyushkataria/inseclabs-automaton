import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple
from pathlib import Path
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode

class BaseParser:
    """Base parser class with common utilities"""
    
    @staticmethod
    def normalize_subdomain(subdomain: str) -> str:
        """Normalize subdomain name"""
        subdomain = subdomain.lower().strip()
        if subdomain.endswith('.'):
            subdomain = subdomain[:-1]
        return subdomain
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)
        
        # Normalize scheme and host
        scheme = parsed.scheme.lower() if parsed.scheme else 'http'
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if ':' in netloc:
            host, port = netloc.split(':', 1)
            if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                netloc = host
        
        # Normalize path (keep case for path, remove trailing slash)
        path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
        
        # Normalize query parameters (sort keys)
        query = parsed.query
        if query:
            params = parse_qs(query, keep_blank_values=True)
            # Sort parameters by key
            sorted_params = sorted(params.items())
            query = urlencode(sorted_params, doseq=True)
        
        # Reconstruct URL
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        
        return normalized
    
    @staticmethod
    def generate_hash(content: str) -> str:
        """Generate SHA256 hash"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        """Parse artifact and return results"""
        raise NotImplementedError

class SubfinderParser(BaseParser):
    """Parser for subfinder output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "subdomains": [],
            "metrics": {"total": 0, "inserted": 0, "updated": 0}
        }
        
        with open(artifact_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                subdomain = self.normalize_subdomain(line)
                results["subdomains"].append({
                    "subdomain_name": subdomain,
                    "discovery_sources": ["subfinder"],
                    "confidence_score": 70,
                    "tool_source": "subfinder",
                    "job_id": job_id,
                    "task_id": task_id
                })
        
        results["metrics"]["total"] = len(results["subdomains"])
        return results

class HttpxParser(BaseParser):
    """Parser for httpx JSON output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "subdomain_history": [],
            "urls": [],
            "metrics": {"total": 0, "alive": 0}
        }
        
        with open(artifact_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                url = data.get("url", "")
                if not url:
                    continue
                
                parsed_url = urlparse(url)
                subdomain = parsed_url.netloc.lower()
                
                # Extract headers
                headers = data.get("headers", {})
                headers_hash = self.generate_hash(json.dumps(headers, sort_keys=True))
                
                # Extract technologies
                tech_raw = data.get("tech", [])
                technologies = []
                if isinstance(tech_raw, list):
                    technologies = [{"name": t, "confidence": 100} for t in tech_raw]
                
                # Add to subdomain history
                results["subdomain_history"].append({
                    "subdomain_name": subdomain,
                    "http_status": data.get("status_code"),
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length"),
                    "headers_hash": headers_hash,
                    "headers": headers,
                    "technologies": technologies,
                    "checked_at": data.get("timestamp", ""),
                    "tool_source": "httpx",
                    "job_id": job_id,
                    "task_id": task_id
                })
                
                # Add base URL
                normalized_url = self.normalize_url(url)
                results["urls"].append({
                    "url": url,
                    "normalized_url": normalized_url,
                    "path": parsed_url.path,
                    "query_params": parse_qs(parsed_url.query) if parsed_url.query else {},
                    "http_status": data.get("status_code"),
                    "content_length": data.get("content_length"),
                    "title": data.get("title", ""),
                    "discovered_by": "httpx",
                    "subdomain_name": subdomain,
                    "job_id": job_id,
                    "task_id": task_id
                })
                
                if data.get("status_code", 0) < 400:
                    results["metrics"]["alive"] += 1
        
        results["metrics"]["total"] = len(results["subdomain_history"])
        return results

class NaabuParser(BaseParser):
    """Parser for naabu JSON output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "ports": [],
            "metrics": {"total": 0, "open": 0}
        }
        
        with open(artifact_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                ip = data.get("ip", "")
                port = data.get("port", 0)
                hostname = data.get("host", "")
                
                if not ip or not port:
                    continue
                
                results["ports"].append({
                    "ip_address": ip,
                    "port_number": int(port),
                    "protocol": data.get("protocol", "tcp").lower(),
                    "state": "open",
                    "scan_tool": "naabu",
                    "banner": data.get("banner", ""),
                    "hostname": hostname,
                    "job_id": job_id,
                    "task_id": task_id
                })
                results["metrics"]["open"] += 1
        
        results["metrics"]["total"] = len(results["ports"])
        return results

class NmapParser(BaseParser):
    """Parser for nmap XML output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "ports": [],
            "service_details": [],
            "metrics": {"ports_found": 0, "services_identified": 0}
        }
        
        try:
            tree = ET.parse(artifact_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                # Get IP address
                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is None:
                    continue
                ip = address_elem.get("addr")
                
                # Get hostname
                hostname = ""
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name")
                
                # Process ports
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                
                for port_elem in ports_elem.findall("port"):
                    port_num = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol")
                    
                    # Get port state
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"
                    
                    if state != "open":
                        continue
                    
                    # Get service information
                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_version = ""
                    banner = ""
                    
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        service_version = service_elem.get("version", "")
                        banner = service_elem.get("product", "")
                        if service_elem.get("extrainfo"):
                            banner += f" ({service_elem.get('extrainfo')})"
                    
                    # Add port
                    port_data = {
                        "ip_address": ip,
                        "port_number": port_num,
                        "protocol": protocol,
                        "state": state,
                        "scan_tool": "nmap",
                        "service_name": service_name,
                        "service_version": service_version,
                        "banner": banner,
                        "hostname": hostname,
                        "job_id": job_id,
                        "task_id": task_id
                    }
                    results["ports"].append(port_data)
                    results["metrics"]["ports_found"] += 1
                    
                    # Add service details if available
                    if service_name:
                        service_data = {
                            "ip_address": ip,
                            "port_number": port_num,
                            "service_name": service_name,
                            "service_version": service_version,
                            "banner": banner,
                            "cpe": [],  # Could extract from service_elem
                            "job_id": job_id,
                            "task_id": task_id
                        }
                        results["service_details"].append(service_data)
                        results["metrics"]["services_identified"] += 1
        
        except ET.ParseError as e:
            print(f"Error parsing nmap XML: {e}")
        
        return results

class DirsearchParser(BaseParser):
    """Parser for dirsearch JSON output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "urls": [],
            "metrics": {"total": 0, "interesting": 0}
        }
        
        with open(artifact_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return results
        
        # Dirsearch JSON structure
        if "results" in data:
            for item in data["results"]:
                url = item.get("url", "")
                if not url:
                    continue
                
                status = item.get("status", 0)
                content_length = item.get("content-length", 0)
                
                parsed_url = urlparse(url)
                subdomain = parsed_url.netloc.lower()
                
                # Check if interesting
                is_interesting = False
                interesting_reason = ""
                
                if 200 <= status < 300:
                    is_interesting = True
                    interesting_reason = "2xx status"
                elif status == 403:
                    is_interesting = True
                    interesting_reason = "403 Forbidden"
                elif status == 500:
                    is_interesting = True
                    interesting_reason = "500 Internal Error"
                
                normalized_url = self.normalize_url(url)
                results["urls"].append({
                    "url": url,
                    "normalized_url": normalized_url,
                    "path": parsed_url.path,
                    "query_params": parse_qs(parsed_url.query) if parsed_url.query else {},
                    "http_status": status,
                    "content_length": content_length,
                    "discovered_by": "dirsearch",
                    "is_interesting": is_interesting,
                    "interesting_reason": interesting_reason if is_interesting else "",
                    "subdomain_name": subdomain,
                    "job_id": job_id,
                    "task_id": task_id
                })
                
                if is_interesting:
                    results["metrics"]["interesting"] += 1
        
        results["metrics"]["total"] = len(results["urls"])
        return results

class NucleiParser(BaseParser):
    """Parser for nuclei JSON output"""
    
    def parse(self, artifact_path: str, job_id: int, task_id: int) -> Dict:
        results = {
            "vulnerabilities": [],
            "vulnerability_details": [],
            "metrics": {"total": 0, "critical": 0, "high": 0}
        }
        
        with open(artifact_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                template_id = data.get("template-id", "")
                info = data.get("info", {})
                severity = info.get("severity", "info").lower()
                
                # Skip info severity for production
                if severity == "info":
                    continue
                
                # Generate dedupe hash
                dedupe_content = f"{template_id}:{data.get('host', '')}:{data.get('matched-at', '')}"
                dedupe_hash = self.generate_hash(dedupe_content)
                
                # Create vulnerability record
                vuln = {
                    "vulnerability_type": template_id,
                    "template_id": template_id,
                    "severity": severity,
                    "title": info.get("name", ""),
                    "description": info.get("description", ""),
                    "remediation": info.get("remediation", ""),
                    "scanner_tool": "nuclei",
                    "dedupe_hash": dedupe_hash,
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "matcher_name": data.get("matcher-name", ""),
                    "job_id": job_id,
                    "task_id": task_id
                }
                
                # Add CVE if available
                if "classification" in info:
                    cve = info["classification"].get("cve-id")
                    if cve:
                        vuln["cve_id"] = cve
                
                results["vulnerabilities"].append(vuln)
                
                # Add vulnerability details
                if "request" in data and "response" in data:
                    details = {
                        "dedupe_hash": dedupe_hash,
                        "request_data": data.get("request", ""),
                        "response_data": data.get("response", ""),
                        "payload": data.get("payload", ""),
                        "raw_output": line.strip(),
                        "job_id": job_id,
                        "task_id": task_id
                    }
                    results["vulnerability_details"].append(details)
                
                # Update metrics
                results["metrics"]["total"] += 1
                if severity == "critical":
                    results["metrics"]["critical"] += 1
                elif severity == "high":
                    results["metrics"]["high"] += 1
        
        return results

# Parser registry
PARSER_REGISTRY = {
    "subfinder": SubfinderParser(),
    "httpx": HttpxParser(),
    "naabu": NaabuParser(),
    "nmap": NmapParser(),
    "dirsearch": DirsearchParser(),
    "nuclei": NucleiParser(),
    # Add more parsers as needed
}

def get_parser(tool_name: str) -> BaseParser:
    """Get parser for a tool"""
    return PARSER_REGISTRY.get(tool_name)
