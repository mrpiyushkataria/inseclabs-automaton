import asyncio
import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from .workflow_planner import WorkflowPlanner
from .parsers import get_parser
from ..database.models import get_session, JobTask, ScanningJob

class JobOrchestrator:
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.workflow_planner = WorkflowPlanner()
        self.active_jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    async def start_scan(self, job_id: int, target: str, profile: str) -> Dict:
        """Start a new scanning job"""
        db = get_session()
        
        try:
            # Update job status
            job = db.query(ScanningJob).filter(ScanningJob.id == job_id).first()
            if not job:
                return {"success": False, "error": "Job not found"}
            
            job.status = "running"
            job.started_at = datetime.utcnow()
            db.commit()
            
            # Build pipeline
            pipeline = self.workflow_planner.build_pipeline(
                target_type=self.detect_target_type(target),
                profile=profile,
                input_value=target
            )
            
            # Create job directory
            job_dir = Path(f"/opt/inseclabs/artifacts/{job_id}")
            job_dir.mkdir(parents=True, exist_ok=True)
            
            # Execute pipeline
            self.active_jobs[job_id] = {
                "job": job,
                "pipeline": pipeline,
                "artifacts_dir": job_dir,
                "status": "running"
            }
            
            # Start execution in background
            asyncio.create_task(self.execute_pipeline(job_id, pipeline, job_dir))
            
            return {"success": True, "job_id": job_id}
            
        except Exception as e:
            db.rollback()
            return {"success": False, "error": str(e)}
        finally:
            db.close()
    
    def detect_target_type(self, target: str) -> str:
        """Detect target type from input"""
        if target.startswith('http://') or target.startswith('https://'):
            return 'url'
        elif '/' in target and (target.split('/')[-1].isdigit() or ':' in target):
            return 'cidr'
        elif target.replace('.', '').isdigit():
            if target.count('.') == 3:
                return 'ip'
        else:
            return 'domain'
    
    async def execute_pipeline(self, job_id: int, pipeline: List[Dict], job_dir: Path):
        """Execute pipeline stages"""
        db = get_session()
        
        try:
            job = db.query(ScanningJob).filter(ScanningJob.id == job_id).first()
            if not job:
                return
            
            completed_stages = set()
            stage_results = {}
            
            # Execute stages in order
            for stage in pipeline:
                stage_name = stage["name"]
                
                # Check dependencies
                deps_met = all(dep in completed_stages for dep in stage.get("depends_on", []))
                if not deps_met:
                    continue
                
                # Check condition
                condition = stage.get("condition")
                if condition and not self.evaluate_condition(condition, stage_results):
                    continue
                
                # Execute stage
                stage_result = await self.execute_stage(
                    job_id, stage, job_dir, stage_results
                )
                
                stage_results[stage_name] = stage_result
                completed_stages.add(stage_name)
                
                # Update job progress
                progress = int((len(completed_stages) / len(pipeline)) * 100)
                job.progress_percent = progress
                db.commit()
            
            # Mark job as completed
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            job.progress_percent = 100
            
            # Generate summary
            summary = self.generate_job_summary(job_id, stage_results)
            job.results_summary = summary
            
            db.commit()
            
        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            db.commit()
        finally:
            db.close()
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
    
    async def execute_stage(self, job_id: int, stage: Dict, job_dir: Path, 
                           previous_results: Dict) -> Dict:
        """Execute a single pipeline stage"""
        db = get_session()
        stage_result = {"tools": [], "outputs": {}}
        
        try:
            tools = stage["tool_configs"]
            
            if stage.get("parallel", False):
                # Execute tools in parallel
                futures = []
                for tool_config in tools:
                    future = self.executor.submit(
                        self.execute_tool,
                        job_id, tool_config, job_dir, previous_results
                    )
                    futures.append(future)
                
                for future in as_completed(futures):
                    tool_result = future.result()
                    stage_result["tools"].append(tool_result)
            else:
                # Execute tools sequentially
                for tool_config in tools:
                    tool_result = await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.execute_tool,
                        job_id, tool_config, job_dir, previous_results
                    )
                    stage_result["tools"].append(tool_result)
            
            # Merge outputs
            for tool_result in stage_result["tools"]:
                if tool_result["success"] and tool_result.get("output"):
                    stage_result["outputs"].update(tool_result["output"])
            
            return stage_result
            
        finally:
            db.close()
    
    def execute_tool(self, job_id: int, tool_config: Dict, job_dir: Path, 
                    previous_results: Dict) -> Dict:
        """Execute a single tool"""
        db = get_session()
        
        try:
            # Create task record
            task = JobTask(
                job_id=job_id,
                tool_name=tool_config["name"],
                task_type=tool_config.get("category", "scan"),
                status="running",
                started_at=datetime.utcnow()
            )
            db.add(task)
            db.commit()
            
            # Prepare command
            command = self.prepare_command(
                tool_config, job_dir, task.id, previous_results
            )
            task.command_line = command
            
            # Create output directory
            task_dir = job_dir / str(task.id)
            task_dir.mkdir(exist_ok=True)
            
            output_file = task_dir / f"{tool_config['name']}.json"
            
            # Execute command
            start_time = datetime.utcnow()
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool_config.get("timeout", 300)
            )
            end_time = datetime.utcnow()
            
            # Save output
            if process.stdout:
                with open(output_file, 'w') as f:
                    f.write(process.stdout)
            
            # Update task record
            task.status = "success" if process.returncode == 0 else "failed"
            task.exit_code = process.returncode
            task.stdout = process.stdout[:5000]  # Truncate
            task.stderr = process.stderr[:5000]   # Truncate
            task.output_file_path = str(output_file)
            task.completed_at = end_time
            
            # Calculate resource usage
            duration = (end_time - start_time).total_seconds()
            task.resource_usage = {
                "duration": duration,
                "cpu_percent": psutil.cpu_percent(),
                "memory_mb": psutil.virtual_memory().used / 1024 / 1024
            }
            
            # Parse output if successful
            if process.returncode == 0 and output_file.exists():
                parser = get_parser(tool_config["name"])
                if parser:
                    parse_result = parser.parse(str(output_file), job_id, task.id)
                    
                    # Save parsed results to database
                    self.save_parsed_results(parse_result, db)
                    
                    task.tables_written = list(parse_result.keys())
            
            db.commit()
            
            return {
                "success": process.returncode == 0,
                "task_id": task.id,
                "duration": duration,
                "output": parse_result if 'parse_result' in locals() else None
            }
            
        except subprocess.TimeoutExpired:
            task.status = "failed"
            task.error_message = "Timeout expired"
            db.commit()
            return {"success": False, "error": "Timeout"}
            
        except Exception as e:
            if 'task' in locals():
                task.status = "failed"
                task.error_message = str(e)
                db.commit()
            return {"success": False, "error": str(e)}
            
        finally:
            db.close()
    
    def prepare_command(self, tool_config: Dict, job_dir: Path, task_id: int,
                       previous_results: Dict) -> str:
        """Prepare command with proper arguments and inputs"""
        command_template = tool_config.get("command_template", "")
        
        # Create input file if needed
        input_path = None
        if "{input_path}" in command_template:
            # Get inputs from previous results
            inputs = self.collect_inputs(tool_config, previous_results)
            if inputs:
                input_file = job_dir / f"{task_id}_input.txt"
                with open(input_file, 'w') as f:
                    for item in inputs:
                        f.write(f"{item}\n")
                input_path = str(input_file)
        
        # Replace placeholders
        command = command_template
        if input_path:
            command = command.replace("{input_path}", input_path)
        
        command = command.replace("{output_path}", str(job_dir / str(task_id) / "output"))
        command = command.replace("{job_dir}", str(job_dir))
        command = command.replace("{task_id}", str(task_id))
        
        # Add default args
        default_args = tool_config.get("default_args", [])
        if default_args:
            command += " " + " ".join(default_args)
        
        return command
    
    def collect_inputs(self, tool_config: Dict, previous_results: Dict) -> List[str]:
        """Collect inputs from previous stage results"""
        inputs = []
        
        # This would collect appropriate inputs based on tool category
        # For example, for httpx, collect subdomains from dnsx stage
        # For naabu, collect IPs from dnsx stage
        
        return inputs
    
    def save_parsed_results(self, parse_result: Dict, db):
        """Save parsed results to database"""
        # This would save to appropriate tables based on parser output
        # Implementation depends on your database models
        pass
    
    def evaluate_condition(self, condition: str, stage_results: Dict) -> bool:
        """Evaluate condition for stage execution"""
        # Simple condition evaluation
        # Could be extended with a proper expression evaluator
        return True
    
    def generate_job_summary(self, job_id: int, stage_results: Dict) -> Dict:
        """Generate job summary from results"""
        summary = {
            "subdomains_found": 0,
            "alive_hosts": 0,
            "open_ports": 0,
            "urls_found": 0,
            "vulnerabilities_found": 0,
            "critical_vulns": 0,
            "high_vulns": 0
        }
        
        # Aggregate results from all stages
        for stage_name, results in stage_results.items():
            if "outputs" in results:
                outputs = results["outputs"]
                
                # Count subdomains
                if "subdomains" in outputs:
                    summary["subdomains_found"] += len(outputs["subdomains"])
                
                # Count alive hosts
                if "subdomain_history" in outputs:
                    alive = sum(1 for h in outputs["subdomain_history"] 
                              if h.get("http_status", 0) < 400)
                    summary["alive_hosts"] += alive
                
                # Count open ports
                if "ports" in outputs:
                    summary["open_ports"] += len(outputs["ports"])
                
                # Count URLs
                if "urls" in outputs:
                    summary["urls_found"] += len(outputs["urls"])
                
                # Count vulnerabilities
                if "vulnerabilities" in outputs:
                    vulns = outputs["vulnerabilities"]
                    summary["vulnerabilities_found"] += len(vulns)
                    summary["critical_vulns"] += sum(1 for v in vulns 
                                                    if v.get("severity") == "critical")
                    summary["high_vulns"] += sum(1 for v in vulns 
                                                if v.get("severity") == "high")
        
        return summary
    
    async def stop_job(self, job_id: int) -> bool:
        """Stop a running job"""
        if job_id not in self.active_jobs:
            return False
        
        # Mark job as stopped
        db = get_session()
        try:
            job = db.query(ScanningJob).filter(ScanningJob.id == job_id).first()
            if job:
                job.status = "stopped"
                db.commit()
            
            # Cancel running tasks (implementation depends on your task system)
            # This would send SIGTERM to running processes
            
            return True
            
        finally:
            db.close()
