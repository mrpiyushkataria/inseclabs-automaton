from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from ..dependencies import get_current_user, get_db
from ...database.models import User, ScanningJob, JobTask
from ...tools.orchestrator import JobOrchestrator

router = APIRouter(prefix="/api/scans", tags=["scans"])
orchestrator = JobOrchestrator()

# Request/Response Models
class ScanCreate(BaseModel):
    target: str
    profile: str = "standard"
    description: Optional[str] = None
    tags: Optional[List[str]] = None

class ScanResponse(BaseModel):
    id: int
    target: str
    profile: str
    status: str
    progress_percent: int
    results_summary: Optional[dict]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

class TaskResponse(BaseModel):
    id: int
    tool_name: str
    task_type: str
    status: str
    command_line: Optional[str]
    exit_code: Optional[int]
    resource_usage: Optional[dict]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Create a new scan"""
    # Create target record
    from ...database.models import Target
    target = Target(
        user_id=current_user.id,
        target_type=orchestrator.detect_target_type(scan_data.target),
        target_value=scan_data.target,
        description=scan_data.description,
        tags=scan_data.tags or [],
        authorization_given=True
    )
    db.add(target)
    db.commit()
    
    # Create scanning job
    job = ScanningJob(
        user_id=current_user.id,
        target_id=target.id,
        profile=scan_data.profile,
        status="pending"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Start scan in background
    background_tasks.add_task(
        orchestrator.start_scan,
        job.id,
        scan_data.target,
        scan_data.profile
    )
    
    return ScanResponse(
        id=job.id,
        target=scan_data.target,
        profile=job.profile,
        status=job.status,
        progress_percent=job.progress_percent,
        results_summary=job.results_summary,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at
    )

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """List scans for current user"""
    query = db.query(ScanningJob).filter(ScanningJob.user_id == current_user.id)
    
    if status:
        query = query.filter(ScanningJob.status == status)
    
    scans = query.order_by(ScanningJob.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        ScanResponse(
            id=scan.id,
            target=scan.target.target_value,
            profile=scan.profile,
            status=scan.status,
            progress_percent=scan.progress_percent,
            results_summary=scan.results_summary,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at
        )
        for scan in scans
    ]

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get scan details"""
    scan = db.query(ScanningJob).filter(
        ScanningJob.id == scan_id,
        ScanningJob.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse(
        id=scan.id,
        target=scan.target.target_value,
        profile=scan.profile,
        status=scan.status,
        progress_percent=scan.progress_percent,
        results_summary=scan.results_summary,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at
    )

@router.get("/{scan_id}/tasks", response_model=List[TaskResponse])
async def get_scan_tasks(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get tasks for a scan"""
    scan = db.query(ScanningJob).filter(
        ScanningJob.id == scan_id,
        ScanningJob.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    tasks = db.query(JobTask).filter(JobTask.job_id == scan_id).all()
    
    return [
        TaskResponse(
            id=task.id,
            tool_name=task.tool_name,
            task_type=task.task_type,
            status=task.status,
            command_line=task.command_line,
            exit_code=task.exit_code,
            resource_usage=task.resource_usage,
            started_at=task.started_at,
            completed_at=task.completed_at
        )
        for task in tasks
    ]

@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user)
):
    """Stop a running scan"""
    success = await orchestrator.stop_job(scan_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or not running")
    
    return {"message": "Scan stopped"}
