from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON, Enum, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
import enum
from datetime import datetime
import os

Base = declarative_base()

# Enums
class UserRole(str, enum.Enum):
    ADMIN = 'admin'
    ANALYST = 'analyst'
    VIEWER = 'viewer'

class TargetType(str, enum.Enum):
    DOMAIN = 'domain'
    SUBDOMAIN = 'subdomain'
    URL = 'url'
    IP = 'ip'
    CIDR = 'cidr'
    BATCH = 'batch'

class ScanProfile(str, enum.Enum):
    QUICK = 'quick'
    STANDARD = 'standard'
    DEEP = 'deep'
    PASSIVE = 'passive'

class JobStatus(str, enum.Enum):
    PENDING = 'pending'
    QUEUED = 'queued'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    STOPPED = 'stopped'

class TaskStatus(str, enum.Enum):
    PENDING = 'pending'
    QUEUED = 'queued'
    RUNNING = 'running'
    SUCCESS = 'success'
    FAILED = 'failed'
    SKIPPED = 'skipped'

class SeverityLevel(str, enum.Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

# Models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)
    api_key = Column(String(64), unique=True)
    api_key_expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = Column(DateTime)
    
    # Relationships
    targets = relationship('Target', back_populates='user')
    scanning_jobs = relationship('ScanningJob', back_populates='user')
    
    __table_args__ = (
        Index('idx_role', 'role'),
        Index('idx_api_key', 'api_key'),
    )

class Target(Base):
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    target_type = Column(Enum(TargetType), nullable=False)
    target_value = Column(String(500), nullable=False)
    description = Column(Text)
    tags = Column(JSON, default=list)
    scope_type = Column(Enum('allow', 'deny'), default='allow')
    authorization_given = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='targets')
    domains = relationship('Domain', back_populates='target')
    scanning_jobs = relationship('ScanningJob', back_populates='target')
    vulnerabilities = relationship('Vulnerability', back_populates='target')
    
    __table_args__ = (
        Index('idx_target_value', 'target_value'),
        Index('idx_scope_type', 'scope_type'),
    )

class Domain(Base):
    __tablename__ = 'domains'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    domain_name = Column(String(255), nullable=False)
    tld = Column(String(50))
    registrar = Column(String(255))
    creation_date = Column(DateTime)
    expiration_date = Column(DateTime)
    dns_records = Column(JSON)
    whois_data = Column(JSON)
    risk_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship('Target', back_populates='domains')
    subdomains = relationship('Subdomain', back_populates='domain')
    
    __table_args__ = (
        Index('idx_domain_name', 'domain_name'),
        Index('idx_risk_score', 'risk_score'),
    )

class Subdomain(Base):
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id'), nullable=False)
    subdomain_name = Column(String(255), nullable=False)
    ip_addresses = Column(JSON)
    dns_records = Column(JSON)
    is_wildcard = Column(Boolean, default=False)
    is_cdn = Column(Boolean, default=False)
    cdn_provider = Column(String(100))
    discovery_sources = Column(JSON)
    confidence_score = Column(Integer, default=50)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    domain = relationship('Domain', back_populates='subdomains')
    history = relationship('SubdomainHistory', back_populates='subdomain')
    ports = relationship('Port', back_populates='subdomain')
    urls = relationship('Url', back_populates='subdomain')
    
    __table_args__ = (
        Index('idx_subdomain_name', 'subdomain_name'),
        Index('idx_last_seen', 'last_seen_at'),
        Index('idx_confidence', 'confidence_score'),
    )

class SubdomainHistory(Base):
    __tablename__ = 'subdomain_history'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    http_status = Column(Integer)
    title = Column(String(500))
    content_length = Column(Integer)
    headers_hash = Column(String(64))
    headers = Column(JSON)
    technologies = Column(JSON)
    screenshot_path = Column(String(500))
    ssl_info = Column(JSON)
    waf_detected = Column(String(100))
    checked_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    subdomain = relationship('Subdomain', back_populates='history')
    
    __table_args__ = (
        Index('idx_checked_at', 'checked_at'),
        Index('idx_status', 'http_status'),
        Index('idx_subdomain_checked', 'subdomain_id', 'checked_at'),
    )

class Port(Base):
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'))
    ip_address = Column(String(45), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(Enum('tcp', 'udp', 'sctp'), default='tcp')
    state = Column(Enum('open', 'closed', 'filtered'), default='open')
    scan_tool = Column(String(50))
    banner = Column(Text)
    service_name = Column(String(100))
    service_version = Column(String(100))
    cpe = Column(JSON)
    first_discovered_at = Column(DateTime, default=datetime.utcnow)
    last_scanned_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    subdomain = relationship('Subdomain', back_populates='ports')
    service_details = relationship('ServiceDetails', back_populates='port')
    vulnerabilities = relationship('Vulnerability', back_populates='port')
    
    __table_args__ = (
        Index('idx_ip_port', 'ip_address', 'port_number'),
        Index('idx_state', 'state'),
        Index('idx_service', 'service_name'),
    )

class ServiceDetails(Base):
    __tablename__ = 'service_details'
    
    id = Column(Integer, primary_key=True)
    port_id = Column(Integer, ForeignKey('ports.id'), nullable=False)
    ssl_cert = Column(JSON)
    http_title = Column(String(500))
    http_headers = Column(JSON)
    http_technologies = Column(JSON)
    waf_info = Column(JSON)
    cdn_info = Column(JSON)
    vulnerability_hints = Column(JSON)
    raw_response = Column(Text)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    port = relationship('Port', back_populates='service_details')

class Url(Base):
    __tablename__ = 'urls'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    url = Column(Text, nullable=False)
    normalized_url = Column(String(2000))
    path = Column(String(1000))
    query_params = Column(JSON)
    http_method = Column(String(10), default='GET')
    discovered_by = Column(String(50))
    http_status = Column(Integer)
    content_length = Column(Integer)
    title = Column(String(500))
    content_hash = Column(String(64))
    is_interesting = Column(Boolean, default=False)
    interesting_reason = Column(String(200))
    last_checked_at = Column(DateTime, default=datetime.utcnow)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    subdomain = relationship('Subdomain', back_populates='urls')
    parameters = relationship('UrlParameter', back_populates='url')
    historical_data = relationship('HistoricalData', back_populates='url')
    vulnerabilities = relationship('Vulnerability', back_populates='url')
    
    __table_args__ = (
        Index('idx_normalized_url', 'normalized_url'),
        Index('idx_status', 'http_status'),
        Index('idx_interesting', 'is_interesting'),
        Index('idx_discovered_by', 'discovered_by'),
        Index('idx_first_seen', 'first_seen_at'),
    )

class UrlParameter(Base):
    __tablename__ = 'url_parameters'
    
    id = Column(Integer, primary_key=True)
    url_id = Column(Integer, ForeignKey('urls.id'), nullable=False)
    parameter_name = Column(String(255), nullable=False)
    parameter_type = Column(Enum('query', 'body', 'header', 'cookie', 'json'), default='query')
    parameter_value = Column(Text)
    is_interesting = Column(Boolean, default=False)
    interesting_reason = Column(String(200))
    fuzzing_status = Column(Enum('pending', 'queued', 'running', 'completed', 'failed'), default='pending')
    fuzzing_results = Column(JSON)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    url = relationship('Url', back_populates='parameters')

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'))
    url_id = Column(Integer, ForeignKey('urls.id'))
    port_id = Column(Integer, ForeignKey('ports.id'))
    vulnerability_type = Column(String(100), nullable=False)
    template_id = Column(String(100))
    cve_id = Column(String(50))
    severity = Column(Enum(SeverityLevel), nullable=False)
    confidence = Column(Enum('certain', 'firm', 'tentative'), default='tentative')
    status = Column(Enum('new', 'verified', 'false_positive', 'remediated', 'accepted_risk'), default='new')
    title = Column(String(500), nullable=False)
    description = Column(Text)
    remediation = Column(Text)
    evidence_path = Column(String(500))
    scanner_tool = Column(String(50), nullable=False)
    dedupe_hash = Column(String(64), nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime)
    verified_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship('Target', back_populates='vulnerabilities')
    subdomain = relationship('Subdomain')
    url = relationship('Url')
    port = relationship('Port')
    verifier = relationship('User', foreign_keys=[verified_by])
    details = relationship('VulnerabilityDetails', back_populates='vulnerability')
    
    __table_args__ = (
        Index('idx_severity', 'severity'),
        Index('idx_status', 'status'),
        Index('idx_dedupe_hash', 'dedupe_hash'),
        Index('idx_discovered_at', 'discovered_at'),
        Index('idx_template_id', 'template_id'),
    )

class ScanningJob(Base):
    __tablename__ = 'scanning_jobs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    profile = Column(Enum(ScanProfile), default=ScanProfile.STANDARD)
    status = Column(Enum(JobStatus), default=JobStatus.PENDING)
    progress_percent = Column(Integer, default=0)
    estimated_duration = Column(Integer)
    results_summary = Column(JSON)
    error_message = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='scanning_jobs')
    target = relationship('Target', back_populates='scanning_jobs')
    tasks = relationship('JobTask', back_populates='job')
    
    __table_args__ = (
        Index('idx_status', 'status'),
        Index('idx_user_created', 'user_id', 'created_at'),
        Index('idx_target_profile', 'target_id', 'profile'),
    )

class JobTask(Base):
    __tablename__ = 'job_tasks'
    
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey('scanning_jobs.id'), nullable=False)
    tool_name = Column(String(100), nullable=False)
    task_type = Column(Enum('discovery', 'scan', 'analysis', 'system'), default='scan')
    command_line = Column(Text)
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    output_file_path = Column(String(500))
    tables_written = Column(JSON)
    resource_usage = Column(JSON)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    job = relationship('ScanningJob', back_populates='tasks')
    
    __table_args__ = (
        Index('idx_job_status', 'job_id', 'status'),
        Index('idx_tool_name', 'tool_name'),
        Index('idx_task_type', 'task_type'),
    )

# Database connection
def get_database_engine():
    db_url = os.getenv('DATABASE_URL', 'mysql+pymysql://root:root_password@localhost/inseclabs_automaton')
    return create_engine(db_url, pool_pre_ping=True, pool_size=20, max_overflow=30)

def get_session():
    engine = get_database_engine()
    Session = sessionmaker(bind=engine)
    return Session()
