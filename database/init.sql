-- Main Database
CREATE DATABASE IF NOT EXISTS inseclabs_automaton;
USE inseclabs_automaton;

-- Users and Authentication
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    api_key VARCHAR(64) UNIQUE,
    api_key_expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    INDEX idx_role (role),
    INDEX idx_api_key (api_key)
);

CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token),
    INDEX idx_user_expires (user_id, expires_at)
);

-- Targets and Assets
CREATE TABLE targets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    target_type ENUM('domain', 'subdomain', 'url', 'ip', 'cidr', 'batch') NOT NULL,
    target_value VARCHAR(500) NOT NULL,
    description TEXT,
    tags JSON DEFAULT (JSON_ARRAY()),
    scope_type ENUM('allow', 'deny') DEFAULT 'allow',
    authorization_given BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_target_value (target_value(255)),
    INDEX idx_scope_type (scope_type),
    UNIQUE KEY unique_active_target (target_value, user_id, is_active)
);

CREATE TABLE domains (
    id INT PRIMARY KEY AUTO_INCREMENT,
    target_id INT NOT NULL,
    domain_name VARCHAR(255) NOT NULL,
    tld VARCHAR(50),
    registrar VARCHAR(255),
    creation_date DATE,
    expiration_date DATE,
    dns_records JSON,
    whois_data JSON,
    risk_score INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_domain_name (domain_name),
    INDEX idx_risk_score (risk_score),
    UNIQUE KEY unique_domain_target (domain_name, target_id)
);

CREATE TABLE subdomains (
    id INT PRIMARY KEY AUTO_INCREMENT,
    domain_id INT NOT NULL,
    subdomain_name VARCHAR(255) NOT NULL,
    ip_addresses JSON,
    dns_records JSON,
    is_wildcard BOOLEAN DEFAULT FALSE,
    is_cdn BOOLEAN DEFAULT FALSE,
    cdn_provider VARCHAR(100),
    discovery_sources JSON,
    confidence_score INT DEFAULT 50,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_subdomain_name (subdomain_name),
    INDEX idx_last_seen (last_seen_at),
    INDEX idx_confidence (confidence_score),
    UNIQUE KEY unique_subdomain_domain (subdomain_name, domain_id)
);

CREATE TABLE subdomain_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    subdomain_id INT NOT NULL,
    http_status INT,
    title VARCHAR(500),
    content_length INT,
    headers_hash VARCHAR(64),
    headers JSON,
    technologies JSON,
    screenshot_path VARCHAR(500),
    ssl_info JSON,
    waf_detected VARCHAR(100),
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE,
    INDEX idx_checked_at (checked_at),
    INDEX idx_status (http_status),
    INDEX idx_subdomain_checked (subdomain_id, checked_at)
);

-- Ports and Services
CREATE TABLE ports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    subdomain_id INT,
    ip_address VARCHAR(45) NOT NULL,
    port_number INT NOT NULL,
    protocol ENUM('tcp', 'udp', 'sctp') DEFAULT 'tcp',
    state ENUM('open', 'closed', 'filtered') DEFAULT 'open',
    scan_tool VARCHAR(50),
    banner TEXT,
    service_name VARCHAR(100),
    service_version VARCHAR(100),
    cpe JSON,
    first_discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE SET NULL,
    INDEX idx_ip_port (ip_address, port_number),
    INDEX idx_state (state),
    INDEX idx_service (service_name),
    UNIQUE KEY unique_port_entry (ip_address, port_number, protocol, subdomain_id)
);

CREATE TABLE service_details (
    id INT PRIMARY KEY AUTO_INCREMENT,
    port_id INT NOT NULL,
    ssl_cert JSON,
    http_title VARCHAR(500),
    http_headers JSON,
    http_technologies JSON,
    waf_info JSON,
    cdn_info JSON,
    vulnerability_hints JSON,
    raw_response TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE,
    INDEX idx_scanned_at (scanned_at)
);

-- URLs and Parameters
CREATE TABLE urls (
    id INT PRIMARY KEY AUTO_INCREMENT,
    subdomain_id INT NOT NULL,
    url TEXT NOT NULL,
    normalized_url VARCHAR(2000),
    path VARCHAR(1000),
    query_params JSON,
    http_method VARCHAR(10) DEFAULT 'GET',
    discovered_by VARCHAR(50),
    http_status INT,
    content_length INT,
    title VARCHAR(500),
    content_hash VARCHAR(64),
    is_interesting BOOLEAN DEFAULT FALSE,
    interesting_reason VARCHAR(200),
    last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE,
    INDEX idx_normalized_url (normalized_url(255)),
    INDEX idx_status (http_status),
    INDEX idx_interesting (is_interesting),
    INDEX idx_discovered_by (discovered_by),
    INDEX idx_first_seen (first_seen_at),
    UNIQUE KEY unique_normalized_url (normalized_url(255))
);

CREATE TABLE url_parameters (
    id INT PRIMARY KEY AUTO_INCREMENT,
    url_id INT NOT NULL,
    parameter_name VARCHAR(255) NOT NULL,
    parameter_type ENUM('query', 'body', 'header', 'cookie', 'json') DEFAULT 'query',
    parameter_value TEXT,
    is_interesting BOOLEAN DEFAULT FALSE,
    interesting_reason VARCHAR(200),
    fuzzing_status ENUM('pending', 'queued', 'running', 'completed', 'failed') DEFAULT 'pending',
    fuzzing_results JSON,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
    INDEX idx_parameter_name (parameter_name),
    INDEX idx_interesting_param (is_interesting),
    INDEX idx_fuzzing_status (fuzzing_status),
    UNIQUE KEY unique_url_parameter (url_id, parameter_name, parameter_type)
);

-- Historical Data
CREATE TABLE historical_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    url_id INT NOT NULL,
    snapshot_date DATE NOT NULL,
    http_status INT,
    content_hash VARCHAR(64),
    content_length INT,
    title VARCHAR(500),
    headers JSON,
    wayback_id VARCHAR(100),
    raw_html_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
    INDEX idx_snapshot_date (snapshot_date),
    UNIQUE KEY unique_url_snapshot (url_id, snapshot_date)
);

CREATE TABLE historical_comparison (
    id INT PRIMARY KEY AUTO_INCREMENT,
    url_id INT NOT NULL,
    old_snapshot_id INT NOT NULL,
    new_snapshot_id INT NOT NULL,
    changes_detected JSON,
    diff_score INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
    FOREIGN KEY (old_snapshot_id) REFERENCES historical_data(id) ON DELETE CASCADE,
    FOREIGN KEY (new_snapshot_id) REFERENCES historical_data(id) ON DELETE CASCADE,
    INDEX idx_diff_score (diff_score)
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id INT PRIMARY KEY AUTO_INCREMENT,
    target_id INT NOT NULL,
    subdomain_id INT,
    url_id INT,
    port_id INT,
    vulnerability_type VARCHAR(100) NOT NULL,
    template_id VARCHAR(100),
    cve_id VARCHAR(50),
    severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
    confidence ENUM('certain', 'firm', 'tentative') DEFAULT 'tentative',
    status ENUM('new', 'verified', 'false_positive', 'remediated', 'accepted_risk') DEFAULT 'new',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    remediation TEXT,
    evidence_path VARCHAR(500),
    scanner_tool VARCHAR(50) NOT NULL,
    dedupe_hash VARCHAR(64) NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP NULL,
    verified_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE SET NULL,
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE SET NULL,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL,
    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_dedupe_hash (dedupe_hash),
    INDEX idx_discovered_at (discovered_at),
    INDEX idx_template_id (template_id),
    UNIQUE KEY unique_vulnerability_hash (dedupe_hash)
);

CREATE TABLE vulnerability_details (
    id INT PRIMARY KEY AUTO_INCREMENT,
    vulnerability_id INT NOT NULL,
    request_data TEXT,
    response_data TEXT,
    payload TEXT,
    matcher_name VARCHAR(100),
    extracted_results JSON,
    references JSON,
    tags JSON,
    raw_output_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    INDEX idx_vulnerability_id (vulnerability_id)
);

-- Scanning Jobs and Tasks
CREATE TABLE scanning_jobs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    target_id INT NOT NULL,
    profile ENUM('quick', 'standard', 'deep', 'passive') DEFAULT 'standard',
    status ENUM('pending', 'queued', 'running', 'completed', 'failed', 'stopped') DEFAULT 'pending',
    progress_percent INT DEFAULT 0,
    estimated_duration INT,
    results_summary JSON,
    error_message TEXT,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_status (status),
    INDEX idx_user_created (user_id, created_at),
    INDEX idx_target_profile (target_id, profile)
);

CREATE TABLE job_tasks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    job_id INT NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    task_type ENUM('discovery', 'scan', 'analysis', 'system') DEFAULT 'scan',
    command_line TEXT,
    status ENUM('pending', 'queued', 'running', 'success', 'failed', 'skipped') DEFAULT 'pending',
    exit_code INT,
    stdout TEXT,
    stderr TEXT,
    output_file_path VARCHAR(500),
    tables_written JSON,
    resource_usage JSON,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES scanning_jobs(id) ON DELETE CASCADE,
    INDEX idx_job_status (job_id, status),
    INDEX idx_tool_name (tool_name),
    INDEX idx_task_type (task_type)
);

-- Tool Management
CREATE TABLE tool_configurations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    tool_name VARCHAR(100) UNIQUE NOT NULL,
    tool_category VARCHAR(50),
    version VARCHAR(50),
    install_method VARCHAR(50),
    install_path VARCHAR(500),
    is_installed BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    health_status ENUM('healthy', 'unhealthy', 'unknown') DEFAULT 'unknown',
    last_health_check TIMESTAMP NULL,
    default_args JSON,
    risk_level ENUM('passive', 'active', 'intrusive') DEFAULT 'passive',
    output_format VARCHAR(20),
    parser_id VARCHAR(50),
    tables_written JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_health_status (health_status),
    INDEX idx_is_enabled (is_enabled),
    INDEX idx_tool_category (tool_category)
);

-- Notifications
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    notification_type VARCHAR(50) NOT NULL,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    severity ENUM('info', 'warning', 'error', 'critical') DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    related_entity_type VARCHAR(50),
    related_entity_id INT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_unread (user_id, is_read),
    INDEX idx_created_at (created_at)
);

CREATE TABLE email_notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    notification_id INT NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    subject VARCHAR(200) NOT NULL,
    body_html TEXT,
    body_text TEXT,
    sent_at TIMESTAMP NULL,
    delivery_status ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
    INDEX idx_delivery_status (delivery_status),
    INDEX idx_sent_at (sent_at)
);

-- Reports
CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(200) NOT NULL,
    format ENUM('pdf', 'html', 'json', 'markdown') DEFAULT 'pdf',
    filters JSON,
    status ENUM('generating', 'ready', 'failed') DEFAULT 'generating',
    file_path VARCHAR(500),
    file_size INT,
    generated_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_report_type (report_type),
    INDEX idx_status (status),
    INDEX idx_generated_at (generated_at)
);

-- System Monitoring
CREATE TABLE dashboard_widgets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    widget_type VARCHAR(50) NOT NULL,
    title VARCHAR(100) NOT NULL,
    config JSON,
    position INT,
    is_visible BOOLEAN DEFAULT TRUE,
    refresh_interval INT DEFAULT 300,
    user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_widget_type (widget_type),
    INDEX idx_user_position (user_id, position)
);

CREATE TABLE system_stats (
    id INT PRIMARY KEY AUTO_INCREMENT,
    metric_type VARCHAR(50) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    unit VARCHAR(20),
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_metric_type_name (metric_type, metric_name),
    INDEX idx_collected_at (collected_at)
);

-- Audit Logs
CREATE TABLE audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_action (action),
    INDEX idx_performed_at (performed_at),
    INDEX idx_user_action (user_id, action)
);

-- Trigger for subdomain last_seen update
DELIMITER $$
CREATE TRIGGER update_subdomain_last_seen
AFTER INSERT ON subdomain_history
FOR EACH ROW
BEGIN
    UPDATE subdomains 
    SET last_seen_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.subdomain_id;
END$$
DELIMITER ;

-- Trigger for vulnerability status change audit
DELIMITER $$
CREATE TRIGGER audit_vulnerability_changes
AFTER UPDATE ON vulnerabilities
FOR EACH ROW
BEGIN
    IF OLD.status != NEW.status OR OLD.severity != NEW.severity THEN
        INSERT INTO audit_logs (
            user_id, 
            action, 
            entity_type, 
            entity_id, 
            old_values, 
            new_values
        ) VALUES (
            NEW.verified_by,
            'vulnerability_status_change',
            'vulnerability',
            NEW.id,
            JSON_OBJECT('status', OLD.status, 'severity', OLD.severity),
            JSON_OBJECT('status', NEW.status, 'severity', NEW.severity)
        );
    END IF;
END$$
DELIMITER ;
