# inseclabs-automaton
11. Complete Installation Instructions
INSTALLATION GUIDE
Prerequisites
Ubuntu 20.04/22.04 LTS

Docker and Docker Compose

Minimum 8GB RAM, 4 CPU cores, 100GB disk

Root/sudo access

Step 1: Clone Repository
bash
git clone https://github.com/yourusername/inseclabs-automaton.git
cd inseclabs-automaton
Step 2: Configure Environment
bash
cp .env.example .env
# Edit .env with your configuration
nano .env
Step 3: Start with Docker
bash
cd docker
docker-compose up -d
Step 4: Initialize Database
bash
# Access database container
docker exec -it inseclabs-db mysql -u root -p

# Execute initialization
USE inseclabs_automaton;
SOURCE /docker-entrypoint-initdb.d/init.sql;

# Create admin user (in backend container)
docker exec -it inseclabs-backend python scripts/create_admin.py
Step 5: Install Tools
bash
# Run tool installer
docker exec -it inseclabs-tool-installer /bin/bash
./scripts/install_tools.sh

# Or install manually
cd scripts
chmod +x install_tools.sh
./install_tools.sh
Step 6: Start Services
bash
# Start all services
docker-compose up -d backend frontend worker

# Check status
docker-compose ps

# View logs
docker-compose logs -f backend
Step 7: Access Dashboard
Open browser: http://localhost

Login: admin / changeme123

Change password on first login

Step 8: First Scan
Navigate to "Targets" page

Click "Add Target"

Enter: example.com

Select "Standard" profile

Check authorization checkbox

Click "Start Scan"

Step 9: Monitor Progress
Go to "Scans" page

Click on running scan

View "Progress" tab for real-time updates

Check "Assets" pages as results populate

12. Security Considerations
Important Security Notes:
NEVER run this on systems without proper authorization

Use only for authorized penetration testing

Set up proper firewalls and network isolation

Regularly update tools and dependencies

Monitor resource usage to prevent abuse

Implement rate limiting

Keep sensitive data encrypted

Regular backups of database

Access control and audit logging

Emergency stop procedures

Default Credentials:
Database: root / root_password (change in production!)

Admin: admin / changeme123 (change immediately!)

API: generate unique keys per user

Production Deployment Checklist:
Change all default passwords

Configure SSL/TLS

Set up proper firewall rules

Enable audit logging

Configure backups

Set up monitoring alerts

Implement rate limiting

Regular security updates

User access reviews

Incident response plan

Key Features Implemented:
Complete Database Schema - All tables with proper relationships

Workflow Planner - Automatic pipeline building based on input type

Tool Manager - Installation, version control, health checks

Parsers - Normalization and deduplication for all major tools

Job Orchestrator - Parallel execution with dependency management

REST API - Full CRUD for all entities

Dashboard UI - Real-time monitoring and visualization

3D Graph - Interactive relationship visualization

Docker Support - Production-ready containerization

Security Controls - RBAC, scope checking, authorization

This is a production-ready security scanning platform that automatically orchestrates tools, parses outputs, stores results in a normalized database, and provides a comprehensive dashboard for analysis. The system is modular, scalable, and designed for real-world security operations.

Remember: Use responsibly and only on authorized targets. Always get proper authorization before scanning.
