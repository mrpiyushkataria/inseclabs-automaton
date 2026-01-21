<template>
  <div class="dashboard">
    <!-- Header -->
    <div class="dashboard-header">
      <h1>Security Dashboard</h1>
      <div class="quick-actions">
        <button @click="startNewScan" class="btn btn-primary">
          <i class="fas fa-plus"></i> New Scan
        </button>
        <button @click="refreshDashboard" class="btn btn-secondary">
          <i class="fas fa-sync"></i> Refresh
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon bg-danger">
          <i class="fas fa-bug"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.criticalVulns || 0 }}</h3>
          <p>Critical Vulnerabilities</p>
        </div>
      </div>
      
      <div class="stat-card">
        <div class="stat-icon bg-warning">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.highVulns || 0 }}</h3>
          <p>High Severity</p>
        </div>
      </div>
      
      <div class="stat-card">
        <div class="stat-icon bg-info">
          <i class="fas fa-globe"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.activeTargets || 0 }}</h3>
          <p>Active Targets</p>
        </div>
      </div>
      
      <div class="stat-card">
        <div class="stat-icon bg-success">
          <i class="fas fa-server"></i>
        </div>
        <div class="stat-content">
          <h3>{{ stats.runningScans || 0 }}</h3>
          <p>Running Scans</p>
        </div>
      </div>
    </div>

    <!-- Main Content Grid -->
    <div class="dashboard-grid">
      <!-- Recent Scans -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3><i class="fas fa-history"></i> Recent Scans</h3>
          <router-link to="/scans" class="btn-link">View All</router-link>
        </div>
        <div class="card-body">
          <table class="table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Profile</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="scan in recentScans" :key="scan.id">
                <td>{{ scan.target }}</td>
                <td><span class="badge" :class="`badge-${scan.profile}`">{{ scan.profile }}</span></td>
                <td>
                  <span class="status-badge" :class="`status-${scan.status}`">
                    {{ scan.status }}
                  </span>
                </td>
                <td>
                  <div class="progress">
                    <div class="progress-bar" :style="{ width: `${scan.progress_percent}%` }"></div>
                  </div>
                </td>
                <td>{{ formatDate(scan.created_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- System Health -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3><i class="fas fa-heartbeat"></i> System Health</h3>
        </div>
        <div class="card-body">
          <div class="health-metrics">
            <div class="metric">
              <div class="metric-label">CPU Usage</div>
              <div class="metric-value">{{ systemHealth.cpu_percent || 0 }}%</div>
              <div class="progress">
                <div class="progress-bar" :class="getHealthClass(systemHealth.cpu_percent, 'cpu')"
                     :style="{ width: `${systemHealth.cpu_percent || 0}%` }"></div>
              </div>
            </div>
            
            <div class="metric">
              <div class="metric-label">Memory Usage</div>
              <div class="metric-value">{{ systemHealth.memory_percent || 0 }}%</div>
              <div class="progress">
                <div class="progress-bar" :class="getHealthClass(systemHealth.memory_percent, 'memory')"
                     :style="{ width: `${systemHealth.memory_percent || 0}%` }"></div>
              </div>
            </div>
            
            <div class="metric">
              <div class="metric-label">Disk Usage</div>
              <div class="metric-value">{{ systemHealth.disk_percent || 0 }}%</div>
              <div class="progress">
                <div class="progress-bar" :class="getHealthClass(systemHealth.disk_percent, 'disk')"
                     :style="{ width: `${systemHealth.disk_percent || 0}%` }"></div>
              </div>
            </div>
          </div>
          
          <div class="tool-health">
            <h4>Tool Status</h4>
            <div class="tool-list">
              <div v-for="tool in healthyTools" :key="tool.name" class="tool-item">
                <span class="tool-name">{{ tool.name }}</span>
                <span class="tool-status" :class="`status-${tool.health_status}`">
                  <i class="fas fa-circle"></i> {{ tool.health_status }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Vulnerabilities -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3><i class="fas fa-shield-alt"></i> Recent Vulnerabilities</h3>
          <router-link to="/vulnerabilities" class="btn-link">View All</router-link>
        </div>
        <div class="card-body">
          <div class="vuln-list">
            <div v-for="vuln in recentVulns" :key="vuln.id" class="vuln-item">
              <div class="vuln-severity" :class="`severity-${vuln.severity}`">
                {{ vuln.severity.toUpperCase() }}
              </div>
              <div class="vuln-details">
                <div class="vuln-title">{{ vuln.title }}</div>
                <div class="vuln-meta">
                  <span class="vuln-target">{{ vuln.target }}</span>
                  <span class="vuln-time">{{ formatTimeAgo(vuln.discovered_at) }}</span>
                </div>
              </div>
              <div class="vuln-actions">
                <button @click="viewVulnerability(vuln.id)" class="btn btn-sm btn-outline">
                  View
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Start -->
      <div class="dashboard-card">
        <div class="card-header">
          <h3><i class="fas fa-rocket"></i> Quick Start</h3>
        </div>
        <div class="card-body">
          <form @submit.prevent="quickScan" class="quick-scan-form">
            <div class="form-group">
              <label for="target">Target</label>
              <input v-model="quickScanTarget" type="text" class="form-control" 
                     placeholder="example.com or https://example.com" required>
            </div>
            
            <div class="form-group">
              <label for="profile">Profile</label>
              <select v-model="quickScanProfile" class="form-control">
                <option value="quick">Quick Scan</option>
                <option value="standard">Standard Scan</option>
                <option value="deep">Deep Scan</option>
                <option value="passive">Passive Recon</option>
              </select>
            </div>
            
            <div class="form-group">
              <label class="checkbox">
                <input v-model="quickScanAuth" type="checkbox">
                <span>I have authorization to scan this target</span>
              </label>
            </div>
            
            <button type="submit" class="btn btn-primary btn-block" :disabled="!quickScanAuth">
              Start Scan
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import api from '@/services/api'
import { formatDistanceToNow, format } from 'date-fns'

export default {
  name: 'Dashboard',
  setup() {
    const router = useRouter()
    
    // State
    const stats = ref({})
    const recentScans = ref([])
    const recentVulns = ref([])
    const systemHealth = ref({})
    const healthyTools = ref([])
    
    const quickScanTarget = ref('')
    const quickScanProfile = ref('standard')
    const quickScanAuth = ref(false)
    
    // Computed
    const healthyToolCount = computed(() => {
      return healthyTools.value.filter(t => t.health_status === 'healthy').length
    })
    
    // Methods
    const loadDashboard = async () => {
      try {
        const [statsRes, scansRes, vulnsRes, healthRes, toolsRes] = await Promise.all([
          api.get('/dashboard/stats'),
          api.get('/scans?limit=5'),
          api.get('/vulnerabilities?limit=5'),
          api.get('/system/health'),
          api.get('/tools')
        ])
        
        stats.value = statsRes.data
        recentScans.value = scansRes.data
        recentVulns.value = vulnsRes.data
        systemHealth.value = healthRes.data
        healthyTools.value = toolsRes.data.filter(t => t.is_installed).slice(0, 5)
      } catch (error) {
        console.error('Failed to load dashboard:', error)
      }
    }
    
    const refreshDashboard = () => {
      loadDashboard()
    }
    
    const startNewScan = () => {
      router.push('/scans/new')
    }
    
    const quickScan = async () => {
      if (!quickScanAuth.value) {
        alert('Please confirm authorization')
        return
      }
      
      try {
        const response = await api.post('/scans', {
          target: quickScanTarget.value,
          profile: quickScanProfile.value
        })
        
        router.push(`/scans/${response.data.id}`)
      } catch (error) {
        alert('Failed to start scan: ' + error.message)
      }
    }
    
    const viewVulnerability = (id) => {
      router.push(`/vulnerabilities/${id}`)
    }
    
    const formatDate = (date) => {
      return format(new Date(date), 'MMM d, HH:mm')
    }
    
    const formatTimeAgo = (date) => {
      return formatDistanceToNow(new Date(date), { addSuffix: true })
    }
    
    const getHealthClass = (value, type) => {
      if (value > 90) return 'bg-danger'
      if (value > 70) return 'bg-warning'
      return 'bg-success'
    }
    
    // Lifecycle
    onMounted(() => {
      loadDashboard()
      // Set up auto-refresh every 30 seconds
      setInterval(loadDashboard, 30000)
    })
    
    return {
      stats,
      recentScans,
      recentVulns,
      systemHealth,
      healthyTools,
      healthyToolCount,
      quickScanTarget,
      quickScanProfile,
      quickScanAuth,
      refreshDashboard,
      startNewScan,
      quickScan,
      viewVulnerability,
      formatDate,
      formatTimeAgo,
      getHealthClass
    }
  }
}
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.dashboard-header h1 {
  margin: 0;
  color: #333;
}

.quick-actions {
  display: flex;
  gap: 10px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  display: flex;
  align-items: center;
  gap: 20px;
}

.stat-icon {
  width: 60px;
  height: 60px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  color: white;
}

.stat-content h3 {
  margin: 0;
  font-size: 28px;
  font-weight: bold;
}

.stat-content p {
  margin: 5px 0 0;
  color: #666;
  font-size: 14px;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
  gap: 20px;
}

.dashboard-card {
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  overflow: hidden;
}

.card-header {
  padding: 20px;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h3 {
  margin: 0;
  font-size: 18px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.card-body {
  padding: 20px;
}

.table {
  width: 100%;
  border-collapse: collapse;
}

.table th, .table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.table th {
  font-weight: 600;
  color: #666;
}

.badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
}

.badge-quick { background: #e3f2fd; color: #1976d2; }
.badge-standard { background: #e8f5e9; color: #388e3c; }
.badge-deep { background: #fff3e0; color: #f57c00; }
.badge-passive { background: #f3e5f5; color: #7b1fa2; }

.status-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
}

.status-running { background: #e3f2fd; color: #1976d2; }
.status-completed { background: #e8f5e9; color: #388e3c; }
.status-failed { background: #ffebee; color: #d32f2f; }
.status-pending { background: #fff3e0; color: #f57c00; }

.progress {
  height: 6px;
  background: #eee;
  border-radius: 3px;
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  transition: width 0.3s;
}

.health-metrics {
  margin-bottom: 20px;
}

.metric {
  margin-bottom: 15px;
}

.metric-label {
  font-size: 14px;
  color: #666;
  margin-bottom: 5px;
}

.metric-value {
  font-weight: bold;
  margin-bottom: 5px;
}

.tool-health h4 {
  margin: 0 0 15px;
  font-size: 16px;
}

.tool-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tool-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  background: #f8f9fa;
  border-radius: 5px;
}

.tool-name {
  font-weight: 500;
}

.tool-status {
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 5px;
}

.status-healthy { color: #4caf50; }
.status-unhealthy { color: #f44336; }
.status-unknown { color: #ff9800; }

.vuln-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.vuln-item {
  display: flex;
  align-items: center;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 5px;
  gap: 15px;
}

.vuln-severity {
  padding: 6px 12px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
  text-transform: uppercase;
  min-width: 80px;
  text-align: center;
}

.severity-critical { background: #ffebee; color: #d32f2f; }
.severity-high { background: #fff3e0; color: #f57c00; }
.severity-medium { background: #fff8e1; color: #ffa000; }
.severity-low { background: #f1f8e9; color: #689f38; }

.vuln-details {
  flex: 1;
}

.vuln-title {
  font-weight: 500;
  margin-bottom: 5px;
}

.vuln-meta {
  display: flex;
  gap: 15px;
  font-size: 12px;
  color: #666;
}

.quick-scan-form {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.form-group {
  margin: 0;
}

.checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox input {
  margin: 0;
}

.btn-block {
  width: 100%;
}
</style>
