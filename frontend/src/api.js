import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Add auth token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !['/', '/login', '/register', '/methodology', '/methodology-ar'].includes(window.location.pathname)) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/'
    }
    return Promise.reject(error)
  }
)

// Auth
export const login = (data) => api.post('/auth/login', data)
export const register = (data) => api.post('/auth/register', data)
export const getProfile = () => api.get('/auth/profile')
export const getMyOrganization = () => api.get('/auth/organization')
export const changePassword = (data) => api.put('/auth/password', data)

// Targets
export const getTargets = () => api.get('/targets')
export const createTarget = (data) => api.post('/targets', data)
export const createBulkTargets = (targets) => api.post('/targets/bulk', { targets })
export const updateTarget = (id, data) => api.put(`/targets/${id}`, data)
export const deleteTarget = (id) => api.delete(`/targets/${id}`)

// Scans
export const getScanJobs = () => api.get('/scans')
export const getScanJob = (id) => api.get(`/scans/${id}`)
export const startScan = (data) => api.post('/scans/start', data)
export const deleteScanJob = (id) => api.delete(`/scans/${id}`)

// Results
export const getScanResult = (id) => api.get(`/results/${id}`)
export const downloadReport = (id) => api.get(`/results/${id}/pdf`, { responseType: 'blob' })
export const getScoreHistory = (id) => api.get(`/targets/${id}/history`)

// Dashboard & Leaderboard
export const getDashboardStats = () => api.get('/dashboard')
export const getLeaderboard = () => api.get('/leaderboard')

// Comparison & Compliance
export const compareScanResults = (oldId, newId) => api.get(`/compare?old=${oldId}&new=${newId}`)
export const getComplianceReport = (id) => api.get(`/results/${id}/compliance`)

// Public: Scan Criteria / Methodology / Plans
export const getScanCriteria = () => api.get('/criteria')
export const getPlans = () => api.get('/plans')

// AI Analysis
export const analyzeResult = (id) => api.post(`/ai/analyze/${id}`)
export const getAIAnalysis = (id) => api.get(`/ai/analysis/${id}`)

// AI Chat
export const chatWithAI = (data) => api.post('/ai/chat', data)

// Admin: Users
export const getUsers = () => api.get('/users')
export const createUser = (data) => api.post('/users', data)
export const updateUser = (id, data) => api.put(`/users/${id}`, data)
export const deleteUser = (id) => api.delete(`/users/${id}`)

// Admin: Settings
export const getSettings = () => api.get('/settings')
export const updateSettings = (data) => api.put('/settings', data)

// Upgrade Requests
export const requestUpgrade = (data) => api.post('/upgrade/request', data)
export const getMyUpgradeRequests = () => api.get('/upgrade/requests')
export const getAllUpgradeRequests = () => api.get('/upgrade/all')
export const approveUpgrade = (id, notes) => api.put(`/upgrade/${id}/approve`, { admin_notes: notes })
export const rejectUpgrade = (id, notes) => api.put(`/upgrade/${id}/reject`, { admin_notes: notes })

// Scheduled Scans
export const getSchedules = () => api.get('/schedules')
export const createSchedule = (data) => api.post('/schedules', data)
export const updateSchedule = (id, data) => api.put(`/schedules/${id}`, data)
export const deleteSchedule = (id) => api.delete(`/schedules/${id}`)
export const toggleSchedule = (id) => api.put(`/schedules/${id}/toggle`)

// Domain Verification
export const initiateVerification = (targetId) => api.post(`/targets/${targetId}/verify`)
export const getVerificationStatus = (targetId) => api.get(`/targets/${targetId}/verify`)
export const checkVerification = (targetId) => api.put(`/targets/${targetId}/verify`)

// API Keys
export const generateAPIKey = (data) => api.post('/api-keys', data)
export const listAPIKeys = () => api.get('/api-keys')
export const revokeAPIKey = (id) => api.delete(`/api-keys/${id}`)

// Webhooks
export const getWebhooks = () => api.get('/webhooks')
export const createWebhook = (data) => api.post('/webhooks', data)
export const updateWebhook = (id, data) => api.put(`/webhooks/${id}`, data)
export const deleteWebhook = (id) => api.delete(`/webhooks/${id}`)
export const testWebhook = (id) => api.post(`/webhooks/${id}/test`)

// Remediation Guides
export const getRemediationGuide = (checkName, serverType) => api.get(`/remediation?check=${encodeURIComponent(checkName)}&server=${serverType || 'all'}`)

// Tags
export const getTags = () => api.get('/tags')
export const createTag = (data) => api.post('/tags', data)
export const deleteTag = (id) => api.delete(`/tags/${id}`)
export const tagTarget = (targetId, tagId) => api.post('/tags/assign', { target_id: targetId, tag_id: tagId })
export const untagTarget = (targetId, tagId) => api.delete(`/tags/assign/${targetId}/${tagId}`)
export const getTargetsByTag = (tagId) => api.get(`/tags/${tagId}/targets`)
export const getTargetTags = (targetId) => api.get(`/targets/${targetId}/tags`)

export default api
