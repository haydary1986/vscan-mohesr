import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

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

// Dashboard
export const getDashboardStats = () => api.get('/dashboard')

export default api
