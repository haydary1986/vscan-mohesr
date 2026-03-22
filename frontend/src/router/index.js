import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Targets from '../views/Targets.vue'
import Scans from '../views/Scans.vue'
import ScanDetail from '../views/ScanDetail.vue'
import ResultDetail from '../views/ResultDetail.vue'

const routes = [
  { path: '/', name: 'Dashboard', component: Dashboard },
  { path: '/targets', name: 'Targets', component: Targets },
  { path: '/scans', name: 'Scans', component: Scans },
  { path: '/scans/:id', name: 'ScanDetail', component: ScanDetail },
  { path: '/results/:id', name: 'ResultDetail', component: ResultDetail },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
