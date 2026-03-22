<script setup>
import { ref, onMounted } from 'vue'
import { getProfile, getMyOrganization, changePassword } from '../api'
import api from '../api'

const user = ref(null)
const org = ref(null)
const loading = ref(true)
const saving = ref(false)
const message = ref('')
const error = ref('')

const profileForm = ref({ username: '', full_name: '', email: '' })
const passwordForm = ref({ old_password: '', new_password: '', confirm_password: '' })
const showPasswordForm = ref(false)

async function loadProfile() {
  loading.value = true
  try {
    const [userRes, orgRes] = await Promise.all([getProfile(), getMyOrganization()])
    user.value = userRes.data
    org.value = orgRes.data
    profileForm.value = {
      username: userRes.data.username,
      full_name: userRes.data.full_name || '',
      email: userRes.data.email || '',
    }
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

async function saveProfile() {
  saving.value = true
  message.value = ''
  error.value = ''
  try {
    const { data } = await api.put('/auth/profile', profileForm.value)
    user.value = data
    // Update localStorage
    const stored = JSON.parse(localStorage.getItem('user') || '{}')
    stored.username = data.username
    stored.full_name = data.full_name
    stored.email = data.email
    localStorage.setItem('user', JSON.stringify(stored))
    message.value = 'Profile updated successfully'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to update profile'
  } finally {
    saving.value = false
  }
}

async function updatePassword() {
  message.value = ''
  error.value = ''
  if (passwordForm.value.new_password !== passwordForm.value.confirm_password) {
    error.value = 'Passwords do not match'
    return
  }
  if (passwordForm.value.new_password.length < 6) {
    error.value = 'Password must be at least 6 characters'
    return
  }
  saving.value = true
  try {
    await changePassword({
      old_password: passwordForm.value.old_password,
      new_password: passwordForm.value.new_password,
    })
    message.value = 'Password changed successfully'
    passwordForm.value = { old_password: '', new_password: '', confirm_password: '' }
    showPasswordForm.value = false
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to change password'
  } finally {
    saving.value = false
  }
}

const planLabels = { free: 'Free', basic: 'Basic', pro: 'Pro', enterprise: 'Enterprise' }

onMounted(loadProfile)
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Profile Settings</h1>
      <p class="text-gray-500 mt-1">Manage your account and organization settings</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="max-w-2xl space-y-6">
      <!-- Messages -->
      <div v-if="message" class="bg-green-50 border border-green-200 text-green-700 rounded-lg p-4">{{ message }}</div>
      <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">{{ error }}</div>

      <!-- Organization Info -->
      <div v-if="org" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>
          </svg>
          Organization
        </h3>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-gray-500">Name:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.name }}</span>
          </div>
          <div>
            <span class="text-gray-500">Plan:</span>
            <span :class="['mr-2 px-2 py-0.5 rounded-full text-xs font-medium',
              org.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
              org.plan === 'pro' ? 'bg-indigo-100 text-indigo-700' :
              org.plan === 'basic' ? 'bg-blue-100 text-blue-700' :
              'bg-gray-100 text-gray-700']">
              {{ planLabels[org.plan] || org.plan }}
            </span>
          </div>
          <div>
            <span class="text-gray-500">Max Targets:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.max_targets }}</span>
          </div>
          <div>
            <span class="text-gray-500">Max Scans/Month:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.max_scans }}</span>
          </div>
        </div>
      </div>

      <!-- Profile Form -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
          </svg>
          Account Information
        </h3>
        <form @submit.prevent="saveProfile" class="space-y-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Username</label>
            <input v-model="profileForm.username" type="text" required
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Full Name</label>
            <input v-model="profileForm.full_name" type="text"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Email</label>
            <input v-model="profileForm.email" type="email"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
            {{ saving ? 'Saving...' : 'Save Changes' }}
          </button>
        </form>
      </div>

      <!-- Password Change -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
            Password
          </h3>
          <button @click="showPasswordForm = !showPasswordForm"
            class="text-sm text-indigo-600 hover:text-indigo-800">
            {{ showPasswordForm ? 'Cancel' : 'Change Password' }}
          </button>
        </div>

        <form v-if="showPasswordForm" @submit.prevent="updatePassword" class="space-y-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Current Password</label>
            <input v-model="passwordForm.old_password" type="password" required
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">New Password</label>
            <input v-model="passwordForm.new_password" type="password" required minlength="6"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Confirm New Password</label>
            <input v-model="passwordForm.confirm_password" type="password" required
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50">
            {{ saving ? 'Changing...' : 'Change Password' }}
          </button>
        </form>
        <p v-else class="text-sm text-gray-500">Click "Change Password" to update your password</p>
      </div>
    </div>
  </div>
</template>
