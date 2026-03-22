<script setup>
import { ref, onMounted } from 'vue'
import { getSettings, updateSettings } from '../api'

const settings = ref({
  ai_provider: 'deepseek',
  ai_api_key: '',
  ai_model: '',
  ai_base_url: '',
})
const loading = ref(true)
const saving = ref(false)
const message = ref('')

const providers = [
  { value: 'deepseek', label: 'DeepSeek', defaultModel: 'deepseek-chat', defaultUrl: 'https://api.deepseek.com/v1' },
  { value: 'openai', label: 'OpenAI', defaultModel: 'gpt-4o-mini', defaultUrl: 'https://api.openai.com/v1' },
  { value: 'custom', label: 'Custom (OpenAI-compatible)', defaultModel: '', defaultUrl: '' },
]

function onProviderChange() {
  const provider = providers.find(p => p.value === settings.value.ai_provider)
  if (provider) {
    settings.value.ai_model = provider.defaultModel
    settings.value.ai_base_url = provider.defaultUrl
  }
}

async function loadSettings() {
  loading.value = true
  try {
    const { data } = await getSettings()
    if (data.ai_provider) settings.value.ai_provider = data.ai_provider
    if (data.ai_api_key) settings.value.ai_api_key = data.ai_api_key
    if (data.ai_model) settings.value.ai_model = data.ai_model
    if (data.ai_base_url) settings.value.ai_base_url = data.ai_base_url
  } catch (e) {
    console.error('Failed to load settings:', e)
  } finally {
    loading.value = false
  }
}

async function saveSettings() {
  saving.value = true
  message.value = ''
  try {
    await updateSettings(settings.value)
    message.value = 'Settings saved successfully!'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    message.value = 'Failed to save: ' + (e.response?.data?.error || e.message)
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Settings</h1>
      <p class="text-gray-500 mt-1">Configure AI analysis and system settings</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="max-w-2xl">
      <!-- AI Configuration -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
            <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900">AI Analysis Configuration</h3>
            <p class="text-sm text-gray-500">Configure AI to analyze scan results and suggest fixes</p>
          </div>
        </div>

        <form @submit.prevent="saveSettings" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">AI Provider</label>
            <select v-model="settings.ai_provider" @change="onProviderChange"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
              <option v-for="p in providers" :key="p.value" :value="p.value">{{ p.label }}</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">API Key</label>
            <input v-model="settings.ai_api_key" type="password"
              placeholder="sk-..."
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            <p class="text-xs text-gray-400 mt-1">Your API key is stored securely on the server</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Model</label>
            <input v-model="settings.ai_model" type="text"
              placeholder="deepseek-chat"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Base URL</label>
            <input v-model="settings.ai_base_url" type="text"
              placeholder="https://api.deepseek.com/v1"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
          </div>

          <div v-if="message" :class="['px-4 py-3 rounded-lg text-sm', message.includes('Failed') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700']">
            {{ message }}
          </div>

          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
            {{ saving ? 'Saving...' : 'Save Settings' }}
          </button>
        </form>
      </div>

      <!-- How it works -->
      <div class="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <h4 class="font-semibold text-blue-900 mb-3">How AI Analysis Works</h4>
        <ol class="list-decimal list-inside space-y-2 text-sm text-blue-800">
          <li>Configure your AI provider above (DeepSeek is recommended - affordable and capable)</li>
          <li>Run a security scan on your target websites</li>
          <li>Open any scan result and click <strong>"AI Analysis"</strong></li>
          <li>The AI will analyze all findings and provide:
            <ul class="list-disc list-inside mr-4 mt-1 text-blue-700">
              <li>Executive summary of security posture</li>
              <li>Detailed fix instructions for each vulnerability</li>
              <li>Step-by-step roadmap to achieve 100% score</li>
              <li>Configuration examples and code snippets</li>
            </ul>
          </li>
        </ol>
      </div>
    </div>
  </div>
</template>
