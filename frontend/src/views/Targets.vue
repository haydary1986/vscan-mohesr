<script setup>
import { ref, onMounted } from 'vue'
import { getTargets, createTarget, createBulkTargets, deleteTarget } from '../api'

const targets = ref([])
const loading = ref(true)
const showAddForm = ref(false)
const showBulkForm = ref(false)

const newTarget = ref({ url: '', name: '', institution: '' })
const bulkText = ref('')

async function loadTargets() {
  loading.value = true
  try {
    const { data } = await getTargets()
    targets.value = data
  } catch (e) {
    console.error('Failed to load targets:', e)
  } finally {
    loading.value = false
  }
}

async function addTarget() {
  if (!newTarget.value.url) return
  try {
    await createTarget(newTarget.value)
    newTarget.value = { url: '', name: '', institution: '' }
    showAddForm.value = false
    await loadTargets()
  } catch (e) {
    console.error('Failed to add target:', e)
  }
}

async function addBulkTargets() {
  const lines = bulkText.value.trim().split('\n').filter(l => l.trim())
  if (lines.length === 0) return

  const bulkTargets = lines.map(line => {
    const parts = line.split(',').map(p => p.trim())
    return {
      url: parts[0] || '',
      name: parts[1] || '',
      institution: parts[2] || '',
    }
  }).filter(t => t.url)

  try {
    await createBulkTargets(bulkTargets)
    bulkText.value = ''
    showBulkForm.value = false
    await loadTargets()
  } catch (e) {
    console.error('Failed to add bulk targets:', e)
  }
}

async function removeTarget(id) {
  if (!confirm('Are you sure you want to delete this target?')) return
  try {
    await deleteTarget(id)
    await loadTargets()
  } catch (e) {
    console.error('Failed to delete target:', e)
  }
}

onMounted(loadTargets)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Targets</h1>
        <p class="text-gray-500 mt-1">Manage websites to scan</p>
      </div>
      <div class="flex gap-3">
        <button
          @click="showBulkForm = !showBulkForm; showAddForm = false"
          class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm"
        >
          Bulk Add
        </button>
        <button
          @click="showAddForm = !showAddForm; showBulkForm = false"
          class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
        >
          Add Target
        </button>
      </div>
    </div>

    <!-- Add Single Target Form -->
    <div v-if="showAddForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">Add New Target</h3>
      <form @submit.prevent="addTarget" class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label class="block text-sm text-gray-600 mb-1">URL *</label>
          <input
            v-model="newTarget.url"
            type="text"
            placeholder="example.edu.iq"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Name</label>
          <input
            v-model="newTarget.name"
            type="text"
            placeholder="University of Baghdad"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Institution</label>
          <input
            v-model="newTarget.institution"
            type="text"
            placeholder="University"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        <div class="md:col-span-3">
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Add Target
          </button>
        </div>
      </form>
    </div>

    <!-- Bulk Add Form -->
    <div v-if="showBulkForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-2">Bulk Add Targets</h3>
      <p class="text-sm text-gray-500 mb-4">Enter one target per line: URL, Name, Institution (comma separated)</p>
      <textarea
        v-model="bulkText"
        rows="8"
        placeholder="uobaghdad.edu.iq, University of Baghdad, University
uomosul.edu.iq, University of Mosul, University
uobasrah.edu.iq, University of Basrah, University"
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-sm"
      ></textarea>
      <button @click="addBulkTargets" class="mt-3 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
        Add All Targets
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- Targets Table -->
    <div v-else class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table v-if="targets.length" class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">#</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">URL</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Name</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Institution</th>
            <th class="text-center py-3 px-4 text-gray-600 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(target, i) in targets" :key="target.ID" class="border-t border-gray-100 hover:bg-gray-50">
            <td class="py-3 px-4 text-gray-400">{{ i + 1 }}</td>
            <td class="py-3 px-4">
              <a :href="'https://' + target.url" target="_blank" class="text-indigo-600 hover:underline">
                {{ target.url }}
              </a>
            </td>
            <td class="py-3 px-4 text-gray-900">{{ target.name || '-' }}</td>
            <td class="py-3 px-4 text-gray-600">{{ target.institution || '-' }}</td>
            <td class="py-3 px-4 text-center">
              <button @click="removeTarget(target.ID)" class="text-red-500 hover:text-red-700 text-sm">
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="text-center py-16 text-gray-400">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
        </svg>
        <p class="text-lg">No targets added yet</p>
        <p class="text-sm mt-1">Add websites to start scanning</p>
      </div>
    </div>
  </div>
</template>
