import { ref, watch } from 'vue'

const theme = ref(localStorage.getItem('vscan_theme') || 'light')

watch(theme, (val) => {
  localStorage.setItem('vscan_theme', val)
  if (val === 'dark') {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
})

// Initialize on load
if (theme.value === 'dark') {
  document.documentElement.classList.add('dark')
}

export function useTheme() {
  function toggleTheme() {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
  }
  return { theme, toggleTheme }
}
