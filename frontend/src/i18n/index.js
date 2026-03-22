import { ref, computed } from 'vue'
import ar from './ar.json'
import en from './en.json'

const messages = { ar, en }
const currentLang = ref(localStorage.getItem('vscan_lang') || 'ar')

export function useI18n() {
  const lang = computed(() => currentLang.value)
  const dir = computed(() => messages[currentLang.value]?.dir || 'rtl')

  function t(key) {
    const keys = key.split('.')
    let result = messages[currentLang.value]
    for (const k of keys) {
      if (result && typeof result === 'object') {
        result = result[k]
      } else {
        return key
      }
    }
    return result || key
  }

  function setLang(newLang) {
    if (messages[newLang]) {
      currentLang.value = newLang
      localStorage.setItem('vscan_lang', newLang)
      document.documentElement.setAttribute('dir', messages[newLang].dir)
      document.documentElement.setAttribute('lang', newLang)
    }
  }

  function toggleLang() {
    setLang(currentLang.value === 'ar' ? 'en' : 'ar')
  }

  return { t, lang, dir, setLang, toggleLang }
}

// Initialize direction on load
const savedLang = localStorage.getItem('vscan_lang') || 'ar'
document.documentElement.setAttribute('dir', messages[savedLang]?.dir || 'rtl')
document.documentElement.setAttribute('lang', savedLang)
