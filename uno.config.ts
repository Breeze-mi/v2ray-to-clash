import { defineConfig, presetUno, presetIcons } from 'unocss'

export default defineConfig({
  presets: [
    presetUno(),
    presetIcons({
      scale: 1.2,
      extraProperties: {
        'display': 'inline-block',
        'vertical-align': 'middle',
      },
    }),
  ],
  theme: {
    colors: {
      primary: {
        50: '#eef2ff',
        100: '#e0e7ff',
        200: '#c7d2fe',
        300: '#a5b4fc',
        400: '#818cf8',
        500: '#6366f1',
        600: '#4f46e5',
        700: '#4338ca',
        800: '#3730a3',
        900: '#312e81',
      },
    },
  },
  shortcuts: {
    'btn': 'px-3 py-1.5 rounded-md text-sm font-medium transition-all duration-200 cursor-pointer',
    'btn-primary': 'btn bg-primary-500 text-white hover:bg-primary-600 active:bg-primary-700',
    'btn-ghost': 'btn bg-gray-100 text-gray-700 hover:bg-gray-200 active:bg-gray-300',
    'card': 'bg-white rounded-lg border border-gray-200 shadow-sm',
    'input-base': 'w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all',
    'section-title': 'text-xs font-semibold text-gray-500 uppercase tracking-wide',
    'badge': 'px-2 py-0.5 text-xs font-medium rounded-full',
    'badge-primary': 'badge bg-primary-100 text-primary-700',
  },
})
