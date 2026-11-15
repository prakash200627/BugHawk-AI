/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#020818',
          900: '#050d1f',
          800: '#091428',
          700: '#0d1c35',
          600: '#122142',
          500: '#1a2f5c',
        },
        cyber: {
          blue: '#3b82f6',
          'blue-bright': '#60a5fa',
          'blue-glow': '#1d4ed8',
          orange: '#f97316',
          'orange-bright': '#fb923c',
          'orange-glow': '#c2410c',
          cyan: '#06b6d4',
          purple: '#8b5cf6',
          green: '#10b981',
          red: '#ef4444',
          yellow: '#f59e0b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid': `
          linear-gradient(rgba(59, 130, 246, 0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(59, 130, 246, 0.03) 1px, transparent 1px)
        `,
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
        'scan-line': 'scanLine 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.6), 0 0 40px rgba(59, 130, 246, 0.2)' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(59, 130, 246, 0.15), 0 4px 24px rgba(0, 0, 0, 0.4)',
        'cyber-hover': '0 0 30px rgba(59, 130, 246, 0.25), 0 8px 32px rgba(0, 0, 0, 0.5)',
        'orange-glow': '0 0 20px rgba(249, 115, 22, 0.3)',
        'inner-blue': 'inset 0 1px 0 rgba(59, 130, 246, 0.1)',
      },
    },
  },
  plugins: [],
}
