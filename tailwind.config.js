/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        obsidian: '#0B0F19',
        card: '#111827',
        cyber: '#06B6D4',
        emerald: { DEFAULT: '#10B981', 400: '#34D399', 500: '#10B981', 600: '#059669' },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      keyframes: {
        floatUp: {
          '0%': { opacity: '0', transform: 'translateY(10px) scale(0.9)' },
          '15%': { opacity: '1', transform: 'translateY(0) scale(1)' },
          '80%': { opacity: '1', transform: 'translateY(-30px)' },
          '100%': { opacity: '0', transform: 'translateY(-50px)' },
        },
        popIn: {
          '0%': { opacity: '0', transform: 'scale(0.8)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
      },
      animation: {
        floatUp: 'floatUp 2s ease-out forwards',
        popIn: 'popIn 0.35s ease-out',
      },
    },
  },
  plugins: [],
};
