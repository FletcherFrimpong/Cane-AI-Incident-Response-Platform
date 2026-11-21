/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', '"Helvetica Neue"', 'Arial', 'sans-serif'],
      },
      colors: {
        // Help-desk style palette: deep teal rail, cool greys, one calm blue for actions
        rail: { DEFAULT: '#0b3640', hover: '#14505c', active: '#1d6573' },
        ink: { DEFAULT: '#2f3941', soft: '#49545c', muted: '#68737d', faint: '#87929d' },
        line: { DEFAULT: '#d8dcde', soft: '#e9ebed' },
        surface: { DEFAULT: '#f8f9f9', sunken: '#f3f4f5' },
        brand: {
          50: '#edf7ff', 100: '#cee2f2', 200: '#adcce4', 300: '#5293c7', 400: '#337fbd',
          500: '#1f73b7', 600: '#1f73b7', 700: '#144a75', 800: '#0f3554', 900: '#0a2a43',
        },
        severity: { critical: '#cc3340', high: '#d2680d', medium: '#c28a00', low: '#1f73b7', info: '#87929d' },
      },
      fontSize: { '2xs': ['11px', '14px'] },
    },
  },
  plugins: [],
}
