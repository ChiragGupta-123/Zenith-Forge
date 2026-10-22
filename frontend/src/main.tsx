import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';

/**
 * Inject baseline Tailwind / dark-scrollbar styles if index.css is not imported separately,
 * ensuring the Obsidian Studio theme (#090D16) renders cleanly in any setup.
 */
const GLOBAL_STUDIO_STYLE_ID = 'devcollab-obsidian-global-styles';
if (
    typeof document !== 'undefined' &&
    !document.getElementById(GLOBAL_STUDIO_STYLE_ID)
) {
    const styleEl = document.createElement('style');
    styleEl.id = GLOBAL_STUDIO_STYLE_ID;
    styleEl.textContent = `
      html, body, #root {
        margin: 0;
        padding: 0;
        min-height: 100%;
        background-color: #090D16;
        color: #f1f5f9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        -webkit-font-smoothing: antialiased;
      }
      ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
      }
      ::-webkit-scrollbar-track {
        background: #090D16;
      }
      ::-webkit-scrollbar-thumb {
        background: #1e293b;
        border-radius: 9999px;
      }
      ::-webkit-scrollbar-thumb:hover {
        background: #334155;
      }
    `;
    document.head.appendChild(styleEl);
}

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error('Failed to locate #root mount element in index.html');
}

ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);