/**
 * Canonical asset URLs respecting Vite's base path for root domain,
 * subpath deployments (e.g. GitHub Pages https://<user>.github.io/<repo>/),
 * and local dev environments.
 */
const BASE = import.meta.env.BASE_URL || './';
const normalizedBase = BASE.endsWith('/') ? BASE : `${BASE}/`;

export const SENTINEL_LOGO_SRC = `${normalizedBase}assets/aistudio/Code_Generated_Image_dcad87d9.png`;
