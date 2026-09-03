// Ignite white-label branding overrides.
//
// This is the ONLY file a customer fork should edit to apply its own
// brand — index.html reads every brand-facing value (product name, page
// title, header logo mark, support link, accent color scale) from
// `window.IGNITE_BRAND` instead of hardcoding them, so upstream changes
// to index.html and a customer's branding never touch the same lines
// and can never merge-conflict.
//
// Leave this object empty (as shipped) and the app renders Ignite's own
// default branding unchanged — every key below is optional and falls
// back to its Ignite default (see DEFAULT_BRAND in index.html's <head>)
// when omitted. Set only the keys you want to override.
//
// Example:
//
// window.IGNITE_BRAND = {
//   name: 'Acme Compliance Gate',
//   title: 'Acme Compliance Gate — Onboarding Gatekeeper',
//   supportUrl: 'https://docs.acme.internal/compliance-gate',
//   // Any SVG markup, sized to fill an 18x18px box (w-4.5 h-4.5), currentColor-friendly.
//   logoSvg: '<svg class="w-4.5 h-4.5 text-white" fill="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>',
//   colors: {
//     // Full 50-900 Tailwind-style scale for the app's one accent color
//     // (buttons, links, active states). All ten shades are required if
//     // you override this — a partial scale will leave some shades
//     // Ignite-blue and others Acme-branded, which looks broken.
//     brand: {
//       50: '#fef2f2', 100: '#fee2e2', 200: '#fecaca', 300: '#fca5a5',
//       400: '#f87171', 500: '#ef4444', 600: '#dc2626', 700: '#b91c1c',
//       800: '#991b1b', 900: '#7f1d1d',
//     },
//   },
// };

window.IGNITE_BRAND = {};
