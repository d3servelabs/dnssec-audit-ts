// Design tokens for the glassmorphism shell.
// Both the webapp and the Chrome extension import these so colors, blur,
// and shadows stay aligned.

export const GLASS_TOKENS = {
  card: {
    background: "rgba(255, 255, 255, 0.08)",
    border: "1px solid rgba(255, 255, 255, 0.18)",
    backdropFilter: "blur(28px) saturate(160%)",
    boxShadow:
      "0 20px 60px -10px rgba(8, 12, 40, 0.45), inset 0 1px 0 rgba(255,255,255,0.25)",
    borderRadius: "24px",
  },
  tone: {
    ok: "rgba(96, 240, 170, 0.9)",
    warn: "rgba(255, 196, 96, 0.92)",
    bad: "rgba(255, 110, 140, 0.92)",
    neutral: "rgba(220, 225, 255, 0.9)",
  },
} as const;
