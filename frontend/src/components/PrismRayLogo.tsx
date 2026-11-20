// SPDX-License-Identifier: MPL-2.0

import { useId } from "react";

export function PrismRayLogo({ className = "h-7 w-7" }: { className?: string }) {
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1024 1024"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`${uid}-bg`} x1="0" y1="0" x2="1024" y2="1024" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1A1D2B" />
          <stop offset="55%" stopColor="#11131A" />
          <stop offset="100%" stopColor="#0B0C11" />
        </linearGradient>
        <linearGradient id={`${uid}-beam`} x1="88" y1="560" x2="360" y2="480" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.18" />
          <stop offset="65%" stopColor="#EEF2FF" stopOpacity="0.92" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="1" />
        </linearGradient>
        <linearGradient id={`${uid}-cyan`} x1="560" y1="480" x2="940" y2="360" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#67E8F9" />
          <stop offset="60%" stopColor="#38BDF8" />
          <stop offset="100%" stopColor="#0EA5E9" stopOpacity="0.3" />
        </linearGradient>
        <linearGradient id={`${uid}-indigo`} x1="580" y1="530" x2="944" y2="530" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#818CF8" />
          <stop offset="60%" stopColor="#5E6AD2" />
          <stop offset="100%" stopColor="#4F46E5" stopOpacity="0.32" />
        </linearGradient>
        <linearGradient id={`${uid}-violet`} x1="600" y1="580" x2="932" y2="690" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#C084FC" />
          <stop offset="60%" stopColor="#9333EA" />
          <stop offset="100%" stopColor="#7E22CE" stopOpacity="0.28" />
        </linearGradient>
        <linearGradient id={`${uid}-left`} x1="250" y1="220" x2="488" y2="790" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="48%" stopColor="#E0E7FF" />
          <stop offset="100%" stopColor="#93C5FD" />
        </linearGradient>
        <linearGradient id={`${uid}-right`} x1="488" y1="180" x2="750" y2="790" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#818CF8" />
          <stop offset="52%" stopColor="#5E6AD2" />
          <stop offset="100%" stopColor="#0EA5E9" />
        </linearGradient>
      </defs>
      <rect
        x="24"
        y="24"
        width="976"
        height="976"
        rx="224"
        fill={`url(#${uid}-bg)`}
        stroke="#FFFFFF"
        strokeOpacity="0.16"
        strokeWidth="22"
      />
      <polygon points="88,542 368,438 386,496 88,588" fill={`url(#${uid}-beam)`} />
      <polygon points="564,432 932,312 932,388 588,486" fill={`url(#${uid}-cyan)`} />
      <polygon points="588,486 942,468 942,544 612,540" fill={`url(#${uid}-indigo)`} />
      <polygon points="612,540 924,624 924,700 636,596" fill={`url(#${uid}-violet)`} />
      <polygon points="488,168 206,796 488,716" fill={`url(#${uid}-left)`} />
      <polygon points="488,168 770,796 488,716" fill={`url(#${uid}-right)`} />
      <polygon points="206,796 488,716 770,796" fill="#312E81" fillOpacity="0.92" />
      <line x1="488" y1="176" x2="488" y2="716" stroke="#FFFFFF" strokeOpacity="0.72" strokeWidth="14" strokeLinecap="round" />
      <polygon points="488,168 770,796 206,796" fill="none" stroke="#E0E7FF" strokeOpacity="0.45" strokeWidth="14" strokeLinejoin="round" />
    </svg>
  );
}
