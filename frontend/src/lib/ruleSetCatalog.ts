// SPDX-License-Identifier: MPL-2.0

export interface RuleSetCatalogEntry {
  id: string;
  tag: string;
  nameZh: string;
  nameEn: string;
  category: "ai" | "messaging" | "dev" | "media" | "platform" | "network";
  url: string;
  format: "binary" | "source";
  update_interval: string;
}

const GEOSITE_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
const GEOIP_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set";

export const RULE_SET_CATALOG: RuleSetCatalogEntry[] = [
  {
    id: "geosite-openai",
    tag: "geosite-openai",
    nameZh: "OpenAI / ChatGPT",
    nameEn: "OpenAI / ChatGPT",
    category: "ai",
    url: `${GEOSITE_BASE}/geosite-openai.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-anthropic",
    tag: "geosite-anthropic",
    nameZh: "Anthropic / Claude",
    nameEn: "Anthropic / Claude",
    category: "ai",
    url: `${GEOSITE_BASE}/geosite-anthropic.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-telegram",
    tag: "geosite-telegram",
    nameZh: "Telegram 域名",
    nameEn: "Telegram Domains",
    category: "messaging",
    url: `${GEOSITE_BASE}/geosite-telegram.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geoip-telegram",
    tag: "geoip-telegram",
    nameZh: "Telegram IP 段",
    nameEn: "Telegram IPs",
    category: "messaging",
    url: `${GEOIP_BASE}/geoip-telegram.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-google",
    tag: "geosite-google",
    nameZh: "Google 全家桶",
    nameEn: "Google Services",
    category: "platform",
    url: `${GEOSITE_BASE}/geosite-google.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-github",
    tag: "geosite-github",
    nameZh: "GitHub 生态",
    nameEn: "GitHub",
    category: "dev",
    url: `${GEOSITE_BASE}/geosite-github.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-youtube",
    tag: "geosite-youtube",
    nameZh: "YouTube 流媒体",
    nameEn: "YouTube",
    category: "media",
    url: `${GEOSITE_BASE}/geosite-youtube.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-netflix",
    tag: "geosite-netflix",
    nameZh: "Netflix 流媒体",
    nameEn: "Netflix",
    category: "media",
    url: `${GEOSITE_BASE}/geosite-netflix.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-steam",
    tag: "geosite-steam",
    nameZh: "Steam 平台",
    nameEn: "Steam",
    category: "media",
    url: `${GEOSITE_BASE}/geosite-steam.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-apple",
    tag: "geosite-apple",
    nameZh: "Apple 服务",
    nameEn: "Apple Services",
    category: "platform",
    url: `${GEOSITE_BASE}/geosite-apple.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-microsoft",
    tag: "geosite-microsoft",
    nameZh: "Microsoft 服务",
    nameEn: "Microsoft Services",
    category: "platform",
    url: `${GEOSITE_BASE}/geosite-microsoft.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-bilibili",
    tag: "geosite-bilibili",
    nameZh: "Bilibili 哔哩哔哩",
    nameEn: "Bilibili",
    category: "media",
    url: `${GEOSITE_BASE}/geosite-bilibili.srs`,
    format: "binary",
    update_interval: "24h",
  },
  {
    id: "geosite-private",
    tag: "geosite-private",
    nameZh: "内网 / 私有域名",
    nameEn: "Private / LAN Domains",
    category: "network",
    url: `${GEOSITE_BASE}/geosite-private.srs`,
    format: "binary",
    update_interval: "72h",
  },
];
