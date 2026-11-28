// SPDX-License-Identifier: MPL-2.0

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrafficPoint } from "../store/appStore.ts";

export interface LiveTrafficChartProps {
  data: TrafficPoint[];
  trafficFilter: "all" | "proxy" | "direct";
  labels: {
    proxyDownload: string;
    proxyUpload: string;
    directDownload: string;
    directUpload: string;
  };
}

export function LiveTrafficChart({ data, trafficFilter, labels }: LiveTrafficChartProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart accessibilityLayer={false} data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="prismProxyFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.28} />
            <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.01} />
          </linearGradient>
          <linearGradient id="prismDirectFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" stopOpacity={0.22} />
            <stop offset="95%" stopColor="#10b981" stopOpacity={0.01} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border)" strokeOpacity={0.75} />
        <XAxis
          dataKey="time"
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
          minTickGap={24}
        />
        <YAxis
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
          tickFormatter={(value: number) =>
            value >= 1024 ? `${(value / 1024).toFixed(1)} MB` : `${value} KB`
          }
          width={68}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "var(--popover)",
            borderColor: "var(--border)",
            borderRadius: "10px",
            boxShadow: "0 10px 28px -8px rgba(0, 0, 0, 0.25)",
            fontSize: "12px",
          }}
        />
        {trafficFilter !== "direct" ? (
          <>
            <Area
              type="monotone"
              dataKey="proxyDownKB"
              name={`${labels.proxyDownload} (KB/s)`}
              stroke="var(--primary)"
              fill="url(#prismProxyFill)"
              strokeWidth={2}
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="proxyUpKB"
              name={`${labels.proxyUpload} (KB/s)`}
              stroke="var(--primary)"
              strokeOpacity={0.72}
              strokeDasharray="5 3"
              fill="var(--primary)"
              fillOpacity={0.04}
              strokeWidth={1.6}
              isAnimationActive={false}
            />
          </>
        ) : null}
        {trafficFilter !== "proxy" ? (
          <>
            <Area
              type="monotone"
              dataKey="directDownKB"
              name={`${labels.directDownload} (KB/s)`}
              stroke="#10b981"
              fill="url(#prismDirectFill)"
              strokeWidth={2}
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="directUpKB"
              name={`${labels.directUpload} (KB/s)`}
              stroke="#10b981"
              strokeOpacity={0.72}
              strokeDasharray="5 3"
              fill="#10b981"
              fillOpacity={0.04}
              strokeWidth={1.6}
              isAnimationActive={false}
            />
          </>
        ) : null}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export default LiveTrafficChart;
