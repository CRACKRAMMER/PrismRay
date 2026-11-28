// SPDX-License-Identifier: MPL-2.0

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrafficHistoryBucket } from "../lib/api.ts";
import { formatBytes } from "../lib/helpers.ts";

export interface TrafficHistoryChartProps {
  buckets: TrafficHistoryBucket[];
  granularity: "hour" | "day";
  trafficFilter: "all" | "proxy" | "direct";
  labels: {
    proxyDownload: string;
    proxyUpload: string;
    directDownload: string;
    directUpload: string;
  };
}

export function TrafficHistoryChart({
  buckets,
  granularity,
  trafficFilter,
  labels,
}: TrafficHistoryChartProps) {
  const data = buckets.map((b) => {
    const dt = new Date(b.bucket_unix * 1000);
    const label =
      granularity === "hour"
        ? dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
        : `${dt.getMonth() + 1}/${dt.getDate()}`;
    return {
      label,
      proxyDownMB: Number((b.proxy_down / (1024 * 1024)).toFixed(2)),
      proxyUpMB: Number((b.proxy_up / (1024 * 1024)).toFixed(2)),
      directDownMB: Number((b.direct_down / (1024 * 1024)).toFixed(2)),
      directUpMB: Number((b.direct_up / (1024 * 1024)).toFixed(2)),
      raw: b,
    };
  });

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart accessibilityLayer={false} data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border)" strokeOpacity={0.75} />
        <XAxis
          dataKey="label"
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
          minTickGap={20}
        />
        <YAxis
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
          tickFormatter={(value: number) =>
            value >= 1024
              ? `${(value / 1024).toFixed(1)} GB`
              : value > 0 && value < 1
                ? `${Math.round(value * 1024)} KB`
                : `${value} MB`
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
          formatter={(value: unknown, name: unknown) => [
            formatBytes(Number(value || 0) * 1024 * 1024),
            String(name ?? ""),
          ]}
        />
        {trafficFilter !== "direct" ? (
          <>
            <Bar dataKey="proxyDownMB" stackId="proxy" name={labels.proxyDownload} fill="var(--primary)" fillOpacity={0.92} radius={[0, 0, 0, 0]} isAnimationActive={false} />
            <Bar dataKey="proxyUpMB" stackId="proxy" name={labels.proxyUpload} fill="var(--primary)" fillOpacity={0.42} radius={[4, 4, 0, 0]} isAnimationActive={false} />
          </>
        ) : null}
        {trafficFilter !== "proxy" ? (
          <>
            <Bar dataKey="directDownMB" stackId="direct" name={labels.directDownload} fill="#10b981" fillOpacity={0.92} radius={[0, 0, 0, 0]} isAnimationActive={false} />
            <Bar dataKey="directUpMB" stackId="direct" name={labels.directUpload} fill="#10b981" fillOpacity={0.42} radius={[4, 4, 0, 0]} isAnimationActive={false} />
          </>
        ) : null}
      </BarChart>
    </ResponsiveContainer>
  );
}

export default TrafficHistoryChart;
