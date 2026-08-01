/**
 * Shared Apache ECharts host for the admin SPA.
 *
 * All charts MUST go through this component (or a thin wrapper that passes
 * EChartsOption). Do not introduce alternate chart libraries.
 */

import { useMemo } from "react";
import ReactEChartsCore from "echarts-for-react/lib/core";
import type { ComposeOption } from "echarts/core";
import type { BarSeriesOption, LineSeriesOption } from "echarts/charts";
import type {
  GridComponentOption,
  LegendComponentOption,
  TitleComponentOption,
  TooltipComponentOption,
} from "echarts/components";
import { echarts } from "../../lib/echartsSetup";

/** Option surface used by admin metrics charts (line + bar only). */
export type AdminChartOption = ComposeOption<
  | LineSeriesOption
  | BarSeriesOption
  | GridComponentOption
  | TooltipComponentOption
  | LegendComponentOption
  | TitleComponentOption
>;

export interface EChartProps {
  option: AdminChartOption;
  /** CSS height (default 220px). */
  height?: number | string;
  className?: string;
  /** Accessible name for the chart region. */
  ariaLabel?: string;
  /** Lazy update reduces flicker on auto-refresh. */
  notMerge?: boolean;
}

export function EChart({
  option,
  height = 220,
  className,
  ariaLabel,
  notMerge = true,
}: EChartProps) {
  const style = useMemo(
    () => ({
      height: typeof height === "number" ? `${height}px` : height,
      width: "100%",
    }),
    [height],
  );

  return (
    <div
      className={className ? `echart-host ${className}` : "echart-host"}
      role="img"
      aria-label={ariaLabel ?? "chart"}
    >
      <ReactEChartsCore
        echarts={echarts}
        option={option}
        style={style}
        notMerge={notMerge}
        lazyUpdate
        opts={{ renderer: "canvas" }}
      />
    </div>
  );
}
