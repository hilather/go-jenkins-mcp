/**
 * Tree-shaken Apache ECharts registration for the admin SPA.
 * Import this module before rendering charts so only line/bar + needed
 * components ship (UI-POLISH-008 residual if still large).
 */

import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  TitleComponent,
  CanvasRenderer,
]);

export { echarts };
