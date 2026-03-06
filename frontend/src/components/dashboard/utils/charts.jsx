import React from "react";
import {
  Bar,
  Area,
  BarChart,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import axios from "axios";

import {
  AnyChartWidget,
  getRandomColorsArray,
  useTimePickerStore,
} from "@certego/certego-ui";
import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEEDS_STATISTICS_TYPES_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
  FEEDS_STATISTICS_COUNTRIES_URI,
} from "../../../constants/api";

import { FEED_COLOR_MAP, ENRICHMENT_COLOR_MAP } from "../../../constants";

const COUNTRY_BAR_COLOR = "#e05252";

// constants
const colors = getRandomColorsArray(30, true);

export const FeedsSourcesChart = React.memo(() => {
  console.debug("FeedsSourcesChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: FEEDS_STATISTICS_SOURCES_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(FEED_COLOR_MAP)
          .slice(0, 1)
          .map(([dkey, color]) => (
            <Area
              type="monotone"
              key={dkey}
              dataKey={dkey}
              fill={color}
              stroke={color}
            />
          )),
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const FeedsDownloadsChart = React.memo(() => {
  console.debug("FeedsDownloadsChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: FEEDS_STATISTICS_DOWNLOADS_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(FEED_COLOR_MAP)
          .slice(1, 2)
          .map(([dkey, color]) => (
            <Area
              type="monotone"
              key={dkey}
              dataKey={dkey}
              fill={color}
              stroke={color}
            />
          )),
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const EnrichmentSourcesChart = React.memo(() => {
  console.debug("EnrichmentSourcesChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: ENRICHMENT_STATISTICS_SOURCES_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(ENRICHMENT_COLOR_MAP)
          .slice(0, 1)
          .map(([dkey, color]) => (
            <Area
              type="monotone"
              key={dkey}
              dataKey={dkey}
              fill={color}
              stroke={color}
            />
          )),
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const EnrichmentRequestsChart = React.memo(() => {
  console.debug("EnrichmentRequestsChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: ENRICHMENT_STATISTICS_REQUESTS_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(ENRICHMENT_COLOR_MAP)
          .slice(1, 2)
          .map(([dkey, color]) => (
            <Area
              type="monotone"
              key={dkey}
              dataKey={dkey}
              fill={color}
              stroke={color}
            />
          )),
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const FeedsTypesChart = React.memo(() => {
  console.debug("FeedsTypesChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: FEEDS_STATISTICS_TYPES_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: (respData) => {
        console.debug("respData", respData);
        if (!respData || !respData?.length) return null;

        // Exctract keys only from respData[0]:
        // feed types are the same for all elements of respData.
        // Slice "date" field: we are only interested in feeds types.
        const feedsTypes = [];
        Object.entries(respData[0])
          .slice(1)
          .map(([dKey], i) => (feedsTypes[i] = dKey));

        // map each feed type to a color
        return feedsTypes.map((dKey, i) => (
          <Bar stackId="feedtype" key={dKey} dataKey={dKey} fill={colors[i]} />
        ));
      },
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const AttackOriginCountriesChart = React.memo(() => {
  console.debug("AttackOriginCountriesChart rendered!");

  const { range } = useTimePickerStore();
  const [data, setData] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    setLoading(true);
    setError(null);
    axios
      .get(FEEDS_STATISTICS_COUNTRIES_URI, { params: { range } })
      .then((resp) => setData(resp.data))
      .catch((err) => {
        console.error("AttackOriginCountriesChart error:", err);
        setError("Failed to load country data.");
      })
      .finally(() => setLoading(false));
  }, [range]);

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        {error}
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        No country data available for the selected time range.
      </div>
    );
  }

  // recharts renders top-to-bottom, so reverse so highest count is at top
  const chartData = data.slice(0, 15);

  return (
    <ResponsiveContainer
      width="100%"
      height={Math.max(180, chartData.length * 28)}
    >
      <BarChart
        layout="vertical"
        data={chartData}
        margin={{ top: 4, right: 48, left: 8, bottom: 4 }}
      >
        <XAxis
          type="number"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          type="category"
          dataKey="country"
          width={140}
          interval={0}
          tick={{ fontSize: 12 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          cursor={{ fill: "rgba(255,255,255,0.06)" }}
          formatter={(value) => [value.toLocaleString(), "IOCs"]}
        />
        <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={20}>
          {chartData.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={COUNTRY_BAR_COLOR}
              fillOpacity={0.55 + 0.45 * (index / (chartData.length - 1 || 1))}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
});
