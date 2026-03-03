import React from "react";
import { Bar, Area } from "recharts";

import { AnyChartWidget, getRandomColorsArray } from "@certego/certego-ui";
import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEEDS_STATISTICS_TYPES_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
} from "../../../constants/api";

import { FEED_COLOR_MAP, ENRICHMENT_COLOR_MAP } from "../../../constants";

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
