import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../components/dashboard/utils/charts";

export const feedsChartList = [
  ["FeedsSourcesChart", "Feeds: Sources", FeedsSourcesChart],
  ["FeedsDownloadsChart", "Feeds: Downloads", FeedsDownloadsChart],
];

export const feedsTypesChartList = [
  ["FeedsTypesChart", "Feeds: Types", FeedsTypesChart],
];

export const enrichmentChartList = [
  ["EnrichmentSourcesChart", "Enrichment Service: Sources", EnrichmentSourcesChart],
  ["EnrichmentRequestsChart", "Enrichment Service: Requests", EnrichmentRequestsChart],
];