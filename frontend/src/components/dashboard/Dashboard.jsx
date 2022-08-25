import React from "react";
import { Container, Row, Col } from "reactstrap";

import {
    ElasticTimePicker,
    useTimePickerStore,
    SmallInfoCard,
} from "@certego/certego-ui";

import {
    FeedsSourcesChart,
    FeedsDownloadsChart,
    EnrichmentSourcesChart,
    EnrichmentRequestsChart,
    FeedsTypesChart
} from "./utils/charts";

const feedsChartList = [
    ["FeedsSourcesChart", "Feeds: Sources", FeedsSourcesChart],
    ["FeedsDownloadsChart", "Feeds: Downloads", FeedsDownloadsChart],
    ["FeedsTypesChart", "Feeds: Types", FeedsTypesChart]
];

const enrichmentChartList = [
    ["EnrichmentSourcesChart", "Enrichment Service: Sources", EnrichmentSourcesChart],
    ["EnrichmentRequestsChart", "Enrichment Service: Requests", EnrichmentRequestsChart],
];

function Dashboard() {
    console.debug("Dashboard rendered!");
    const { range, onTimeIntervalChange } = useTimePickerStore();

    return (
        <Container fluid id="Dashboard">
            <div className="g-0 d-flex align-items-baseline flex-column flex-lg-row mb-2">
                <h3 className="fw-bold">Dashboard</h3>
                <ElasticTimePicker
                className="ms-auto"
                size="sm"
                defaultSelected={range}
                onChange={onTimeIntervalChange}
                />
            </div>
            <Row className="d-flex flex-wrap flex-lg-nowrap">
                {feedsChartList.map(([id, header, Component]) => (
                    <Col key={id} md={12} lg={4}>
                        <SmallInfoCard
                        id={id}
                        header={header}
                        body={
                            <div className="pt-2">
                            <Component/>
                            </div>
                        }
                        style={{ minHeight: 360 }}
                        />
                    </Col>
                ))}
            </Row>
            <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
                {enrichmentChartList.map(([id, header, Component]) => (
                    <Col key={id} md={12} lg={6}>
                        <SmallInfoCard
                        id={id}
                        header={header}
                        body={
                            <div className="pt-2">
                            <Component/>
                            </div>
                        }
                        style={{ minHeight: 360 }}
                        />
                    </Col>
                ))}
            </Row>
      </Container>
    )
}

export default Dashboard;