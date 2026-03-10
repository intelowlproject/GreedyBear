import React from "react";
import { Container, Row, Col } from "reactstrap";

import {
  ElasticTimePicker,
  useTimePickerStore,
  SmallInfoCard,
} from "@certego/certego-ui";

import {
  feedsChartList,
  feedsTypesChartList,
  enrichmentChartList,
} from "../../constants/dashboardConfig";
import EnrichmentLookup from "./EnrichmentLookup";


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

      {/* Enrichment Lookup Section - Publicly visible */}
      <Row className="mb-4">
        <Col md={12}>
          <SmallInfoCard
            id="enrichment-lookup"
            header="Enrichment Lookup"
            body={
              <div className="pt-2">
                <EnrichmentLookup />
              </div>
            }
          />
        </Col>
      </Row>

      <Row className="d-flex flex-wrap flex-lg-nowrap">
        {feedsTypesChartList.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={12}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {feedsChartList.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={6}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
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
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
    </Container>
  );
}

export default Dashboard;
