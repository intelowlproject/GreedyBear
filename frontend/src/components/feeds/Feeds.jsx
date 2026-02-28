import React from "react";
import { Container, Button, Col, Label, FormGroup, Row } from "reactstrap";
import { VscJson } from "react-icons/vsc";
import { TbLicense } from "react-icons/tb";
import { useNavigate, useLocation } from "react-router-dom";
import { FEEDS_BASE_URI, GENERAL_HONEYPOT_URI } from "../../constants/api";
import {
  ContentSection,
  MultiSelectDropdownInput,
  Select,
  useAxiosComponentLoader,
  useDataTable,
} from "@certego/certego-ui";
import { Form, Formik } from "formik";
import { feedsTableColumns } from "./tableColumns";
import { FEEDS_LICENSE } from "../../constants";

// constants
const attackTypeChoices = [
  { label: "All", value: "all" },
  { label: "Scanner", value: "scanner" },
  { label: "Payload request", value: "payload_request" },
];

const iocTypeChoices = [
  { label: "All", value: "all" },
  { label: "IP addresses", value: "ip" },
  { label: "Domains", value: "domain" },
];

const prioritizationChoices = [
  { label: "Recent", value: "recent" },
  { label: "Persistent", value: "persistent" },
  { label: "Likely to recur", value: "likely_to_recur" },
  { label: "Most expected hits", value: "most_expected_hits" },
];

const initialValues = {
  feeds_type: "all",
  attack_type: "all",
  ioc_type: "all",
  prioritize: "recent",
};

const toPassTableProps = {
  columns: feedsTableColumns,
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing filter.</small>
    </>
  ),
};

// prioritizations where backend overrides "ordering" query param.
const OVERRIDING_PRIORITIZATIONS = ["likely_to_recur", "most_expected_hits"];

let honeypotFeedsType = [];

// when multiple feed types are selected, the path-based raw data url
// can only express a single segment, so fall back to "all".
const feedTypePath = (feedsType) =>
  feedsType.includes(",") ? "all" : feedsType;

// extracted child component so useDataTable hooks are owned here.
// changing the `key` on this component forces a full unmount/remount.
function FeedsTable({ tableParams, onDataLoad, onSortChange }) {
  const location = useLocation();

  const [feedsData, tableNode] = useDataTable(
    {
      url: FEEDS_BASE_URI,
      params: tableParams,
      initialParams: {
        page: "1",
      },
    },
    toPassTableProps,
    (data) => data.results.iocs,
  );

  // Notify parent of data changes so it can display the count
  React.useEffect(() => {
    if (onDataLoad) {
      onDataLoad(feedsData);
    }
  }, [feedsData, onDataLoad]);

  // if the current prioritization mode overrides ordering on the backend
  // notify the parent so it can reset prioritization to "recent".
  React.useEffect(() => {
    const params = new URLSearchParams(location.search);
    if (
      params.has("ordering") &&
      OVERRIDING_PRIORITIZATIONS.includes(tableParams.prioritize) &&
      onSortChange
    ) {
      onSortChange();
    }
  }, [location.search, tableParams.prioritize, onSortChange]);

  return tableNode;
}

export default function Feeds() {
  console.debug("Feeds rendered!");

  console.debug("Feeds-initialValues", initialValues);

  const navigate = useNavigate();

  const [url, setUrl] = React.useState(
    `${FEEDS_BASE_URI}/${initialValues.feeds_type}/${initialValues.attack_type}/${initialValues.prioritize}.json`,
  );

  // Counter used to force remount FeedsTable
  const [tableKey, setTableKey] = React.useState(0);

  // feedsData is lifted from FeedsTable so we can show the count in the header
  const [feedsData, setFeedsData] = React.useState(null);

  // API to extract general honeypot
  const [honeypots, Loader] = useAxiosComponentLoader({
    url: `${GENERAL_HONEYPOT_URI}?onlyActive=true`,
    headers: { "Content-Type": "application/json" },
  });
  console.debug("Feeds-honeypots:", honeypots);

  honeypots.forEach((honeypot) => {
    //check if honeypot.label exist in honeypotFeedsType array or not (index === -1)
    const index = honeypotFeedsType.findIndex((x) => x.label === honeypot);
    if (index === -1)
      honeypotFeedsType.push({
        label: honeypot,
        value: honeypot.toLowerCase(),
      });
  });

  // reset the prioritize dropdown to "recent"
  const handleSortChange = React.useCallback(() => {
    initialValues.prioritize = "recent";
    setUrl(
      `${FEEDS_BASE_URI}/${feedTypePath(initialValues.feeds_type)}/${initialValues.attack_type}/recent.json?ioc_type=${initialValues.ioc_type}`,
    );
    setTableKey((prev) => prev + 1);
  }, [setUrl]);

  // callbacks
  const onSubmit = React.useCallback(
    (values) => {
      try {
        setUrl(
          `${FEEDS_BASE_URI}/${feedTypePath(values.feeds_type)}/${values.attack_type}/${values.prioritize}.json?ioc_type=${values.ioc_type}`,
        );
        initialValues.feeds_type = values.feeds_type;
        initialValues.attack_type = values.attack_type;
        initialValues.ioc_type = values.ioc_type;
        initialValues.prioritize = values.prioritize;

        // Clear any ordering / page query params.
        navigate({ search: "" }, { replace: true });

        // force remount FeedsTable
        setTableKey((prev) => prev + 1);
      } catch (e) {
        console.debug(e);
      }
    },
    [setUrl, navigate],
  );

  return (
    <Container>
      <div className="d-flex justify-content-between">
        <h1>
          Feeds&nbsp;
          <small className="text-muted">{feedsData?.count} total</small>
        </h1>
        <Button
          className="mb-3 mt-auto"
          color="primary"
          outline
          href={FEEDS_LICENSE}
          target="_blank"
        >
          <TbLicense />
          &nbsp;Feeds license
        </Button>
      </div>
      <ContentSection>
        <Row className="mb-4 mt-2 justify-content-between">
          <Col sm={12} md={9}>
            {/* Form */}
            <Loader
              render={() => (
                <Formik initialValues={initialValues} onSubmit={onSubmit}>
                  {(formik) => (
                    <Form>
                      <FormGroup row>
                        <Col sm={12} md={3}>
                          <Label
                            className="form-control-label"
                            htmlFor="Feeds__feeds_type"
                          >
                            Feed type:
                          </Label>
                          <MultiSelectDropdownInput
                            inputId="Feeds__feeds_type"
                            options={honeypotFeedsType}
                            value={
                              formik.values.feeds_type &&
                              formik.values.feeds_type !== "all"
                                ? formik.values.feeds_type
                                    .split(",")
                                    .map((v) =>
                                      honeypotFeedsType.find(
                                        (o) => o.value === v,
                                      ),
                                    )
                                    .filter(Boolean)
                                : []
                            }
                            placeholder="All"
                            onChange={(selected) => {
                              const newFeedsType =
                                selected && selected.length > 0
                                  ? selected.map((o) => o.value).join(",")
                                  : "all";
                              formik.setFieldValue("feeds_type", newFeedsType);
                              onSubmit({
                                ...formik.values,
                                feeds_type: newFeedsType,
                              });
                            }}
                          />
                        </Col>
                        <Col sm={12} md={3}>
                          <Label
                            className="form-control-label"
                            htmlFor="Feeds__attack_type"
                          >
                            Attack type:
                          </Label>
                          <Select
                            id="Feeds__attack_type"
                            name="attack_type"
                            value={initialValues.attack_type}
                            choices={attackTypeChoices}
                            onChange={(e) => {
                              formik.handleChange(e);
                              formik.submitForm();
                            }}
                          />
                        </Col>
                        <Col sm={12} md={3}>
                          <Label
                            className="form-control-label"
                            htmlFor="Feeds__ioc_type"
                          >
                            IOC type:
                          </Label>
                          <Select
                            id="Feeds__ioc_type"
                            name="ioc_type"
                            value={initialValues.ioc_type}
                            choices={iocTypeChoices}
                            onChange={(e) => {
                              formik.handleChange(e);
                              formik.submitForm();
                            }}
                          />
                        </Col>
                        <Col sm={12} md={3}>
                          <Label
                            className="form-control-label"
                            htmlFor="Feeds__prioritize"
                          >
                            Prioritize:
                          </Label>
                          <Select
                            id="Feeds__prioritize"
                            name="prioritize"
                            value={initialValues.prioritize}
                            choices={prioritizationChoices}
                            onChange={(e) => {
                              formik.handleChange(e);
                              formik.submitForm();
                            }}
                          />
                        </Col>
                      </FormGroup>
                    </Form>
                  )}
                </Formik>
              )}
            />
          </Col>
          <Col
            sm={12}
            md={2}
            className="d-flex justify-content-end align-items-end"
          >
            <Button
              className="mb-3"
              color="primary"
              outline
              href={url}
              target="_blank"
            >
              <VscJson />
              &nbsp;Raw data
            </Button>
          </Col>
        </Row>
        {/*Table*/}
        <FeedsTable
          key={tableKey}
          tableParams={{
            feed_type: initialValues.feeds_type,
            attack_type: initialValues.attack_type,
            ioc_type: initialValues.ioc_type,
            prioritize: initialValues.prioritize,
          }}
          onDataLoad={setFeedsData}
          onSortChange={handleSortChange}
        />
      </ContentSection>
    </Container>
  );
}
