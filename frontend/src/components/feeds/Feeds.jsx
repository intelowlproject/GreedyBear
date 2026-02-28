import React from "react";
import { Container, Button, Col, Label, FormGroup, Row } from "reactstrap";
import { VscJson } from "react-icons/vsc";
import { TbLicense } from "react-icons/tb";
import { useLocation } from "react-router-dom";
import { FEEDS_BASE_URI, GENERAL_HONEYPOT_URI } from "../../constants/api";
import {
  ContentSection,
  Select,
  useAxiosComponentLoader,
  useDataTable,
} from "@certego/certego-ui";
import { Form, Formik } from "formik";
import { feedsTableColumns } from "./tableColumns";
import { FEEDS_LICENSE } from "../../constants";

// constants
const feedTypeChoices = [{ label: "All", value: "all" }];

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

const DEFAULT_VALUES = Object.freeze({
  feeds_type: "all",
  attack_type: "all",
  ioc_type: "all",
  prioritize: "recent",
});

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
  console.debug("Feeds-DEFAULT_VALUES", DEFAULT_VALUES);
  const formikRef = React.useRef(null);

  const [feedsState, setFeedsState] = React.useState({
    url: `${FEEDS_BASE_URI}/${DEFAULT_VALUES.feeds_type}/${DEFAULT_VALUES.attack_type}/${DEFAULT_VALUES.prioritize}.json`,
    tableParams: {
      feed_type: DEFAULT_VALUES.feeds_type,
      attack_type: DEFAULT_VALUES.attack_type,
      ioc_type: DEFAULT_VALUES.ioc_type,
      prioritize: DEFAULT_VALUES.prioritize,
    },
    tableKey: 0,
  });

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
  const handleSortChange = React.useCallback(async () => {
    const formik = formikRef.current;
    if (!formik) return;

    await formik.setFieldValue("prioritize", "recent", true);
    await formik.setFieldTouched("prioritize", true, false);
    await formik.submitForm();
  }, []);

  // callbacks
  const onSubmit = React.useCallback((values) => {
    try {
      setFeedsState((prev) => ({
        url: `${FEEDS_BASE_URI}/${values.feeds_type}/${values.attack_type}/${values.prioritize}.json?ioc_type=${values.ioc_type}`,
        tableParams: {
          feed_type: values.feeds_type,
          attack_type: values.attack_type,
          ioc_type: values.ioc_type,
          prioritize: values.prioritize,
        },

        tableKey: prev.tableKey + 1,
      }));
    } catch (e) {
      console.debug(e);
    }
  }, []);

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
                <Formik
                  initialValues={DEFAULT_VALUES}
                  onSubmit={onSubmit}
                  innerRef={formikRef}
                >
                  {(formik) => {
                    return (
                      <Form>
                        <FormGroup row>
                          <Col sm={12} md={3}>
                            <Label
                              className="form-control-label"
                              htmlFor="Feeds__feeds_type"
                            >
                              Feed type:
                            </Label>
                            <Select
                              id="Feeds__feeds_type"
                              name="feeds_type"
                              value={formik.values.feeds_type}
                              choices={feedTypeChoices.concat(
                                honeypotFeedsType,
                              )}
                              onChange={async (e) => {
                                await formik.setFieldValue(
                                  "feeds_type",
                                  e.target.value,
                                  true,
                                );
                                await formik.setFieldTouched(
                                  "feeds_type",
                                  true,
                                  false,
                                );
                                await formik.submitForm();
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
                              value={formik.values.attack_type}
                              choices={attackTypeChoices}
                              onChange={async (e) => {
                                await formik.setFieldValue(
                                  "attack_type",
                                  e.target.value,
                                  true,
                                );
                                await formik.setFieldTouched(
                                  "attack_type",
                                  true,
                                  false,
                                );
                                await formik.submitForm();
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
                              value={formik.values.ioc_type}
                              choices={iocTypeChoices}
                              onChange={async (e) => {
                                await formik.setFieldValue(
                                  "ioc_type",
                                  e.target.value,
                                  true,
                                );
                                await formik.setFieldTouched(
                                  "ioc_type",
                                  true,
                                  false,
                                );
                                await formik.submitForm();
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
                              value={formik.values.prioritize}
                              choices={prioritizationChoices}
                              onChange={async (e) => {
                                await formik.setFieldValue(
                                  "prioritize",
                                  e.target.value,
                                  true,
                                );
                                await formik.setFieldTouched(
                                  "prioritize",
                                  true,
                                  false,
                                );
                                await formik.submitForm();
                              }}
                            />
                          </Col>
                        </FormGroup>
                      </Form>
                    );
                  }}
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
              href={feedsState.url}
              target="_blank"
            >
              <VscJson />
              &nbsp;Raw data
            </Button>
          </Col>
        </Row>
        {/*Table*/}
        <FeedsTable
          key={feedsState.tableKey}
          tableParams={feedsState.tableParams}
          onDataLoad={setFeedsData}
          onSortChange={handleSortChange}
        />
      </ContentSection>
    </Container>
  );
}
