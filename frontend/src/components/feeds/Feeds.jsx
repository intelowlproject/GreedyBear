import React from "react";
import { Container, Button, Col, Label, FormGroup, Row } from "reactstrap";
import { VscJson } from "react-icons/vsc";
import { TbLicense } from "react-icons/tb";
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

// costants
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

const initialValues = {
  feeds_type: "all",
  attack_type: "all",
  ioc_type: "all",
  prioritize: "recent",
};

const initialState = {
  pageIndex: 0,
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

let honeypotFeedsType = [];

export default function Feeds() {
  console.debug("Feeds rendered!");

  console.debug("Feeds-initialValues", initialValues);

  const [url, setUrl] = React.useState(
    `${FEEDS_BASE_URI}/${initialValues.feeds_type}/${initialValues.attack_type}/${initialValues.prioritize}.json`,
  );

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

  const [feedsData, tableNode, , tableStateReducer] = useDataTable(
    {
      url: FEEDS_BASE_URI,
      params: {
        feed_type: initialValues.feeds_type,
        attack_type: initialValues.attack_type,
        ioc_type: initialValues.ioc_type,
        prioritize: initialValues.prioritize,
      },
      initialParams: {
        page: "1",
      },
    },
    toPassTableProps,
    (data) => data.results.iocs,
  );

  // callbacks
  const onSubmit = React.useCallback(
    (values) => {
      try {
        setUrl(
          `${FEEDS_BASE_URI}/${values.feeds_type}/${values.attack_type}/${values.prioritize}.json?ioc_type=${values.ioc_type}`,
        );
        initialValues.feeds_type = values.feeds_type;
        initialValues.attack_type = values.attack_type;
        initialValues.ioc_type = values.ioc_type;
        initialValues.prioritize = values.prioritize;

        const resetPage = {
          type: "gotoPage",
          pageIndex: 0,
        };
        tableStateReducer(initialState, resetPage);
      } catch (e) {
        console.debug(e);
      }
    },
    [setUrl, tableStateReducer],
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
                          <Select
                            id="Feeds__feeds_type"
                            name="feeds_type"
                            value={initialValues.feeds_type}
                            choices={feedTypeChoices.concat(honeypotFeedsType)}
                            onChange={(e) => {
                              formik.handleChange(e);
                              formik.submitForm();
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
        {tableNode}
      </ContentSection>
    </Container>
  );
}
