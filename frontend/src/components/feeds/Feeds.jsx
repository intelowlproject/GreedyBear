import React from "react";
import { Container, Button, Col, Label, FormGroup } from "reactstrap";
import { FEEDS_BASE_URI } from "../../constants/api";
import {
  ContentSection,
  Select,
  useAxiosComponentLoader,
  useDataTable,
} from "@certego/certego-ui";
import { Form, Formik } from "formik";
import { VscJson } from "react-icons/vsc";
import { GENERAL_HONEYPOT_URI } from "../../constants/api";
import { feedsTableColumns } from "./tableColumns";

// costants
const feedTypeChoices = [
  { label: "All", value: "all" },
  { label: "Log4j", value: "log4j" },
  { label: "Cowrie", value: "cowrie" },
];

const attackTypeChoices = [
  { label: "All", value: "all" },
  { label: "Scanner", value: "scanner" },
  { label: "Payload request", value: "payload_request" },
];

const ageChoices = [
  { label: "Recent", value: "recent" },
  { label: "Persistant", value: "persistent" },
];

const initialValues = {
  feeds_type: "all",
  attack_type: "all",
  age: "recent",
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
    `${FEEDS_BASE_URI}/${initialValues.feeds_type}/${initialValues.attack_type}/${initialValues.age}.json`
  );

  // API to extract general honeypot
  const [honeypots, Loader] = useAxiosComponentLoader({
    url: `${GENERAL_HONEYPOT_URI}?onlyActive=true`,
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

  const [feedsData, tableNode, refetch] = useDataTable(
    {
      url: FEEDS_BASE_URI,
      params: {
        feed_type: initialValues.feeds_type,
        attack_type: initialValues.attack_type,
        age: initialValues.age,
      },
      initialParams: {
        page_size: "10",
        page: "1",
      },
    },
    toPassTableProps,
    (data) => data.results.iocs
  );

  // callbacks
  const onSubmit = React.useCallback(
    (values) => {
      try {
        setUrl(
          `${FEEDS_BASE_URI}/${values.feeds_type}/${values.attack_type}/${values.age}.json`
        );
        initialValues.feeds_type = values.feeds_type;
        initialValues.attack_type = values.attack_type;
        initialValues.age = values.age;
        refetch();
      } catch (e) {
        console.debug(e);
      }
    },
    [setUrl, refetch]
  );

  return (
    <Container>
      <div className="d-flex justify-content-between">
        <h1>
          Feeds&nbsp;
          <small className="text-muted">{feedsData?.count} total</small>
        </h1>
        <Button
          className="mb-auto"
          color="primary"
          outline
          href={url}
          target="_blank"
        >
          <VscJson />
          &nbsp;Raw data
        </Button>
      </div>
      <Loader
        render={() => (
          <ContentSection>
            {/* Form */}
            <Formik initialValues={initialValues} onSubmit={onSubmit}>
              {(formik) => (
                <Form>
                  <FormGroup row>
                    <Col sm={12} md={4}>
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
                        choices={feedTypeChoices.concat(honeypotFeedsType)}
                        onChange={(e) => {
                          formik.handleChange(e);
                          formik.submitForm();
                        }}
                      />
                    </Col>
                    <Col sm={12} md={4}>
                      <Label
                        className="form-control-label"
                        htmlFor="Feeds__attack_type"
                      >
                        Attack type:
                      </Label>
                      <Select
                        id="Feeds__attack_type"
                        name="attack_type"
                        choices={attackTypeChoices}
                        onChange={(e) => {
                          formik.handleChange(e);
                          formik.submitForm();
                        }}
                      />
                    </Col>
                    <Col sm={12} md={4}>
                      <Label
                        className="form-control-label"
                        htmlFor="Feeds__age"
                      >
                        Age:
                      </Label>
                      <Select
                        id="Feeds__age"
                        name="age"
                        choices={ageChoices}
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
          </ContentSection>
        )}
      />
      <ContentSection className="mt-3 bg-dark border border-dark shadow">
        {/*Table*/}
        {tableNode}
      </ContentSection>
    </Container>
  );
}
