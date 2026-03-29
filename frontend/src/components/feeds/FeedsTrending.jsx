import React from "react";
import axios from "axios";
import {
  Container,
  Button,
  Col,
  Label,
  FormGroup,
  Input,
  Table,
  Alert,
  Spinner,
} from "reactstrap";
import { VscJson } from "react-icons/vsc";
import { MdFilterAltOff } from "react-icons/md";
import { ContentSection, useAxiosComponentLoader } from "@certego/certego-ui";
import { Form, Formik } from "formik";

import { MultiSelectDropdown } from "./MultiSelectDropdown";
import { FEEDS_TRENDING_URI, GENERAL_HONEYPOT_URI } from "../../constants/api";

const DEFAULT_TRENDING_VALUES = Object.freeze({
  feed_type: "all",
  window_minutes: 24 * 60,
  limit: 10,
});

export default function FeedsTrending() {
  const [trendingData, setTrendingData] = React.useState(null);
  const [trendingLoading, setTrendingLoading] = React.useState(false);
  const [trendingError, setTrendingError] = React.useState("");
  const [trendingFilters, setTrendingFilters] = React.useState(
    DEFAULT_TRENDING_VALUES,
  );

  const [honeypots, Loader] = useAxiosComponentLoader({
    url: `${GENERAL_HONEYPOT_URI}?onlyActive=true`,
    headers: { "Content-Type": "application/json" },
  });

  const honeypotFeedsType = React.useMemo(
    () =>
      honeypots.map((honeypot) => ({
        label: honeypot,
        value: honeypot.toLowerCase(),
      })),
    [honeypots],
  );

  const fetchTrending = React.useCallback(async (values) => {
    setTrendingLoading(true);
    setTrendingError("");
    try {
      const response = await axios.get(FEEDS_TRENDING_URI, {
        params: {
          feed_type: values.feed_type,
          window_minutes: values.window_minutes,
          limit: values.limit,
        },
        headers: { "Content-Type": "application/json" },
      });
      setTrendingData(response.data);
    } catch (error) {
      const errMsg =
        error.response?.data?.window_minutes?.[0] ||
        error.response?.data?.feed_type?.[0] ||
        error.response?.data?.limit?.[0] ||
        error.response?.data?.detail ||
        "Failed to fetch trending attackers.";
      setTrendingError(errMsg);
      setTrendingData(null);
    } finally {
      setTrendingLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchTrending(DEFAULT_TRENDING_VALUES);
  }, [fetchTrending]);

  return (
    <Container>
      <ContentSection>
        <div className="d-flex justify-content-between align-items-end mb-3">
          <h1 className="mb-0">
            Trending attackers&nbsp;
            <small className="text-muted">
              {trendingData?.count ?? 0} total
            </small>
          </h1>
          <Button
            color="primary"
            outline
            href={`${FEEDS_TRENDING_URI}?feed_type=${encodeURIComponent(trendingFilters.feed_type)}&window_minutes=${encodeURIComponent(
              trendingFilters.window_minutes,
            )}&limit=${encodeURIComponent(trendingFilters.limit)}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            <VscJson />
            &nbsp;Raw trending data
          </Button>
        </div>

        <Loader
          render={() => (
            <Formik
              initialValues={DEFAULT_TRENDING_VALUES}
              onSubmit={async (values) => {
                const normalizedValues = {
                  ...values,
                  window_minutes: Number(values.window_minutes),
                  limit: Number(values.limit),
                };
                setTrendingFilters(normalizedValues);
                await fetchTrending(normalizedValues);
              }}
            >
              {(formik) => (
                <Form>
                  <FormGroup row className="align-items-end">
                    <Col sm={12} md={5}>
                      <Label
                        className="form-control-label"
                        htmlFor="TrendingPage__feed_type"
                      >
                        Feed type:
                      </Label>
                      <MultiSelectDropdown
                        id="TrendingPage__feed_type"
                        options={honeypotFeedsType}
                        value={
                          formik.values.feed_type &&
                          formik.values.feed_type !== "all"
                            ? formik.values.feed_type
                                .split(",")
                                .map((v) =>
                                  honeypotFeedsType.find((o) => o.value === v),
                                )
                                .filter(Boolean)
                            : []
                        }
                        placeholder="All"
                        onChange={(selected) => {
                          const nextFeedType =
                            selected.length > 0
                              ? selected.map((o) => o.value).join(",")
                              : "all";
                          formik.setFieldValue("feed_type", nextFeedType);
                        }}
                      />
                    </Col>

                    <Col sm={12} md={2}>
                      <Label
                        className="form-control-label"
                        htmlFor="TrendingPage__window_minutes"
                      >
                        Window (minutes):
                      </Label>
                      <Input
                        id="TrendingPage__window_minutes"
                        name="window_minutes"
                        type="number"
                        min={60}
                        step={60}
                        value={formik.values.window_minutes}
                        onChange={formik.handleChange}
                      />
                    </Col>

                    <Col sm={12} md={2}>
                      <Label
                        className="form-control-label"
                        htmlFor="TrendingPage__limit"
                      >
                        Limit:
                      </Label>
                      <Input
                        id="TrendingPage__limit"
                        name="limit"
                        type="number"
                        min={1}
                        max={1000}
                        value={formik.values.limit}
                        onChange={formik.handleChange}
                      />
                    </Col>

                    <Col sm={12} md="auto" className="d-flex gap-2">
                      <Button
                        color="primary"
                        type="submit"
                        disabled={trendingLoading}
                      >
                        {trendingLoading ? (
                          <>
                            <Spinner size="sm" />
                            &nbsp;Loading...
                          </>
                        ) : (
                          "Apply"
                        )}
                      </Button>
                      <Button
                        color="primary"
                        outline
                        disabled={trendingLoading}
                        title="Reset filters"
                        aria-label="Reset filters"
                        onClick={() => {
                          formik.resetForm({
                            values: DEFAULT_TRENDING_VALUES,
                          });
                          setTrendingFilters(DEFAULT_TRENDING_VALUES);
                          fetchTrending(DEFAULT_TRENDING_VALUES);
                        }}
                      >
                        <MdFilterAltOff />
                      </Button>
                    </Col>
                  </FormGroup>
                </Form>
              )}
            </Formik>
          )}
        />

        {trendingError ? (
          <Alert color="danger" className="mt-3 mb-0">
            {trendingError}
          </Alert>
        ) : null}

        {trendingData ? (
          <>
            <div className="small text-muted mt-3">
              Data source: {trendingData.data_source} | Current window:{" "}
              {trendingData.current_window?.start} →{" "}
              {trendingData.current_window?.end}
            </div>
            <Table responsive hover className="mt-2">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Current</th>
                  <th>Previous</th>
                  <th>Delta</th>
                  <th>Growth</th>
                  <th>Current Rank</th>
                  <th>Previous Rank</th>
                  <th>Rank Delta</th>
                </tr>
              </thead>
              <tbody>
                {trendingData.attackers?.length ? (
                  trendingData.attackers.map((attacker) => (
                    <tr key={attacker.attacker_ip}>
                      <td>{attacker.attacker_ip}</td>
                      <td>{attacker.current_interactions}</td>
                      <td>{attacker.previous_interactions}</td>
                      <td>{attacker.interaction_delta}</td>
                      <td>{attacker.growth_score}</td>
                      <td>{attacker.current_rank ?? "-"}</td>
                      <td>{attacker.previous_rank ?? "-"}</td>
                      <td>{attacker.rank_delta ?? "-"}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="text-center text-muted">
                      No trending attackers for current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </>
        ) : null}
      </ContentSection>
    </Container>
  );
}
