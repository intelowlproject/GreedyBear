import React from "react";
import { ContentSection } from "@certego/certego-ui";
import { Spinner } from "reactstrap";
import { PUBLIC_URL } from "../../constants/environment";

export const NewsWidget = React.memo(() => {
  const [data, setData] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);

  const parseDate = (dateStr) => {
    try {
      // removing the  ordinal suffixes like st, nd, rd, th from day numbers
      const cleaned = dateStr.replace(/(\d+)(st|nd|rd|th)/, "$1");
      const parsed = new Date(cleaned);

      // checking if date is valid
      return isNaN(parsed.getTime()) ? new Date(0) : parsed;
    } catch (e) {
      console.error("Error parsing date:", dateStr, e);
      return new Date(0);
    }
  };

  React.useEffect(() => {
    fetch(`${PUBLIC_URL}/news.json`)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((newsData) => {
        const filtered = newsData
          .filter((item) => item.project === "greedybear")
          .sort((a, b) => parseDate(b.date) - parseDate(a.date));
        setData(filtered);
      })
      .catch((err) => {
        console.error("Error fetching news:", err);
        setError(true);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  // loading state
  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <Spinner size="sm" className="me-2" />
        <span className="text-muted">Loading news...</span>
      </div>
    );
  }

  // error state
  if (error) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <span className="text-muted">
          Unable to load news. Please try again later.
        </span>
      </div>
    );
  }

  // empty state
  if (data.length === 0) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <span className="text-muted">No news available at the moment.</span>
      </div>
    );
  }

  return (
    <>
      {data.map((item) => (
        <ContentSection
          key={item.id || item.title}
          className="border-dark bg-body mb-3"
        >
          <small className="text-muted float-end">{item.date}</small>
          <h5 className="text-secondary">{item.title}</h5>
          <p className="mb-2 text-muted">{item.subText}</p>
          <a
            className="link-ul-primary"
            href={item.link}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`Read more about ${item.title}`}
          >
            Read more
          </a>
        </ContentSection>
      ))}
    </>
  );
});
