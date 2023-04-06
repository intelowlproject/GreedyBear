import { BooleanIcon } from "@certego/certego-ui";

// costants
const feedsTableColumns = [
  {
    Header: "Last Seen",
    accessor: "last_seen",
    maxWidth: 80,
  },
  {
    Header: "First Seen",
    accessor: "first_seen",
    maxWidth: 80,
  },
  {
    Header: "Feed type",
    accessor: "feed_type",
    maxWidth: 60,
  },
  {
    Header: "Value",
    accessor: "value",
    maxWidth: 60,
  },
  {
    Header: "Scanner",
    accessor: "scanner",
    Cell: ({ value }) => <BooleanIcon truthy={value} withColors />,
    maxWidth: 60,
  },
  {
    Header: "Payload Request",
    accessor: "payload_request",
    Cell: ({ value }) => <BooleanIcon truthy={value} withColors />,
    maxWidth: 70,
  },
  {
    Header: "Times Seen",
    accessor: "times_seen",
    maxWidth: 60,
  },
];

export { feedsTableColumns };
