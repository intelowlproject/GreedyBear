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
    Header: "Value",
    accessor: "value",
    maxWidth: 60,
  },
  {
    Header: "Feed type",
    accessor: "feed_type",
    maxWidth: 60,
    Cell: ({ value }) => (
        Array.isArray(value) ? (
          <ul className="d-flex flex-column text-left" key={value}>
            {value?.map((val, index) => (
              <li
                className="mb-1 pb-2"
                key={index}
                id={val}
              >
                <div className="d-flex align-items-start">
                  {val}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div>{value}</div>
        )
    ),
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
    Header: "Attack Count",
    accessor: "attack_count",
    maxWidth: 60,
  },
];

export { feedsTableColumns };
