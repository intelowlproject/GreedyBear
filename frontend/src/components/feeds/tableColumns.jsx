import { UncontrolledPopover, PopoverBody } from "reactstrap";
import { FiInfo } from "react-icons/fi";
import { BooleanIcon, IconButton } from "@certego/certego-ui";


const formatInteger = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return Number(value).toLocaleString();
};

// required for recurrence value
const formatPercent = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return `${(Number(value) * 100).toFixed(1)}%`;
};

// constants
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
    Cell: ({ value }) =>
      Array.isArray(value) ? (
        <ul className="d-flex flex-column text-left" key={value}>
          {value?.map((val, index) => (
            <li className="mb-1 pb-2" key={index} id={val}>
              <div className="d-flex align-items-start">{val}</div>
            </li>
          ))}
        </ul>
      ) : (
        <div>{value}</div>
      ),
  },
  {
    Header: "Attack Count",
    accessor: "attack_count",
    maxWidth: 60,
  },
  {
    Header: "Details",
    accessor: "details",
    Cell: ({ row }) => {
      const {
        scanner,
        payload_request,
        recurrence_probability,
        expected_interactions,
        interaction_count,
        destination_port_count,
        login_attempts,
        asn,
        ip_reputation,
      } = row.original;
      const popoverId = `feeds-details-${row.id}`;
      return (
        <div className="d-flex justify-content-center">
          <IconButton
            id={popoverId}
            color="light"
            outline
            size="xs"
            Icon={FiInfo}
          />
          <UncontrolledPopover
            trigger="hover"
            target={popoverId}
            placement="left"
            className="feeds-details-popover"
          >
            <PopoverBody className="small">
              <div className="text-muted">Scores</div>
              <div>Recurrence: {formatPercent(recurrence_probability)}</div>
              <div>Expected: {formatInteger(Math.round(expected_interactions))}</div>
              <hr className="my-2" />
              <div className="text-muted">Activity</div>
              <div>Interactions: {formatInteger(interaction_count)}</div>
              <div>Ports: {formatInteger(destination_port_count)}</div>
              <div>Logins: {formatInteger(login_attempts)}</div>
              <hr className="my-2" />
              <div className="text-muted">Enrichment</div>
              <div>ASN: {formatInteger(asn)}</div>
              <div>Reputation: {ip_reputation || "-"}</div>
              <hr className="my-2" />
              <div className="text-muted">Flags</div>
              <div className="d-flex align-items-center">
                <span className="me-2">Scanner</span>
                <BooleanIcon truthy={scanner} withColors />
              </div>
              <div className="d-flex align-items-center">
                <span className="me-2">Payload</span>
                <BooleanIcon truthy={payload_request} withColors />
              </div>
            </PopoverBody>
          </UncontrolledPopover>
        </div>
      );
    },
    maxWidth: 60,
  },
];

export { feedsTableColumns };
