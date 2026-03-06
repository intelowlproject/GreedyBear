import React from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
} from "react-simple-maps";
import axios from "axios";
import { useTimePickerStore } from "@certego/certego-ui";
import { FEEDS_STATISTICS_COUNTRIES_URI } from "../../constants/api";
const GEO_URL =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// Normalise country names coming from T-Pot geoip to match the topojson properties.name values
const NAME_FIXES = {
  "United States": "United States of America",
  "Czech Republic": "Czechia",
  "Ivory Coast": "Côte d'Ivoire",
  "Democratic Republic of the Congo": "Dem. Rep. Congo",
  "Republic of the Congo": "Congo",
};

function normalise(name) {
  return NAME_FIXES[name] ?? name;
}

// Interpolate between two hex colours by t ∈ [0, 1]
function lerpColor(a, b, t) {
  const ah = parseInt(a.replace("#", ""), 16);
  const bh = parseInt(b.replace("#", ""), 16);
  const ar = (ah >> 16) & 0xff;
  const ag = (ah >> 8) & 0xff;
  const ab = ah & 0xff;
  const br = (bh >> 16) & 0xff;
  const bg = (bh >> 8) & 0xff;
  const bb = bh & 0xff;
  const rr = Math.round(ar + (br - ar) * t);
  const rg = Math.round(ag + (bg - ag) * t);
  const rb = Math.round(ab + (bb - ab) * t);
  return `rgb(${rr},${rg},${rb})`;
}

const COLOR_EMPTY = "#2a2a3a";
const COLOR_LOW = "#ffffb2";
const COLOR_MID = "#fd8d3c";
const COLOR_HIGH = "#bd0026";

export default function AttackOriginMap() {
  const { range } = useTimePickerStore();
  const [countryData, setCountryData] = React.useState({});
  const [maxCount, setMaxCount] = React.useState(1);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);

  // tooltip state
  const [tooltip, setTooltip] = React.useState({
    visible: false,
    x: 0,
    y: 0,
    name: "",
    count: 0,
  });

  React.useEffect(() => {
    setLoading(true);
    setError(null);
    axios
      .get(FEEDS_STATISTICS_COUNTRIES_URI, { params: { range } })
      .then((resp) => {
        const map = {};
        let max = 1;
        resp.data.forEach(({ country, count }) => {
          const key = normalise(country);
          map[key] = count;
          if (count > max) max = count;
        });
        setCountryData(map);
        setMaxCount(max);
      })
      .catch((err) => {
        console.error("AttackOriginMap error:", err);
        setError("Failed to load map data.");
      })
      .finally(() => setLoading(false));
  }, [range]);

  const getColor = React.useCallback(
    (geoName) => {
      const count = countryData[geoName];
      if (!count) return COLOR_EMPTY;
      const t = Math.sqrt(count / maxCount); // sqrt scale so small values are still visible
      // 3-stop: low (yellow) → mid (orange) → high (red)
      if (t < 0.5) return lerpColor(COLOR_LOW, COLOR_MID, t * 2);
      return lerpColor(COLOR_MID, COLOR_HIGH, (t - 0.5) * 2);
    },
    [countryData, maxCount],
  );

  const handleMouseEnter = (geo, evt) => {
    const name = geo.properties.name;
    const count = countryData[name] ?? 0;
    setTooltip({ visible: true, x: evt.clientX, y: evt.clientY, name, count });
  };

  const handleMouseMove = (evt) => {
    if (tooltip.visible) {
      setTooltip((prev) => ({ ...prev, x: evt.clientX, y: evt.clientY }));
    }
  };

  const handleMouseLeave = () => {
    setTooltip((prev) => ({ ...prev, visible: false }));
  };

  if (loading) {
    return (
      <div
        className="d-flex justify-content-center align-items-center text-muted"
        style={{ height: 320 }}
      >
        Loading map…
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="d-flex justify-content-center align-items-center text-muted"
        style={{ height: 320 }}
      >
        {error}
      </div>
    );
  }

  return (
    <div style={{ position: "relative", userSelect: "none" }}>
      {/* Tooltip */}
      {tooltip.visible && (
        <div
          style={{
            position: "fixed",
            left: tooltip.x + 14,
            top: tooltip.y - 10,
            background: "rgba(20,20,32,0.95)",
            border: "1px solid #444",
            borderRadius: 6,
            padding: "6px 10px",
            pointerEvents: "none",
            zIndex: 9999,
            fontSize: 13,
            color: "#eee",
            whiteSpace: "nowrap",
          }}
        >
          <strong>{tooltip.name}</strong>
          {tooltip.count > 0 ? (
            <>
              <br />
              <span style={{ color: "#ff7070" }}>
                {tooltip.count.toLocaleString()} IOC
                {tooltip.count !== 1 ? "s" : ""}
              </span>
            </>
          ) : (
            <>
              <br />
              <span style={{ color: "#888" }}>No data</span>
            </>
          )}
        </div>
      )}

      {/* Map */}
      <div style={{ maxHeight: 340, overflow: "hidden" }}>
        <ComposableMap
          projection="geoNaturalEarth1"
          style={{ width: "100%", height: "auto", marginTop: -20 }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          <ZoomableGroup zoom={1} minZoom={0.8} maxZoom={6}>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={getColor(geo.properties.name)}
                    stroke="#111"
                    strokeWidth={0.4}
                    onMouseEnter={(evt) => handleMouseEnter(geo, evt)}
                    onMouseLeave={handleMouseLeave}
                    style={{
                      default: { outline: "none" },
                      hover: {
                        outline: "none",
                        fill: "#facc15",
                        transition: "fill 80ms",
                      },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>
      </div>

      {/* Colour-scale legend */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          justifyContent: "flex-end",
          marginTop: 4,
          paddingRight: 8,
          fontSize: 11,
          color: "#aaa",
        }}
      >
        <span>0</span>
        <div
          style={{
            width: 120,
            height: 10,
            borderRadius: 4,
            background: `linear-gradient(to right, ${COLOR_LOW}, ${COLOR_MID}, ${COLOR_HIGH})`,
          }}
        />
        <span>{maxCount.toLocaleString()}</span>
      </div>
    </div>
  );
}
