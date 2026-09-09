import React from "react";
export function Component({ value }) {
  return <span>{value || "fallback"}</span>;
}
