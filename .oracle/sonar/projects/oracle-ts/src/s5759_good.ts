import { createProxyMiddleware } from "http-proxy-middleware";

export const proxy = createProxyMiddleware({
  target: "http://localhost:9000",
  xfwd: false,
});
