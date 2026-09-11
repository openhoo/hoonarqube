import express from "express";
import helmet from "helmet";

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
export default app;
