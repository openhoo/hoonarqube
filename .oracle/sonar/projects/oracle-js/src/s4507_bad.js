// S4507 bad: error-handling middleware mounted outside debug guards.
const app = express();
app.use(errorHandler);
module.exports = { app };
