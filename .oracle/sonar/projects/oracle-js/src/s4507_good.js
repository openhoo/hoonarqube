// S4507 good: middleware unrelated to error handling mounted.
const app = express();
app.use(express.json());
module.exports = { app };
