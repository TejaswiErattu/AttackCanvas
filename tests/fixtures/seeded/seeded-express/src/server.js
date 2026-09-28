const app = require("./app");
const { connect } = require("./db");

const port = Number(process.env.PORT ?? 3000);

connect().then(() => {
  app.listen(port, () => console.log(`invoicing api on :${port}`));
});
