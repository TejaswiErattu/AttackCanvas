// Every route file imports its guards from here, never from the files below.
// SEEDED:x-ctl-barrel-login
module.exports = {
  ...require("./session"),
  ...require("./roles"),
};
