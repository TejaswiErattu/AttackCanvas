const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGO_URL);
let db;

async function connect() {
  await client.connect();
  db = client.db();
}

function collection(name) {
  return db.collection(name);
}

module.exports = { connect, collection };
