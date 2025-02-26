require('dotenv').config();
const env = process.env;
 
const development = {
  username: env.DEV_DB_NAME,
  password: env.DEV_DB_PASSWORD,
  database: env.DEV_DB_NAME,
  host: env.DEV_DB_HOST,
  port: env.DEV_DB_PORT,
  dialect: "postgres",
  dialectOptions: {},
};
 
const production = {
  username: env.PROD_DB_USER,
  password: env.PROD_DB_PASSWORD,
  database: env.PROD_DB_NAME,
  host: env.PROD_DB_HOST,
  port: env.PROD_DB_PORT,
  dialect: "postgres",
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false,
    },
  },
};
 
const test = {
  username: env.TEST_DB_USER,
  password: env.TEST_DB_PASSWORD,
  database: env.TEST_DB_NAME,
  host: env.TEST_DB_HOST,
  port: env.TEST_DB_PORT,
  dialect: "postgres",
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false,
    },
  },
};
 
module.exports = { development, production, test };