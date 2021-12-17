const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./src/auth_config.json");

const app = express();

const port = process.env.API_PORT || 3001;
const appPort = process.env.SERVER_PORT || 3000;
const appOrigin = authConfig.appOrigin || process.env.appOrigin || `http://localhost:${appPort}`;

if (
  !authConfig.domain ||
  !authConfig.audience ||
  authConfig.audience === "YOUR_API_IDENTIFIER"
) {
  console.log(
    "Exiting: Please make sure that auth_config.json is in place and populated with valid domain and audience values"
  );

  process.exit();
}

app.use(morgan("dev"));
app.use(helmet());
app.use(cors({ origin: appOrigin }));

const checkScopes = permissions => jwtAuthz(permissions);

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
  }),
  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ["RS256"],
});

app.get("/api/external", checkJwt, (req, res) => {
  res.send({
    msg: "Your access token was successfully validated!",
  });
});

app.get("/api/1", checkJwt, (req, res) => {
  const requestedOrg = req.query.organizationID;
  const currentOrg = req.user.org_id;
  console.log("Asking for: " + requestedOrg + ' currentOrg: ' + currentOrg);
  var message = "Asking for: " + requestedOrg;
  if (requestedOrg === currentOrg) {
    message = message + "\n1 - Your access token was successfully validated!";
  } else {
    message = message + "\n1 - You cannot use this endpoint with your current organization!";
    res.status(403).send({ error: message });
  }
  res.send({
    msg: message,
  });
});

app.get("/api/2", checkJwt, (req, res) => {
  res.send({
    msg: "2 - Your access token was successfully validated! - " + req.query.organizationID,
  });
});

app.get("/api/3", checkJwt, (req, res) => {
  res.send({
    msg: "3 - Your access token was successfully validated! - " + req.query.organizationID,
  });
});

app.listen(port, () => console.log(`API Server listening on port ${port}`));
