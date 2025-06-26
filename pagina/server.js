require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const axios = require('axios');

const {
  CloudWatchLogsClient,
  PutLogEventsCommand,
  CreateLogStreamCommand,
  DescribeLogStreamsCommand
} = require("@aws-sdk/client-cloudwatch-logs");

const {
  CloudWatchClient,
  PutMetricDataCommand
} = require("@aws-sdk/client-cloudwatch");

const {
  DynamoDBClient,
  GetItemCommand
} = require('@aws-sdk/client-dynamodb');

const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const REGION = process.env.AWS_REGION || "eu-north-1";
const LOG_GROUP_NAME = "LoginAccessLogs";
const LOG_STREAM_NAME = "WebAppStream";
const IP_BLACKLIST_TABLE = "IPBlacklist";
const USERNAME_BLACKLIST_TABLE = "UsernameBlacklist";
const PAYLOAD_ENDPOINT = process.env.PAYLOAD_ENDPOINT;

const cloudwatchLogsClient = new CloudWatchLogsClient({ region: REGION });
const cloudwatchMetricsClient = new CloudWatchClient({ region: REGION });
const dynamoClient = new DynamoDBClient({ region: REGION });
const lambdaClient = new LambdaClient({ region: REGION });

let failedAttemptsByIP = {};


function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync('users.json', 'utf8'));
  } catch (err) {
    console.error('Error loading users.json:', err);
    return {};
  }
}


async function isIPBlacklisted(ip) {
  const command = new GetItemCommand({
    TableName: IP_BLACKLIST_TABLE,
    Key: { ip: { S: ip } }
  });
  const result = await dynamoClient.send(command);
  return !!result.Item;
}


async function isUsernameBlacklisted(username) {
  const data = await dynamoClient.send(new GetItemCommand({
    TableName: USERNAME_BLACKLIST_TABLE,
    Key: { name: { S: username } }
  }));
  return !!data.Item;
}


async function invokeBanIPLambda(ip) {
  try {
    const payload = { ip };
    console.log(`Invoking BanIP Lambda with payload: ${JSON.stringify(payload)}`);

    const command = new InvokeCommand({
      FunctionName: 'LetturaBlackListIP',
      Payload: Buffer.from(JSON.stringify(payload)),
    });

    const response = await lambdaClient.send(command);
    const responsePayload = Buffer.from(response.Payload).toString('utf8');
    console.log(`BanIP Lambda response: ${responsePayload}`);

    return JSON.parse(responsePayload);
  } catch (error) {
    console.error("Error invoking BanIP Lambda:", error);
    return null;
  }
}


async function getSequenceToken() {
  const data = await cloudwatchLogsClient.send(new DescribeLogStreamsCommand({
    logGroupName: LOG_GROUP_NAME,
    logStreamNamePrefix: LOG_STREAM_NAME
  }));

  const stream = data.logStreams.find(s => s.logStreamName === LOG_STREAM_NAME);
  if (!stream) {
    await cloudwatchLogsClient.send(new CreateLogStreamCommand({
      logGroupName: LOG_GROUP_NAME,
      logStreamName: LOG_STREAM_NAME
    }));
    return null;
  }
  return stream.uploadSequenceToken || null;
}


const path = require('path');
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});


async function flushLogs() {
  const snapshot = { ...failedAttemptsByIP };
  const ips = Object.keys(snapshot);
  if (!ips.length) return;

  try {
    const sequenceToken = await getSequenceToken();

    const logEvents = [];
    const payloads = [];

    for (const ip of ips) {
      const entry = snapshot[ip];
      if (!entry || (!entry.metricSent && entry.count <= 10)) continue;

      const logMessage = {
        ip,
        failed_attempts: entry.count,
        name: [...entry.usernames][0] || "",
        timestamp: Date.now()
      };

      logEvents.push({
        message: JSON.stringify(logMessage),
        timestamp: Date.now()
      });

      payloads.push(logMessage);
    }

    if (logEvents.length) {
      await cloudwatchLogsClient.send(new PutLogEventsCommand({
        logEvents,
        logGroupName: LOG_GROUP_NAME,
        logStreamName: LOG_STREAM_NAME,
        sequenceToken
      }));
      console.log(`Sent ${logEvents.length} suspicious logs to CloudWatch Logs`);
    }

    if (PAYLOAD_ENDPOINT && payloads.length) {
      try {
        await axios.post(PAYLOAD_ENDPOINT, payloads);
        console.log(`Payload sent to ${PAYLOAD_ENDPOINT}`);
      } catch (err) {
        console.error('Error sending payload:', err.message);
      }
    }

    for (const ip of ips) {
      const entry = snapshot[ip];
      if (entry && (entry.metricSent || entry.count > 10)) {
        delete failedAttemptsByIP[ip];
      }
    }
  } catch (err) {
    console.error('Error sending logs:', err);
  }
}


async function putFailedLoginMetric(ip) {
  const entry = failedAttemptsByIP[ip];
  if (!entry || entry.metricSent) return;

  await cloudwatchMetricsClient.send(new PutMetricDataCommand({
    Namespace: 'LoginSecurity',
    MetricData: [
      {
        MetricName: 'FailedLoginAttempts',
        Dimensions: [{ Name: 'IP', Value: ip }],
        Timestamp: new Date(),
        Unit: 'Count',
        Value: entry.count
      }
    ]
  }));

  entry.metricSent = true;
  console.log(`Metric sent for IP ${ip}`);
}


function cleanupOldEntries() {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; 

  for (const ip in failedAttemptsByIP) {
    const entry = failedAttemptsByIP[ip];
    if (now - entry.lastAttempt > windowMs) {
      delete failedAttemptsByIP[ip];
    }
  }
}

setInterval(flushLogs, 30 * 1000);        
setInterval(cleanupOldEntries, 60 * 1000); 


app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  if (await isIPBlacklisted(ip)) {
    return res.status(403).send("IP is blocked.");
  }

  if (await isUsernameBlacklisted(username)) {
    return res.status(403).send("Username is blocked.");
  }

  const users = loadUsers();
  if (users[username] !== password) {
    if (!failedAttemptsByIP[ip]) {
      failedAttemptsByIP[ip] = {
        count: 1,
        usernames: new Set([username]),
        lastAttempt: Date.now(),
        metricSent: false,
        bannedCalled: false
      };
    } else {
      failedAttemptsByIP[ip].count++;
      failedAttemptsByIP[ip].usernames.add(username);
      failedAttemptsByIP[ip].lastAttempt = Date.now();
    }

    if (failedAttemptsByIP[ip].count > 10) {
      await putFailedLoginMetric(ip);

      if (!failedAttemptsByIP[ip].bannedCalled) {
        await invokeBanIPLambda(ip);
        failedAttemptsByIP[ip].bannedCalled = true;
      }
    }

    return res.status(401).send("Invalid credentials.");
  }

  return res.send("Login successful.");
});

app.listen(3000, () => console.log("Server started on http://localhost:3000"));
