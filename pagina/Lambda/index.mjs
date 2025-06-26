import {
  CloudWatchLogsClient,
  StartQueryCommand,
  GetQueryResultsCommand
} from "@aws-sdk/client-cloudwatch-logs";
import {
  DynamoDBClient,
  PutItemCommand
} from "@aws-sdk/client-dynamodb";

const REGION = "eu-north-1";
const logsClient = new CloudWatchLogsClient({ region: REGION });
const ddbClient  = new DynamoDBClient({ region: REGION });

const LOG_GROUP         = "LoginAccessLogs";
const LOG_STREAM        = "WebAppStream";
const IP_BLACKLIST      = "IPBlacklist";
const USER_BLACKLIST    = "UsernameBlacklist";
const IP_THRESHOLD      = 10;
const USER_IP_THRESHOLD = 3;
const TTL_SECONDS       = 600;

export const handler = async (event = {}) => {
  const now = Math.floor(Date.now() / 1000);


  if (event.ip) {
    const ip = event.ip;
    console.info(`Immediate block from payload IP: ${ip}`);

    try {
      await ddbClient.send(new PutItemCommand({
        TableName: IP_BLACKLIST,
        Item: {
          ip:        { S: ip },
          attempts:  { N: "999" },
          blockedAt: { S: new Date().toISOString() }
        }
      }));
      console.info(`IP ${ip} added to ${IP_BLACKLIST}`);
    } catch (err) {
      console.error(`Error blocking IP ${ip}:`, err);
    }

  }


  const startQueryTime = now - 600;
  const query = `
    fields @message, @timestamp
    | parse @message /"ip":"(?<ip>[^"]+)"/
    | parse @message /"failed_attempts":(?<failed_attempts>\\d+)/ 
    | parse @message /"name":"(?<name>[^"]+)"/
    | filter @timestamp >= ${startQueryTime * 1000}
    | sort @timestamp desc
    | limit 500
  `;

  let queryId;
  try {
    const { queryId: qid } = await logsClient.send(new StartQueryCommand({
      logGroupName: LOG_GROUP,
      logStreamNames: [LOG_STREAM],
      startTime: startQueryTime,
      endTime: now,
      queryString: query
    }));
    queryId = qid;
    console.info(`Query started (ID: ${queryId})`);
  } catch (err) {
    console.error("Error starting query:", err);
    return;
  }


  let status = "Running";
  let results = [];

  while (status === "Running" || status === "Scheduled") {
    await new Promise(r => setTimeout(r, 1000));
    const resp = await logsClient.send(new GetQueryResultsCommand({ queryId }));
    status = resp.status;
    if (status === "Complete") {
      results = resp.results || [];
    }
  }

  if (results.length === 0) {
    console.warn("No logs in the last 10 minutes.");
    return;
  }

  console.info(`📊 Retrieved ${results.length} log records`);

  const ipCounts = {};
  const nameToIPs = {};

  for (const rec of results) {
    const ip   = rec.find(f => f.field === "ip")?.value;
    const name = rec.find(f => f.field === "name")?.value;
    const attempts = parseInt(rec.find(f => f.field === "failed_attempts")?.value || "0", 10);

    if (ip) ipCounts[ip] = Math.max(ipCounts[ip] || 0, attempts);
    if (ip && name) {
      if (!nameToIPs[name]) nameToIPs[name] = new Set();
      nameToIPs[name].add(ip);
    }
  }


  for (const [ip, attempts] of Object.entries(ipCounts)) {
    if (attempts > IP_THRESHOLD) {
      console.info(`🚧 Blocking IP ${ip} (attempts: ${attempts})`);
      try {
        await ddbClient.send(new PutItemCommand({
          TableName: IP_BLACKLIST,
          Item: {
            ip:        { S: ip },
            attempts:  { N: attempts.toString() },
            blockedAt: { S: new Date().toISOString() },
          }
        }));
        console.info(` IP ${ip} added to ${IP_BLACKLIST}`);
      } catch (err) {
        console.error(`Error blocking IP ${ip}:`, err);
      }
    }
  }


  for (const [name, ipSet] of Object.entries(nameToIPs)) {
    const ipCount = ipSet.size;
    if (ipCount >= USER_IP_THRESHOLD) {
      const expireat = now + TTL_SECONDS;
      console.info(`🚧 Blocking USER '${name}' (unique IPs: ${ipCount})`);
      try {
        await ddbClient.send(new PutItemCommand({
          TableName: USER_BLACKLIST,
          Item: {
            name:      { S: name },
            ipCount:   { N: ipCount.toString() },
            blockedAt: { S: new Date().toISOString() },
            expireat:  { N: expireat.toString() }
          }
        }));
        console.info(`Username '${name}' added to ${USER_BLACKLIST}`);
      } catch (err) {
        console.error(`Error blocking username '${name}':`, err);
      }
    }
  }
};
