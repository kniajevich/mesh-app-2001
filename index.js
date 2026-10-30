const http = require('http');
const https = require('https');
const fs = require('fs');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const promClient = require('prom-client');
const { v4: uuidv4 } = require('uuid');

// Configuration
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const TLS_CERT = process.env.TLS_CERT; // path to cert file
const TLS_KEY = process.env.TLS_KEY;   // path to key file
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const ACK_TIMEOUT_MS = 5000;
const MAX_RETRIES = 3;

// Prometheus metrics
const messagesPublished = new promClient.Counter({
  name: 'ws_event_bus_messages_published_total',
  help: 'Total number of messages published',
});
const messagesDelivered = new promClient.Counter({
  name: 'ws_event_bus_messages_delivered_total',
  help: 'Total number of messages delivered to subscribers',
});
const connectionsOpened = new promClient.Counter({
  name: 'ws_event_bus_connections_opened_total',
  help: 'Total number of WebSocket connections opened',
});
const connectionsClosed = new promClient.Counter({
  name: 'ws_event_bus_connections_closed_total',
  help: 'Total number of WebSocket connections closed',
});
const ackFailures = new promClient.Counter({
  name: 'ws_event_bus_ack_failures_total',
  help: 'Total number of QoS1 messages that failed after retries',
});

// Helper: topic matching with MQTT-like wildcards
function topicMatches(pattern, topic) {
  const patParts = pattern.split('/');
  const topicParts = topic.split('/');
  let i = 0;
  for (; i < patParts.length; i++) {
    const pat = patParts[i];
    const top = topicParts[i];
    if (pat === '#') {
      return true;
    }
    if (pat === '+') {
      if (top === undefined) return false;
      continue;
    }
    if (pat !== top) return false;
  }
  return i === topicParts.length;
}

// ACL check helpers
function canPublish(user, topic) {
  if (!user || !user.publish) return false;
  return user.publish.some((pat) => topicMatches(pat, topic));
}
function canSubscribe(user, topic) {
  if (!user || !user.subscribe) return false;
  return user.subscribe.some((pat) => topicMatches(pat, topic));
}

// Create HTTP or HTTPS server
let server;
if (TLS_CERT && TLS_KEY) {
  const cert = fs.readFileSync(TLS_CERT);
  const key = fs.readFileSync(TLS_KEY);
  server = https.createServer({ cert, key });
} else {
  server = http.createServer();
}

// Metrics endpoint
server.on('request', (req, res) => {
  if (req.url === '/metrics') {
    res.setHeader('Content-Type', promClient.register.contentType);
    res.end(promClient.register.metrics());
  } else {
    res.writeHead(404);
    res.end();
  }
});

// WebSocket server
const wss = new WebSocket.Server({ server });

const clients = new Set();

wss.on('connection', (ws, req) => {
  const clientId = uuidv4();
  ws.id = clientId;
  ws.subscriptions = new Set();
  ws.pending = new Map(); // messageId -> {msg, retries, timeout}
  ws.user = null;

  connectionsOpened.inc();
  console.log(`Client connected: ${clientId}`);

  // Handle authentication via Sec-WebSocket-Protocol or CONNECT message
  const protocols = req.headers['sec-websocket-protocol'];
  if (protocols) {
    const token = protocols.split(',')[0].trim();
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      ws.user = payload;
      console.log(`Client ${clientId} authenticated via protocol`);
      ws.send(JSON.stringify({ type: 'CONNACK', status: 'OK' }));
    } catch (e) {
      console.warn(`Client ${clientId} failed auth via protocol`);
      ws.close(4003, 'Authentication failed');
      return;
    }
  }

  clients.add(ws);

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch (e) {
      console.warn(`Client ${clientId} sent invalid JSON`);
      return;
    }

    switch (msg.type) {
      case 'CONNECT':
        if (ws.user) break; // already authenticated
        if (!msg.token) {
          ws.close(400