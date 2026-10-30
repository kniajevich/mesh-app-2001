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
          ws.close(4003, 'Authentication failed');
          return;
        }
        try {
          const payload = jwt.verify(msg.token, JWT_SECRET);
          ws.user = payload;
          console.log(`Client ${clientId} authenticated via CONNECT`);
          ws.send(JSON.stringify({ type: 'CONNACK', status: 'OK' }));
        } catch (e) {
          console.warn(`Client ${clientId} failed auth via CONNECT`);
          ws.close(4003, 'Authentication failed');
          return;
        }
        break;

      case 'SUBSCRIBE':
        if (!ws.user) {
          ws.send(JSON.stringify({ type: 'SUBACK', status: 'DENIED', reason: 'Not authenticated' }));
          return;
        }
        if (!Array.isArray(msg.topics)) {
          ws.send(JSON.stringify({ type: 'SUBACK', status: 'ERROR', reason: 'Invalid topics' }));
          return;
        }
        const granted = [];
        for (const topic of msg.topics) {
          if (canSubscribe(ws.user, topic)) {
            ws.subscriptions.add(topic);
            granted.push({ topic, qos: 1 });
          } else {
            granted.push({ topic, qos: 0, reason: 'Access denied' });
          }
        }
        ws.send(JSON.stringify({ type: 'SUBACK', status: 'OK', granted }));
        break;

      case 'UNSUBSCRIBE':
        if (!Array.isArray(msg.topics)) return;
        for (const topic of msg.topics) {
          ws.subscriptions.delete(topic);
        }
        ws.send(JSON.stringify({ type: 'UNSUBACK', status: 'OK' }));
        break;

      case 'PUBLISH':
        if (!ws.user) {
          ws.send(JSON.stringify({ type: 'PUBACK', status: 'DENIED', reason: 'Not authenticated' }));
          return;
        }
        if (!msg.topic || !msg.payload) {
          ws.send(JSON.stringify({ type: 'PUBACK', status: 'ERROR', reason: 'Missing topic or payload' }));
          return;
        }
        if (!canPublish(ws.user, msg.topic)) {
          ws.send(JSON.stringify({ type: 'PUBACK', status: 'DENIED', reason: 'Access denied' }));
          return;
        }

        messagesPublished.inc();
        const messageId = msg.messageId || uuidv4();
        const qos = msg.qos || 0;

        // Deliver to all subscribed clients
        for (const client of clients) {
          if (client === ws) continue;
          if (!client.user) continue;
          for (const sub of client.subscriptions) {
            if (topicMatches(sub, msg.topic)) {
              const delivery = {
                type: 'PUBLISH',
                topic: msg.topic,
                payload: msg.payload,
                qos: qos,
                messageId: messageId,
                timestamp: Date.now()
              };
              client.send(JSON.stringify(delivery));
              messagesDelivered.inc();

              if (qos === 1) {
                // Track pending ACK
                const timeout = setTimeout(() => {
                  const pending = client.pending.get(messageId);
                  if (pending) {
                    pending.retries++;
                    if (pending.retries >= MAX_RETRIES) {
                      ackFailures.inc();
                      client.pending.delete(messageId);
                      console.warn(`ACK timeout for message ${messageId} to client ${client.id}`);
                    } else {
                      // Resend
                      client.send(JSON.stringify(delivery));
                    }
                  }
                }, ACK_TIMEOUT_MS);

                client.pending.set(messageId, { msg: delivery, retries: 0, timeout });
              }
              break; // Only deliver once per client even if multiple subs match
            }
          }
        }

        if (qos === 1) {
          ws.send(JSON.stringify({ type: 'PUBACK', status: 'OK', messageId }));
        }
        break;

      case 'PUBACK':
        if (msg.messageId) {
          const pending = ws.pending.get(msg.messageId);
          if (pending) {
            clearTimeout(pending.timeout);
            ws.pending.delete(msg.messageId);
          }
        }
        break;

      default:
        console.warn(`Client ${clientId} sent unknown message type: ${msg.type}`);
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    connectionsClosed.inc();
    // Clear any pending timeouts
    for (const [id, pending] of ws.pending) {
      clearTimeout(pending.timeout);
    }
    ws.pending.clear();
    console.log(`Client disconnected: ${clientId}`);
  });

  ws.on('error', (err) => {
    console.error(`WebSocket error for client ${clientId}:`, err.message);
  });
});

server.listen(PORT, () => {
  console.log(`WebSocket Event Bus server listening on port ${PORT}`);
});