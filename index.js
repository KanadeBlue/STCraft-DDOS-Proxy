const { createClient, createServer } = require('bedrock-protocol');
const express = require('express');
const http = require('http');
const socketio = require('socket.io');
const Redis = require('redis');
const pino = require('pino');
const dgram = require('dgram');
const { prettyFactory } = require('pino-pretty');

// Proxy configuration
const PROXY_PORT = 19134; // Changed port to 19134
const SERVER_HOST = 'localhost';
const SERVER_PORT = 19133;
const MAX_CONNECTIONS = 50;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 50; // Limit each IP to 50 requests per window
const BAN_THRESHOLD = 100; // Number of connections to ban IP
const BAN_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const PACKET_RATE_LIMIT = 1000; // Max packets per second

const redisClient = Redis.createClient();
const logger = pino(prettyFactory({ colorize: true }));
const udpServer = dgram.createSocket('udp4');
const app = express();
const server = http.createServer(app);
const io = socketio(server);

const connections = {};
const packetCounters = {};
const bannedIps = new Set();
let attackLog = [];

// Function to ban an IP
const banIp = (ip) => {
  redisClient.set(`ban:${ip}`, 'banned', 'PX', BAN_DURATION_MS, (err) => {
    if (err) {
      logger.error(`Failed to ban IP ${ip}: ${err}`);
    } else {
      logger.info(`IP ${ip} banned for ${BAN_DURATION_MS} ms`);
      bannedIps.add(ip);
      io.emit('ban', { ip, duration: BAN_DURATION_MS });
    }
  });
};

// Function to check if an IP is banned
const isIpBanned = (ip, callback) => {
  redisClient.get(`ban:${ip}`, (err, result) => {
    if (err) {
      logger.error(`Failed to check ban status for IP ${ip}: ${err}`);
      callback(false);
    } else {
      callback(result === 'banned');
    }
  });
};

// Function to increment packet count
const incrementPacketCount = (ip) => {
  if (!packetCounters[ip]) {
    packetCounters[ip] = 1;
    setTimeout(() => delete packetCounters[ip], 1000);
  } else {
    packetCounters[ip]++;
  }
  return packetCounters[ip];
};

const proxy = createServer({
  host: '0.0.0.0',
  port: PROXY_PORT,
  version: '1.16.220',
});

proxy.on('login', (client) => {
  const clientIp = client.getAddress();

  isIpBanned(clientIp, (isBanned) => {
    if (isBanned) {
      client.disconnect('Your IP is banned');
      return;
    }

    if (connections[clientIp]) {
      connections[clientIp]++;
    } else {
      connections[clientIp] = 1;
    }

    if (connections[clientIp] > MAX_CONNECTIONS) {
      banIp(clientIp);
      client.disconnect('Too many connections');
      return;
    }

    const server = createClient({
      host: SERVER_HOST,
      port: SERVER_PORT,
      username: client.username,
      version: client.version,
    });

    client.on('packet', (packet, meta) => {
      if (server.state === 'play' && meta.name === 'play_status') {
        server.write(meta.name, packet);
      }
    });

    server.on('packet', (packet, meta) => {
      if (client.state === 'play' && meta.name === 'play_status') {
        client.write(meta.name, packet);
      }
    });

    const cleanup = () => {
      connections[clientIp]--;
      if (connections[clientIp] === 0) {
        delete connections[clientIp];
      }
    };

    client.on('end', cleanup);
    server.on('end', cleanup);

    client.on('error', (err) => {
      logger.error('Client Error:', err);
      server.disconnect('Error');
      cleanup();
    });

    server.on('error', (err) => {
      logger.error('Server Error:', err);
      client.disconnect('Error');
      cleanup();
    });
  });

  io.emit('login', { ip: clientIp, username: client.username });
});

udpServer.on('message', (msg, rinfo) => {
  const clientIp = rinfo.address;

  if (incrementPacketCount(clientIp) > PACKET_RATE_LIMIT) {
    banIp(clientIp);
    attackLog.push({ ip: clientIp, type: 'UDP Flood', timestamp: new Date() });
    io.emit('attack', { ip: clientIp, type: 'UDP Flood', timestamp: new Date() });
  }
});

udpServer.on('error', (err) => {
  logger.error(`UDP Server Error: ${err}`);
});

udpServer.bind(PROXY_PORT);

// Web server setup
app.use(express.static('public'));

app.get('/api/attacks', (req, res) => {
  res.json(attackLog);
});

app.get('/api/banned', (req, res) => {
  res.json(Array.from(bannedIps));
});

server.listen(3000, () => {
  console.log('Web server listening on port 3000');
});

console.log(`Proxy listening on port ${PROXY_PORT}`);
