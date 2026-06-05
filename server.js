import express from 'express';
import cors from 'cors';
import { AccessToken, RoomServiceClient } from 'livekit-server-sdk';

const app = express();
app.use(cors());
app.use(express.json());

// Max people allowed in a room (host + 4 others).
const MAX_PARTICIPANTS = 5;

// Your LiveKit project's HTTPS host (wss:// URL with https:// instead).
const LIVEKIT_HOST = 'https://gwovi-thg5bfsf.livekit.cloud';

// ---- In-memory join requests ----
const requests = {}; // requests[room] = { [username]: {status, ts} }

// ---- In-memory event names (host sets when going live) ----
const eventNames = {}; // eventNames[room] = "Baby shower"

function roomRequests(room) {
  if (!requests[room]) requests[room] = {};
  return requests[room];
}

function pruneOld(room) {
  const now = Date.now();
  const list = roomRequests(room);
  for (const name of Object.keys(list)) {
    if (now - list[name].ts > 120000) {
      delete list[name];
    }
  }
}

app.get('/', (req, res) => {
  res.send('GwoVi token server is running.');
});

// ---- Token minting ----
app.post('/token', async (req, res) => {
  try {
    const { username, room } = req.body || {};
    if (!username || !room) {
      return res.status(400).json({ error: 'username and room are required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    try {
      const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
      const participants = await svc.listParticipants(room);
      if (participants.length >= MAX_PARTICIPANTS) {
        return res.status(403).json({ error: 'Room is full' });
      }
    } catch (capErr) {
      console.log('Capacity check note:', capErr?.message || capErr);
    }

    const at = new AccessToken(apiKey, apiSecret, {
      identity: username,
      name: username,
      ttl: '6h',
    });
    at.addGrant({
      roomJoin: true,
      room: room,
      canPublish: true,
      canSubscribe: true,
    });

    const token = await at.toJwt();
    res.json({ token });
  } catch (err) {
    console.error('Token error:', err);
    res.status(500).json({ error: 'Failed to create token' });
  }
});

// ---- Host: register (or clear) the event name for a room ----
app.post('/setevent', (req, res) => {
  const { room, event } = req.body || {};
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  if (event && event.length > 0) {
    eventNames[room] = event;
  } else {
    delete eventNames[room];
  }
  res.json({ ok: true });
});

// ---- Joiner: read the event name before joining ----
app.get('/event', (req, res) => {
  const room = req.query.room;
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  res.json({ event: eventNames[room] || '' });
});

// ---- Joiner: ask to join ----
app.post('/request', (req, res) => {
  const { username, room } = req.body || {};
  if (!username || !room) {
    return res.status(400).json({ error: 'username and room are required' });
  }
  pruneOld(room);
  const list = roomRequests(room);
  list[username] = { status: 'pending', ts: Date.now() };
  res.json({ ok: true });
});

// ---- Host: see pending requests ----
app.get('/pending', (req, res) => {
  const room = req.query.room;
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  pruneOld(room);
  const list = roomRequests(room);
  const pending = Object.keys(list)
    .filter((name) => list[name].status === 'pending')
    .map((name) => ({ username: name }));
  res.json({ pending });
});

// ---- Host: approve/deny ----
app.post('/approve', (req, res) => {
  const { username, room, approve } = req.body || {};
  if (!username || !room) {
    return res.status(400).json({ error: 'username and room are required' });
  }
  const list = roomRequests(room);
  if (!list[username]) {
    return res.status(404).json({ error: 'no such request' });
  }
  list[username].status = approve === false ? 'denied' : 'approved';
  list[username].ts = Date.now();
  res.json({ ok: true, status: list[username].status });
});

// ---- Joiner: check approval status ----
app.get('/check', (req, res) => {
  const { room, username } = req.query;
  if (!room || !username) {
    return res.status(400).json({ error: 'room and username are required' });
  }
  const list = roomRequests(room);
  const entry = list[username];
  const status = entry ? entry.status : 'none';
  res.json({ status });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`GwoVi token server listening on port ${port}`);
});
