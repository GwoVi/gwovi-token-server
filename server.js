import express from 'express';
import cors from 'cors';
import { AccessToken, RoomServiceClient } from 'livekit-server-sdk';

const app = express();
app.use(cors());
app.use(express.json());

// Max people allowed in a room (host + 4 others). Bump this later
// or make it subscription-based when you add paid tiers.
const MAX_PARTICIPANTS = 5;

// Your LiveKit project's HTTPS host, used to query room state.
// This is your wss:// URL with https:// instead.
const LIVEKIT_HOST = 'https://gwovi-thg5bfsf.livekit.cloud';

app.get('/', (req, res) => {
  res.send('GwoVi token server is running.');
});

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

    // --- Capacity check: count who's already in the room ---
    try {
      const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
      const participants = await svc.listParticipants(room);
      if (participants.length >= MAX_PARTICIPANTS) {
        return res.status(403).json({ error: 'Room is full' });
      }
    } catch (capErr) {
      // If the room doesn't exist yet, listParticipants can throw —
      // that just means the room is empty, so we let the join proceed.
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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`GwoVi token server listening on port ${port}`);
});
