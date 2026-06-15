import express from 'express';
import cors from 'cors';
import {
  AccessToken,
  RoomServiceClient,
  EgressClient,
  EncodedFileOutput,
  EncodedFileType,
  EncodingOptionsPreset,
  S3Upload,
} from 'livekit-server-sdk';
import {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const app = express();
app.use(cors());
app.use(express.json());

// ---- Free-tier limits ----
// These are the FREE tier limits. When StoreKit/paid tiers are added later,
// paid users should bypass these (e.g. higher cap, no session timeout).
// Max people allowed in a room (host + 2 others) on the free tier.
const MAX_PARTICIPANTS = 3;
// How long a free-tier session can run before it auto-ends (milliseconds).
const SESSION_LIMIT_MS = 10 * 60 * 1000; // 10 minutes

// Tracks the auto-end timer for each room so we can clear it if the room
// ends early. Note: timers live in memory, so a server restart (e.g. a
// Render redeploy) clears any pending timer. Acceptable for a soft free-tier
// limit; revisit if we ever need hard billing enforcement.
const sessionTimers = {}; // sessionTimers[room] = Timeout

// Your LiveKit project's HTTPS host (wss:// URL with https:// instead).
const LIVEKIT_HOST = 'https://gwovi-thg5bfsf.livekit.cloud';

// ---- In-memory join requests ----
const requests = {}; // requests[room] = { [username]: {status, ts} }

// ---- In-memory event names (host sets when going live) ----
const eventNames = {}; // eventNames[room] = "Baby shower"

// ---- In-memory active recordings ----
const recordings = {}; // recordings[room] = egressId

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

// Arms the free-tier session timer for a room. After SESSION_LIMIT_MS, the
// room is deleted, which disconnects everyone. Clears any existing timer for
// the room first so we don't stack them.
function startSessionTimer(room, apiKey, apiSecret) {
  if (sessionTimers[room]) {
    clearTimeout(sessionTimers[room]);
  }
  sessionTimers[room] = setTimeout(async () => {
    try {
      const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
      await svc.deleteRoom(room);
      console.log(`Session limit reached: ended room ${room}`);
    } catch (e) {
      console.log('Session auto-end note:', e?.message || e);
    }
    delete sessionTimers[room];
    delete recordings[room];
  }, SESSION_LIMIT_MS);
}

// Clears a room's session timer (e.g. when the host leaves early).
function clearSessionTimer(room) {
  if (sessionTimers[room]) {
    clearTimeout(sessionTimers[room]);
    delete sessionTimers[room];
  }
}

// Builds an S3 client pointed at R2. Returns null if creds are missing.
function makeR2Client() {
  const r2AccessKey = process.env.R2_ACCESS_KEY_ID;
  const r2Secret = process.env.R2_SECRET_ACCESS_KEY;
  const r2Endpoint = process.env.R2_ENDPOINT;
  if (!r2AccessKey || !r2Secret || !r2Endpoint) return null;
  return new S3Client({
    region: 'auto',
    endpoint: r2Endpoint,
    credentials: {
      accessKeyId: r2AccessKey,
      secretAccessKey: r2Secret,
    },
  });
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
      canUpdateOwnMetadata: true,
    });

    const token = await at.toJwt();
    res.json({ token });
  } catch (err) {
    console.error('Token error:', err);
    res.status(500).json({ error: 'Failed to create token' });
  }
});

// ---- Start recording (Room Composite -> R2) ----
app.post('/start-recording', async (req, res) => {
  try {
    const { room } = req.body || {};
    if (!room) {
      return res.status(400).json({ error: 'room is required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    const r2AccessKey = process.env.R2_ACCESS_KEY_ID;
    const r2Secret = process.env.R2_SECRET_ACCESS_KEY;
    const r2Endpoint = process.env.R2_ENDPOINT;
    const r2Bucket = process.env.R2_BUCKET;
    if (!r2AccessKey || !r2Secret || !r2Endpoint || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    // Stop any existing recording for this room first (avoid duplicates).
    if (recordings[room]) {
      return res
        .status(409)
        .json({ error: 'A recording is already running for this room' });
    }

    const egressClient = new EgressClient(LIVEKIT_HOST, apiKey, apiSecret);

    // Build the filename so the event name rides along with the file.
    // The gallery parses this back out to show "Event name" + date.
    // Format: {room}/{EventName}__{timestamp}.mp4
    // The double underscore "__" is the separator the app looks for, so a
    // single underscore inside an event name (e.g. "Baby_shower") is safe.
    const stamp = Date.now();
    const rawEvent = (eventNames[room] || '').trim();
    // Keep letters, numbers, spaces, and hyphens; turn anything else into
    // a space; collapse runs of whitespace to single underscores.
    const safeEvent = rawEvent
      .replace(/[^A-Za-z0-9 \-]/g, ' ')
      .replace(/\s+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 60);
    const namePart = safeEvent.length > 0 ? safeEvent : room;
    const filepath = `${room}/${namePart}__${stamp}.mp4`;

    const fileOutput = new EncodedFileOutput({
      fileType: EncodedFileType.MP4,
      filepath: filepath,
      output: {
        case: 's3',
        value: new S3Upload({
          accessKey: r2AccessKey,
          secret: r2Secret,
          bucket: r2Bucket,
          endpoint: r2Endpoint,
          region: 'auto',
          forcePathStyle: true,
        }),
      },
    });

    const info = await egressClient.startRoomCompositeEgress(room, {
      file: fileOutput,
    }, {
      // Record on a PORTRAIT canvas (720 wide x 1280 tall) so an upright
      // phone feed fills the frame instead of being boxed into the center
      // with black bars on the sides. Without this, Egress defaults to a
      // landscape canvas and letterboxes the tall video.
      layout: 'grid',
      encodingOptions: EncodingOptionsPreset.PORTRAIT_H720_30,
    });

    recordings[room] = info.egressId;

    res.json({ ok: true, egressId: info.egressId, filepath: filepath });
  } catch (err) {
    console.error('Start recording error:', err);
    res.status(500).json({ error: 'Failed to start recording' });
  }
});

// ---- Stop recording ----
app.post('/stop-recording', async (req, res) => {
  try {
    const { room } = req.body || {};
    if (!room) {
      return res.status(400).json({ error: 'room is required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    const egressId = recordings[room];
    if (!egressId) {
      return res.status(404).json({ error: 'No active recording for this room' });
    }

    const egressClient = new EgressClient(LIVEKIT_HOST, apiKey, apiSecret);
    await egressClient.stopEgress(egressId);

    delete recordings[room];

    res.json({ ok: true, egressId: egressId });
  } catch (err) {
    console.error('Stop recording error:', err);
    res.status(500).json({ error: 'Failed to stop recording' });
  }
});

// ---- List recordings for a room, with temporary signed playback URLs ----
app.get('/recordings', async (req, res) => {
  try {
    const room = req.query.room;
    if (!room) {
      return res.status(400).json({ error: 'room is required' });
    }

    const r2Bucket = process.env.R2_BUCKET;
    const s3 = makeR2Client();
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    // List everything stored under this room's folder.
    const listed = await s3.send(
      new ListObjectsV2Command({
        Bucket: r2Bucket,
        Prefix: `${room}/`,
      })
    );

    const objects = listed.Contents || [];

    // Keep only the .mp4 video files (skip LiveKit's .json manifests).
    const videos = objects.filter((o) => o.Key && o.Key.endsWith('.mp4'));

    // Newest first.
    videos.sort((a, b) => new Date(b.LastModified) - new Date(a.LastModified));

    // Build a temporary signed URL (valid 1 hour) for each one.
    const out = [];
    for (const v of videos) {
      const url = await getSignedUrl(
        s3,
        new GetObjectCommand({ Bucket: r2Bucket, Key: v.Key }),
        { expiresIn: 3600 }
      );
      out.push({
        key: v.Key,
        url: url,
        size: v.Size,
        modified: v.LastModified,
      });
    }

    res.json({ recordings: out });
  } catch (err) {
    console.error('List recordings error:', err);
    res.status(500).json({ error: 'Failed to list recordings' });
  }
});

// ---- Delete one recording from R2 by its key ----
app.post('/delete-recording', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!key) {
      return res.status(400).json({ error: 'key is required' });
    }

    // Safety guard: only delete a real recording object. It must live inside
    // a room folder (have a "/") and be an .mp4 file. This prevents an empty
    // or malformed key from targeting anything unexpected.
    if (typeof key !== 'string' || !key.includes('/') || !key.endsWith('.mp4')) {
      return res.status(400).json({ error: 'invalid key' });
    }

    const r2Bucket = process.env.R2_BUCKET;
    const s3 = makeR2Client();
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    await s3.send(
      new DeleteObjectCommand({ Bucket: r2Bucket, Key: key })
    );

    res.json({ ok: true, key: key });
  } catch (err) {
    console.error('Delete recording error:', err);
    res.status(500).json({ error: 'Failed to delete recording' });
  }
});

// ---- Host: register (or clear) the event name for a room ----
app.post('/setevent', (req, res) => {
  const { room, event } = req.body || {};
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (event && event.length > 0) {
    eventNames[room] = event;
    // Host just went live -> start the free-tier session countdown.
    if (apiKey && apiSecret) {
      startSessionTimer(room, apiKey, apiSecret);
    }
  } else {
    delete eventNames[room];
    // Host cleared the event (left) -> cancel the countdown.
    clearSessionTimer(room);
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
