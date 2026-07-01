import express from 'express';
import cors from 'cors';
import {
  AccessToken,
  RoomServiceClient,
  EgressClient,
  EncodedFileOutput,
  EncodedFileType,
  EncodingOptions,
  S3Upload,
} from 'livekit-server-sdk';
import {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const app = express();
app.use(cors());
// Raised limit so base64-encoded snapshot images fit in the JSON body.
app.use(express.json({ limit: '15mb' }));

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

// ---- In-memory host identity per room ----
// The host's LiveKit identity (their username). We capture it when the host
// sets the event (goes live). Needed so that, in Nearby mode, a joiner's
// recording can be composited with the HOST's audio track (the host is the
// one participant left unmuted, so their voice is the shared audio).
const hostNames = {}; // hostNames[room] = "Joseph"

// ---- In-memory Nearby mode flag (host toggles when everyone's in one room) ----
// When ON for a room, the app mutes every joiner's mic at the source to kill
// the speaker->mic echo loop, and joiners' mics stay host-controlled. The
// server just remembers the on/off state per room so newly-arriving joiners
// can be muted on entry too. The actual muting is performed by the host app
// via its room-admin token (see /token below); this flag is the shared
// source of truth the app reads.
const nearbyModes = {}; // nearbyModes[room] = true | false

// ---- In-memory active recordings ----
// CHANGED: each person now records their OWN feed independently, so we track
// one egressId PER username inside each room instead of a single egressId for
// the whole room. Shape: recordings[room] = { [username]: egressId }
const recordings = {}; // recordings[room][username] = egressId

function roomRecordings(room) {
  if (!recordings[room]) recordings[room] = {};
  return recordings[room];
}

// Looks up a participant's published track SIDs (audio + video) from the live
// room state via RoomService. Returns { audioSid, videoSid } (either may be
// undefined if that track isn't published yet). Used for composite recordings
// where we pair a joiner's video with the host's audio in Nearby mode.
// TrackType in the LiveKit protocol: AUDIO === 0, VIDEO === 1.
async function getParticipantTrackSids(svc, room, identity) {
  const result = { audioSid: undefined, videoSid: undefined };
  try {
    const p = await svc.getParticipant(room, identity);
    const tracks = p?.tracks || [];
    for (const t of tracks) {
      const isAudio =
        t.type === 0 || t.type === 'AUDIO' || t.type === 'audio' ||
        t.source === 2 || t.source === 'MICROPHONE' || t.source === 'microphone';
      const isVideo =
        t.type === 1 || t.type === 'VIDEO' || t.type === 'video' ||
        t.source === 1 || t.source === 'CAMERA' || t.source === 'camera';
      if (isAudio && !result.audioSid) result.audioSid = t.sid;
      if (isVideo && !result.videoSid) result.videoSid = t.sid;
    }
  } catch (e) {
    console.log(`Track lookup note for ${identity} in ${room}:`, e?.message || e);
  }
  return result;
}

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
    delete nearbyModes[room];
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

// Turns a raw event name into a filename-safe token. Keeps letters, numbers,
// spaces and hyphens; collapses whitespace to single underscores; trims to a
// reasonable length. Returns '' if nothing usable remains.
function safeToken(raw, max) {
  return (raw || '')
    .replace(/[^A-Za-z0-9 \-]/g, ' ')
    .replace(/\s+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, max || 60);
}

app.get('/', (req, res) => {
  res.send('GwoVi token server is running.');
});

// ---- Token minting ----
// CHANGED: now accepts an optional { isHost } flag. When isHost is true, the
// token additionally carries roomAdmin permission, which is what lets the
// host app mute other participants' mics (Nearby mode). Joiners get the exact
// same grant as before (no roomAdmin), so their join path is unchanged.
app.post('/token', async (req, res) => {
  try {
    const { username, room, isHost } = req.body || {};
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

    // Base grant — identical for host and joiner. This is exactly what every
    // participant received before, so the joiner path is untouched.
    const grant = {
      roomJoin: true,
      room: room,
      canPublish: true,
      canSubscribe: true,
      canUpdateOwnMetadata: true,
    };

    // HOST ONLY: roomAdmin lets this participant mute other participants'
    // tracks (the LiveKit admin mute used by Nearby mode). Only the host ever
    // receives this; joiners never do.
    if (isHost === true) {
      grant.roomAdmin = true;
    }

    at.addGrant(grant);

    const token = await at.toJwt();
    res.json({ token });
  } catch (err) {
    console.error('Token error:', err);
    res.status(500).json({ error: 'Failed to create token' });
  }
});

// ---- Nearby mode: host sets on/off for a room ----
// Body: { room, on }  (on is boolean). The app reads this so newly-arriving
// joiners know whether they should come in muted. The host app performs the
// actual admin-mute of existing participants directly via LiveKit.
app.post('/set-nearby', (req, res) => {
  const { room, on } = req.body || {};
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  nearbyModes[room] = on === true;
  res.json({ ok: true, on: nearbyModes[room] });
});

// ---- Nearby mode: read on/off for a room ----
app.get('/nearby', (req, res) => {
  const room = req.query.room;
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  res.json({ on: nearbyModes[room] === true });
});

// ---- Mute (or unmute) a participant's microphone at the source ----
// Body: { room, identity, muted }  where identity is the participant's LiveKit
// identity (their username) and muted is a boolean.
//
// This is the real echo fix for same-room use: the host (whose app calls this)
// asks the server to mute a joiner's PUBLISHED audio track so that joiner stops
// transmitting entirely. Because it's done server-side via RoomService, it
// mutes the joiner for EVERYONE, killing the speaker->mic feedback loop at its
// origin. Unmute (muted:false) restores their mic.
//
// We find the participant's audio track SID from the server's live view of the
// room, then call mutePublishedTrack. If the participant has no audio track yet
// (e.g. still connecting), we return ok with a note rather than erroring, so
// the host's toggle never appears to "fail" for a transient timing reason.
app.post('/mute-participant', async (req, res) => {
  try {
    const { room, identity, muted } = req.body || {};
    if (!room || !identity || typeof muted !== 'boolean') {
      return res
        .status(400)
        .json({ error: 'room, identity, and muted (boolean) are required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);

    // Look up the participant and their audio track from the live room state.
    let participant;
    try {
      participant = await svc.getParticipant(room, identity);
    } catch (lookupErr) {
      // Participant not found (maybe already left). Not a hard error for the
      // host's toggle — just report it couldn't be applied.
      console.log(
        `Mute lookup note for ${identity} in ${room}:`,
        lookupErr?.message || lookupErr
      );
      return res.json({ ok: true, applied: false, reason: 'participant not found' });
    }

    const tracks = participant?.tracks || [];
    // Find the AUDIO track. In the LiveKit protocol TrackType.AUDIO === 0 and
    // TrackType.VIDEO === 1, so we must match 0 here — matching 1 would grab
    // the VIDEO track and muting that freezes the participant's camera on a
    // stuck frame (which is exactly the bug we're fixing). We also match on the
    // string forms and on source === microphone defensively, in case the SDK
    // surfaces the type differently across versions.
    const audioTrack = tracks.find(
      (t) =>
        t.type === 0 ||
        t.type === 'AUDIO' ||
        t.type === 'audio' ||
        t.source === 2 ||          // TrackSource.MICROPHONE
        t.source === 'MICROPHONE' ||
        t.source === 'microphone'
    );

    if (!audioTrack) {
      // No audio track published yet — nothing to mute this instant. When the
      // track appears, the host can toggle again, or a fresh join re-triggers.
      return res.json({ ok: true, applied: false, reason: 'no audio track yet' });
    }

    await svc.mutePublishedTrack(room, identity, audioTrack.sid, muted);

    res.json({ ok: true, applied: true, muted: muted });
  } catch (err) {
    console.error('Mute participant error:', err);
    res.status(500).json({ error: 'Failed to mute participant' });
  }
});

// ---- Start recording (Participant Egress -> R2) ----
// CHANGED: this now records ONE participant's own feed, not the whole room.
// The app sends { room, username } where username is the person who tapped
// record. Each person records independently, producing a separate file.
// Filename: {room}/{EventName}__{Username}__{timestamp}.mp4
app.post('/start-recording', async (req, res) => {
  try {
    const { room, username } = req.body || {};
    if (!room || !username) {
      return res.status(400).json({ error: 'room and username are required' });
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

    const egressClient = new EgressClient(LIVEKIT_HOST, apiKey, apiSecret);

    // SELF-HEALING: if this person already has a recording entry, it may be a
    // STALE one left behind by a recording that never cleanly stopped (app
    // closed, crashed, or session dropped without hitting /stop-recording).
    // A stale entry would otherwise block this user from EVER recording again
    // until a server restart. So instead of rejecting with 409, we try to stop
    // the old Egress (ignoring errors if it's already dead), clear the stale
    // entry, and continue to start a fresh recording below.
    const roomRecs = roomRecordings(room);
    if (roomRecs[username]) {
      const oldEgressId = roomRecs[username];
      try {
        await egressClient.stopEgress(oldEgressId);
        console.log(
          `Cleared stale recording for ${username} in ${room} (egress ${oldEgressId})`
        );
      } catch (stopErr) {
        // The old Egress is probably already gone — that's fine, we just want
        // the stale entry cleared so this user can record again.
        console.log(
          `Stale recording cleanup note for ${username} in ${room}:`,
          stopErr?.message || stopErr
        );
      }
      delete roomRecs[username];
    }

    // Build the filename so the event name AND the username ride along with the
    // file. The gallery parses the event name back out to show "Event name" +
    // date; the username makes each participant's file identifiable.
    // Format: {room}/{EventName}__{Username}__{timestamp}.mp4
    // The double underscore "__" is the separator the app looks for.
    const stamp = Date.now();
    const safeEvent = safeToken((eventNames[room] || '').trim(), 60);
    const safeUser = safeToken(username, 40);
    const eventPart = safeEvent.length > 0 ? safeEvent : room;
    const userPart = safeUser.length > 0 ? safeUser : 'user';
    const filepath = `${room}/${eventPart}__${userPart}__${stamp}.mp4`;

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

    // Explicit recording dimensions (same as before) so the saved file is a
    // true 9:16 phone-portrait canvas (1080 x 1920) and fills the screen in
    // Apple Photos without black bars.
    const encoding = new EncodingOptions({
      width: 1080,
      height: 1920,
      framerate: 30,
      videoBitrate: 4500, // kbps
      videoCodec: 0,      // H.264 baseline default for broad compatibility
    });

    // Decide which kind of recording to start.
    //
    // NORMAL (Nearby off, OR the recorder is the host): record this one
    // participant's own feed (their video + their own audio) via Participant
    // Egress — exactly as before.
    //
    // NEARBY ON + recorder is a JOINER: the joiner's mic is muted to stop echo,
    // so their own audio is silent. Instead we composite the joiner's VIDEO
    // with the HOST's AUDIO (the host is the one unmuted voice), producing a
    // recording that has sound. This is done via Track Composite Egress.
    const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
    const nearbyOn = nearbyModes[room] === true;
    const hostIdentity = hostNames[room];
    const recorderIsHost =
      hostIdentity && hostIdentity === username;

    let info;
    let usedComposite = false;

    if (nearbyOn && !recorderIsHost && hostIdentity) {
      // Look up the joiner's video track and the host's audio track.
      const joinerTracks = await getParticipantTrackSids(svc, room, username);
      const hostTracks = await getParticipantTrackSids(svc, room, hostIdentity);

      if (joinerTracks.videoSid && hostTracks.audioSid) {
        // Track Composite: joiner video + host audio -> single MP4.
        info = await egressClient.startTrackCompositeEgress(
          room,
          {
            file: fileOutput,
            encodingOptions: encoding,
          },
          {
            audioTrackId: hostTracks.audioSid,
            videoTrackId: joinerTracks.videoSid,
          }
        );
        usedComposite = true;
      }
    }

    if (!info) {
      // Fallback / normal path: record the recorder's own participant feed.
      info = await egressClient.startParticipantEgress(
        room,
        username,
        {
          file: fileOutput,
          encodingOptions: encoding,
        }
      );
    }

    roomRecs[username] = info.egressId;

    res.json({
      ok: true,
      egressId: info.egressId,
      filepath: filepath,
      composite: usedComposite,
    });
  } catch (err) {
    console.error('Start recording error:', err);
    res.status(500).json({ error: 'Failed to start recording' });
  }
});

// ---- Stop recording ----
// CHANGED: stops THIS person's recording only. App sends { room, username }.
app.post('/stop-recording', async (req, res) => {
  try {
    const { room, username } = req.body || {};
    if (!room || !username) {
      return res.status(400).json({ error: 'room and username are required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    const roomRecs = roomRecordings(room);
    const egressId = roomRecs[username];
    if (!egressId) {
      return res.status(404).json({ error: 'No active recording for you in this room' });
    }

    const egressClient = new EgressClient(LIVEKIT_HOST, apiKey, apiSecret);
    // Always clear our in-memory entry, even if the stop call fails — a failed
    // stop usually means the Egress already ended, and keeping a dead entry
    // would block this user's next recording.
    try {
      await egressClient.stopEgress(egressId);
    } catch (stopErr) {
      console.log(
        `Stop recording note for ${username} in ${room}:`,
        stopErr?.message || stopErr
      );
    }
    delete roomRecs[username];

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

    // Keep video files (.mp4) and snapshot images (.jpg/.jpeg); skip LiveKit's
    // .json manifests and anything else.
    const media = objects.filter(
      (o) =>
        o.Key &&
        (o.Key.endsWith('.mp4') ||
          o.Key.endsWith('.jpg') ||
          o.Key.endsWith('.jpeg'))
    );

    // Newest first.
    media.sort((a, b) => new Date(b.LastModified) - new Date(a.LastModified));

    // Build a temporary signed URL (valid 1 hour) for each one.
    const out = [];
    for (const v of media) {
      const url = await getSignedUrl(
        s3,
        new GetObjectCommand({ Bucket: r2Bucket, Key: v.Key }),
        { expiresIn: 3600 }
      );
      const isPhoto = v.Key.endsWith('.jpg') || v.Key.endsWith('.jpeg');
      out.push({
        key: v.Key,
        url: url,
        size: v.Size,
        modified: v.LastModified,
        type: isPhoto ? 'photo' : 'video',
      });
    }

    res.json({ recordings: out });
  } catch (err) {
    console.error('List recordings error:', err);
    res.status(500).json({ error: 'Failed to list recordings' });
  }
});

// ---- Upload a snapshot image (captured on-device) to R2 ----
// Body: { room, event, image }  where image is base64 JPEG (no data: prefix).
// Stored as {room}/{EventName}__{timestamp}.jpg so it appears in the gallery
// alongside videos and is covered by the same 24h auto-delete lifecycle rule.
app.post('/upload-snapshot', async (req, res) => {
  try {
    const { room, event, image } = req.body || {};
    if (!room || !image) {
      return res.status(400).json({ error: 'room and image are required' });
    }

    const r2Bucket = process.env.R2_BUCKET;
    const s3 = makeR2Client();
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    // Decode the base64 image into bytes.
    const buffer = Buffer.from(image, 'base64');
    if (!buffer || buffer.length === 0) {
      return res.status(400).json({ error: 'image could not be decoded' });
    }

    // Same naming convention as recordings: {room}/{EventName}__{timestamp}.jpg
    const safeEvent = (event && String(event).trim()) || 'GwoVi';
    const namePart = safeEvent.replace(/[^a-zA-Z0-9-_ ]/g, '').trim() || 'GwoVi';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const key = `${room}/${namePart}__${stamp}.jpg`;

    await s3.send(
      new PutObjectCommand({
        Bucket: r2Bucket,
        Key: key,
        Body: buffer,
        ContentType: 'image/jpeg',
      })
    );

    res.json({ ok: true, key });
  } catch (err) {
    console.error('Upload snapshot error:', err);
    res.status(500).json({ error: 'Failed to upload snapshot' });
  }
});

// ---- Delete one recording from R2 by its key ----
app.post('/delete-recording', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!key) {
      return res.status(400).json({ error: 'key is required' });
    }

    // Safety guard: only delete a real media object. It must live inside a
    // room folder (have a "/") and be a video (.mp4) or photo (.jpg/.jpeg).
    // This prevents an empty or malformed key from targeting anything
    // unexpected.
    const isMedia =
      key.endsWith('.mp4') || key.endsWith('.jpg') || key.endsWith('.jpeg');
    if (typeof key !== 'string' || !key.includes('/') || !isMedia) {
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
  const { room, event, host } = req.body || {};
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (event && event.length > 0) {
    eventNames[room] = event;
    // Remember who the host is (their LiveKit identity) for composite
    // recordings in Nearby mode. The app sends this when the host goes live.
    if (host && String(host).trim().length > 0) {
      hostNames[room] = String(host).trim();
    }
    // Host just went live -> start the free-tier session countdown.
    if (apiKey && apiSecret) {
      startSessionTimer(room, apiKey, apiSecret);
    }
  } else {
    delete eventNames[room];
    delete hostNames[room];
    // Host cleared the event (left) -> cancel the countdown.
    clearSessionTimer(room);
    // Also clear any leftover recording entries for this room so a fresh
    // session never inherits a stale "already recording" block.
    delete recordings[room];
    // Clear Nearby mode too, so a fresh session starts in normal mode.
    delete nearbyModes[room];
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
