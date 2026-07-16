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
  WebhookReceiver,
} from 'livekit-server-sdk';
import {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  PutObjectCommand,
  CopyObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const app = express();
app.use(cors());

// ---- LiveKit webhook receiver ----
// LiveKit signs each webhook request with the project's API key/secret. The
// WebhookReceiver verifies that signature so we KNOW a teardown request really
// came from LiveKit (and not a random POST to our public URL). Created once
// here and reused by the /livekit-webhook route below.
//
// IMPORTANT: the webhook route is registered a few lines down, BEFORE the
// global express.json() parser, because LiveKit signs the RAW request body.
// If express.json() consumed the body first, signature verification would fail.
const webhookReceiver = new WebhookReceiver(
  process.env.LIVEKIT_API_KEY,
  process.env.LIVEKIT_API_SECRET
);

// ---- Force-end a room's in-memory state (shared cleanup) ----
// Clears every piece of in-memory state we track for a room, plus any pending
// session timer. Used by BOTH the manual /end-room kill switch and the
// automatic /livekit-webhook teardown, so the two can never drift apart.
// Note: this does NOT call deleteRoom — callers decide whether the LiveKit
// room still needs deleting (the webhook path doesn't, since LiveKit already
// finished the room; the manual path does).
function clearRoomState(room) {
  clearSessionTimer(room);
  delete eventNames[room];
  delete hostNames[room];
  delete nearbyModes[room];
  delete recordings[room];
  delete requests[room];
  delete sessionTimers[room];
}

// Stops any Egress recordings we still have tracked for a room. Best-effort:
// a failed stop almost always means that Egress already ended on its own, so
// we log and move on. Used by the webhook teardown so a room ending doesn't
// leave orphaned recordings running (which would burn Egress minutes).
async function stopRoomRecordings(room, apiKey, apiSecret) {
  const recs = recordings[room];
  if (!recs) return;
  const ids = Object.values(recs);
  if (ids.length === 0) return;
  try {
    const egressClient = new EgressClient(LIVEKIT_HOST, apiKey, apiSecret);
    for (const egressId of ids) {
      try {
        await egressClient.stopEgress(egressId);
        console.log(`Webhook teardown: stopped egress ${egressId} in ${room}`);
      } catch (e) {
        console.log(
          `Webhook teardown: egress ${egressId} stop note:`,
          e?.message || e
        );
      }
    }
  } catch (e) {
    console.log('Webhook teardown: egress client note:', e?.message || e);
  }
}

// ---- LiveKit webhook endpoint (AUTO session teardown) ----
// LiveKit POSTs here when room events happen (we subscribed to room_finished
// in the LiveKit Cloud dashboard). When a room FINISHES — which LiveKit fires
// after the room empties out past its empty-timeout, or when a room is deleted
// — we clear all our in-memory state for it and stop any lingering recordings.
// This is the reliable auto-end that a solo/Home session (which never arms the
// in-memory session timer) previously lacked, and it survives Render redeploys
// because it doesn't depend on any in-memory timer being alive.
//
// This route MUST be registered before app.use(express.json()) and use a raw
// body parser, because the signature is computed over the raw bytes.
app.post(
  '/livekit-webhook',
  express.raw({ type: '*/*' }),
  async (req, res) => {
    try {
      // req.body is a Buffer here (raw parser). The receiver needs the raw
      // string body plus the Authorization header to verify the signature.
      const event = await webhookReceiver.receive(
        req.body.toString('utf8'),
        req.get('Authorization')
      );

      // We only act on room_finished. Every other event (participant joined/
      // left, track published, egress updates, etc.) is acknowledged and
      // ignored so LiveKit doesn't retry it.
      if (event?.event === 'room_finished') {
        const room = event?.room?.name;
        if (room) {
          const apiKey = process.env.LIVEKIT_API_KEY;
          const apiSecret = process.env.LIVEKIT_API_SECRET;

          // GUARD AGAINST FALSE TEARDOWN.
          // LiveKit Cloud fires room_finished when a room hits its empty-timeout,
          // which can happen during a brief network blip or right as phones are
          // reconnecting between tests — NOT only when everyone has truly left.
          // Blindly wiping state here was the root cause of Nearby mute silently
          // resetting mid-session: nearbyModes[room] and hostNames[room] got
          // erased, the joiner's app self-restored its mic on reconnect, and by
          // record-time the server saw nearbyFlag=off / clientSaysMuted=false =>
          // no composite => silent joiner recording. So before tearing anything
          // down we ASK LiveKit whether the room is actually empty right now. If
          // anyone is still connected (or has already reconnected), this was a
          // false alarm: we keep all state and let the session continue.
          let activeCount = 0;
          if (apiKey && apiSecret) {
            try {
              const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
              const participants = await svc.listParticipants(room);
              activeCount = Array.isArray(participants) ? participants.length : 0;
            } catch (e) {
              // If the room truly no longer exists, listParticipants throws —
              // that means it IS empty/gone, so activeCount stays 0 and we tear
              // down normally below.
              activeCount = 0;
            }
          }

          if (activeCount > 0) {
            console.log(
              `Webhook: room_finished for ${room} IGNORED — ${activeCount} ` +
              `participant(s) still connected (false teardown, keeping state alive).`
            );
          } else {
            console.log(
              `Webhook: room_finished for ${room} — room is empty, tearing down.`
            );
            if (apiKey && apiSecret) {
              await stopRoomRecordings(room, apiKey, apiSecret);
            }
            clearRoomState(room);
          }
        }
      }

      // Always 200 so LiveKit marks the delivery successful.
      res.status(200).json({ ok: true });
    } catch (err) {
      // A verification failure (bad/forged signature) or any parsing error
      // lands here. Respond 200 anyway so LiveKit doesn't hammer us with
      // retries for something we can't process; we just log it.
      console.log('Webhook receive note:', err?.message || err);
      res.status(200).json({ ok: false });
    }
  }
);

// Raised limit so base64-encoded snapshot images fit in the JSON body.
// NOTE: this JSON parser is registered AFTER the webhook route above, so it
// never touches the webhook's raw body.
app.use(express.json({ limit: '15mb' }));

// ---- Free-tier limits ----
// These are the FREE tier limits. When StoreKit/paid tiers are added later,
// paid users should bypass these (e.g. higher cap, no session timeout).
// Parent prefix for all recordings/snapshots in R2: recordings/{room}/...
// Scoping the 24h auto-delete lifecycle rule to this prefix lets recordings
// expire on schedule while preserved abuse evidence under reports/ survives.
const RECORDINGS_PREFIX = 'recordings/';

// Max people allowed in a room (host + 2 others) on the free tier.
const MAX_PARTICIPANTS = 3;
// How long a free-tier session can run before it auto-ends (milliseconds).
const SESSION_LIMIT_MS = 10 * 60 * 1000; // 10 minutes

// Tracks the auto-end timer for each room so we can clear it if the room
// ends early. Note: timers live in memory, so a server restart (e.g. a
// Render redeploy) clears any pending timer. Acceptable for a soft free-tier
// limit; revisit if we ever need hard billing enforcement. The webhook
// teardown above does NOT depend on these timers, so it works even after a
// redeploy wipes them.
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
const nearbyModes = {}; // nearbyModes[room] = 'off' | 'soft' | 'hard'

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

// Reads a participant's InstallID out of their published LiveKit metadata.
// Every participant publishes { installId, event? } as JSON metadata (see the
// app's StreamManager). We look up the participant by identity (their username)
// and pull installId back out. Returns null if not found or not published yet.
// Used at record time to stamp the recorder's and host's InstallID onto the
// recording, so the gallery can hide a blocked person's recordings exactly
// (by InstallID) rather than by their collision-prone username.
async function getParticipantInstallId(svc, room, identity) {
  if (!identity) return null;
  try {
    const p = await svc.getParticipant(room, identity);
    const meta = p?.metadata;
    if (!meta) return null;
    const parsed = JSON.parse(meta);
    return typeof parsed?.installId === 'string' ? parsed.installId : null;
  } catch (e) {
    console.log(`InstallId lookup note for ${identity} in ${room}:`, e?.message || e);
    return null;
  }
}

// Returns the SID of a LIVE, UNMUTED microphone audio track published by some
// participant in the room OTHER than excludeIdentity (the muted joiner who is
// recording). Also returns the identity that owns it.
//
// This is the fix for silent joiner recordings after solo/session reuse: the
// stored hostNames[room] can go stale (point at a host who already left), so a
// composite that trusts it grabs a dead track SID and records silence. Instead
// of trusting stored state, we scan the room's ACTUAL current participants and
// pick a real live voice to composite in. We prefer preferredIdentity (the
// stored host) IF it's actually connected and unmuted; otherwise we fall back
// to any other live unmuted speaker in the room.
async function findLiveAudioPublisher(svc, room, excludeIdentity, preferredIdentity) {
  try {
    const participants = await svc.listParticipants(room);
    const isLiveAudio = (t) => {
      const isAudio =
        t.type === 0 || t.type === 'AUDIO' || t.type === 'audio' ||
        t.source === 2 || t.source === 'MICROPHONE' || t.source === 'microphone';
      // A track that exists and is NOT muted = carrying live sound.
      return isAudio && t.muted !== true;
    };

    // First pass: honor the preferred (stored host) identity, but ONLY if it's
    // actually present in the room right now AND publishing a live unmuted mic.
    if (preferredIdentity) {
      const pref = participants.find(
        (p) => p.identity === preferredIdentity && p.identity !== excludeIdentity
      );
      const prefAudio = (pref?.tracks || []).find(isLiveAudio);
      if (prefAudio) {
        return { identity: preferredIdentity, audioSid: prefAudio.sid };
      }
    }

    // Second pass: any OTHER participant with a live unmuted mic. This covers
    // the case where the stored host is stale/gone but someone else (the real
    // current host) is talking.
    for (const p of participants) {
      if (!p.identity || p.identity === excludeIdentity) continue;
      const audio = (p.tracks || []).find(isLiveAudio);
      if (audio) {
        return { identity: p.identity, audioSid: audio.sid };
      }
    }
  } catch (e) {
    console.log(`Live-audio lookup note in ${room}:`, e?.message || e);
  }
  return { identity: undefined, audioSid: undefined };
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

// Arms the "abandoned room" cleanup timer for a room. Its ONLY job is to clean
// up rooms nobody is using anymore (free-tier cost protection). After
// SESSION_LIMIT_MS it CHECKS whether anyone is still connected:
//   - If the room is EMPTY (or gone), it deletes it and clears state.
//   - If people are STILL CONNECTED, it does NOT kill the live session — it
//     reschedules the check for another SESSION_LIMIT_MS later.
// This fixes the core bug behind silent recordings and dropped sessions: the
// old timer deleted the room after 10 minutes no matter what, which tore down
// ACTIVE sessions mid-use. Every teardown wiped Nearby mode + host identity and
// forced phones to reconnect, which reset the joiner's mic and broke the audio
// composite. By only cleaning up genuinely empty rooms, an in-use session (and
// all its Nearby/mute state) now survives as long as people are actually in it.
function startSessionTimer(room, apiKey, apiSecret) {
  if (sessionTimers[room]) {
    clearTimeout(sessionTimers[room]);
  }
  sessionTimers[room] = setTimeout(async () => {
    try {
      const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);

      // Check whether anyone is still in the room before killing it.
      let activeCount = 0;
      try {
        const participants = await svc.listParticipants(room);
        activeCount = Array.isArray(participants) ? participants.length : 0;
      } catch (e) {
        // If the room doesn't exist / can't be listed, treat as empty.
        activeCount = 0;
      }

      if (activeCount > 0) {
        // Room is still in active use — do NOT tear it down. Reschedule the
        // abandoned-room check for later so we revisit once this window passes.
        console.log(
          `Session check: ${room} still has ${activeCount} participant(s) — ` +
          `keeping it alive, rescheduling cleanup.`
        );
        delete sessionTimers[room];
        startSessionTimer(room, apiKey, apiSecret); // re-arm for another window
        return;
      }

      // Room is empty — safe to clean up (free-tier cost protection).
      await svc.deleteRoom(room);
      console.log(`Session cleanup: ended EMPTY room ${room}`);
      delete sessionTimers[room];
      delete recordings[room];
      delete nearbyModes[room];
    } catch (e) {
      console.log('Session auto-end note:', e?.message || e);
      delete sessionTimers[room];
      delete recordings[room];
      delete nearbyModes[room];
    }
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

// ---- Ban list (server-side enforcement) -------------------------------------
// A ban keys on InstallID (see InstallID.swift). When an InstallID is banned,
// /token refuses to mint a LiveKit token for it, so that install cannot join
// any room. The whole list lives in ONE R2 object, bans.json, shaped:
//   { "<installId>": { reason, ts, reportId }, ... }
// The list is tiny (a set of UUIDs), so one object is simpler than one file
// per ban and avoids a LIST on every /token call.
//
// HONEST LIMIT: InstallID resets on reinstall, so a ban is device-level, not a
// person-level ban. It raises the cost of return without preventing it. Durable
// exclusion needs accounts (V2). Do not represent this as more than it is.
const BANS_KEY = 'bans.json';

async function readBans(s3, bucket) {
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: BANS_KEY })
    );
    const text = await obj.Body.transformToString();
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (e) {
    // No bans.json yet (nobody banned) reads as an empty list, not an error.
    return {};
  }
}

async function writeBans(s3, bucket, bans) {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: BANS_KEY,
      Body: JSON.stringify(bans, null, 2),
      ContentType: 'application/json',
    })
  );
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

// ---- Force-end a room (manual kill switch) ----
// GET so it can be triggered from a browser:
//   https://.../end-room?room=test-room
// Deletes the LiveKit room (disconnecting everyone) and clears all in-memory
// state for it. Use this to kill a stuck/persistent session. Safe to call even
// if the room doesn't exist. (The automatic /livekit-webhook teardown now
// handles the normal empty-room case; this stays as a manual override.)
app.get('/end-room', async (req, res) => {
  const room = req.query.room;
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (!apiKey || !apiSecret) {
    return res.status(500).json({ error: 'Server missing LiveKit credentials' });
  }
  try {
    const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
    await svc.deleteRoom(room);
  } catch (e) {
    // If the room is already gone, that's fine — we still clear state below.
    console.log('end-room note:', e?.message || e);
  }
  // Clear all in-memory state so nothing lingers (shared with webhook teardown).
  clearRoomState(room);
  res.json({ ok: true, room: room, ended: true });
});

// ---- Token minting ----
// CHANGED: now accepts an optional { isHost } flag. When isHost is true, the
// token additionally carries roomAdmin permission, which is what lets the
// host app mute other participants' mics (Nearby mode). Joiners get the exact
// same grant as before (no roomAdmin), so their join path is unchanged.
app.post('/token', async (req, res) => {
  try {
    const { username, room, isHost, installId } = req.body || {};
    if (!username || !room) {
      return res.status(400).json({ error: 'username and room are required' });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!apiKey || !apiSecret) {
      return res.status(500).json({ error: 'Server missing LiveKit credentials' });
    }

    // Ban check FIRST — a banned install shouldn't even reach the capacity
    // check. Distinct error 'banned' (not the 'Room is full' 403) so the app
    // can show the right message. If R2 is unreachable we log and continue
    // rather than locking everyone out on an infra hiccup (fail-open: the
    // enforcement is best-effort, and a hard dependency here would make the
    // whole app unjoinable if bans.json ever failed to read).
    if (installId) {
      try {
        const s3 = makeR2Client();
        const r2Bucket = process.env.R2_BUCKET;
        if (s3 && r2Bucket) {
          const bans = await readBans(s3, r2Bucket);
          if (bans[installId]) {
            return res.status(403).json({ error: 'banned' });
          }
        }
      } catch (banErr) {
        console.log('Ban check note:', banErr?.message || banErr);
      }
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
//
// THREE-STATE: mode is 'off' | 'soft' | 'hard'.
//   off  = normal, nobody muted.
//   soft = joiner mic+speaker muted for echo, but joiner MAY override (re-enable
//          their own) if they've walked out of the echo zone.
//   hard = joiner mic+speaker forced off, no override.
// We accept either { mode } (new) or { on } (legacy boolean, true -> 'hard')
// so an older app build can't wedge the flag. We also return both `mode` and a
// legacy `on` (true when mode !== 'off') for backward compatibility.
app.post('/set-nearby', (req, res) => {
  const { room, mode, on } = req.body || {};
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  let next;
  if (mode === 'off' || mode === 'soft' || mode === 'hard') {
    next = mode;
  } else if (typeof on === 'boolean') {
    next = on ? 'hard' : 'off';   // legacy boolean support
  } else {
    next = 'off';
  }
  nearbyModes[room] = next;
  console.log(
    `[set-nearby] room=${room} -> mode=${next} ` +
    `(received mode=${mode ?? 'none'} on=${on ?? 'none'})`
  );
  res.json({ ok: true, mode: next, on: next !== 'off' });
});

// ---- Nearby mode: read state for a room ----
app.get('/nearby', (req, res) => {
  const room = req.query.room;
  if (!room) {
    return res.status(400).json({ error: 'room is required' });
  }
  const mode = nearbyModes[room] || 'off';
  res.json({ mode: mode, on: mode !== 'off' });
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

    // MUTE-ONLY POLICY (privacy-clean echo control):
    // LiveKit disallows server-side REMOTE UNMUTE by default (it returns a 412
    // "remote unmute not enabled" for privacy reasons). Rather than enable that
    // privacy-weakening setting, this server never remote-unmutes anyone. The
    // server only ever MUTES a joiner at the source (echo control). Restoring a
    // joiner's mic is done by the joiner's OWN app calling setMicrophone(true)
    // on its own local participant — a participant unmuting THEMSELVES is always
    // allowed and never triggers the 412. So here, an unmute request (muted =
    // false) is acknowledged as a no-op success; only muted = true reaches
    // LiveKit. This is what fixes the silent-joiner-recording bug: previously
    // the host cycling Nearby to OFF sent muted:false, LiveKit rejected it with
    // 412, the joiner stayed muted at the source, and their next recording came
    // out silent.
    if (muted === false) {
      return res.json({
        ok: true,
        applied: false,
        reason: 'unmute is handled by the participant themselves (server is mute-only)',
      });
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
  // ENTRY LOG: prints the instant this route is hit, before ANY logic runs.
  // If the phone's record button gets a 200 but this line never appears in the
  // Render logs, the 200 is NOT coming from this running server (stale instance
  // / wrong URL / cached response) — an infrastructure issue, not a code bug.
  // If it DOES appear, the route runs and any silence is downstream (egress).
  console.log(
    `[start-recording] HIT room=${req.body?.room} user=${req.body?.username}`
  );
  try {
    const { room, username } = req.body || {};
    if (!room || !username) {
      return res.status(400).json({ error: 'room and username are required' });
    }

    // The phone tells us directly whether THIS recorder is muted right now
    // (they're a joiner in a soft/hard Nearby state). We trust this flag from
    // the app instead of trying to read LiveKit's source-side track "muted"
    // state, which proved unreliable: the joiner's mute happens locally on
    // their phone and doesn't consistently reflect in listParticipants(), so
    // the server saw them as unmuted and skipped compositing host audio =
    // silent recordings. The app KNOWS its own Nearby/mute state, so it sends
    // it. Accepts { muted: true|false }; defaults to false if absent.
    const clientSaysMuted = req.body?.muted === true;

    // The recorder's own InstallID, sent by the phone (same value it sends to
    // /token). Stamped onto the recording as R2 object metadata so the gallery
    // can hide a blocked person's recordings by InstallID, not by username.
    // Optional: an older app build that doesn't send it just yields no stamp.
    const recorderInstallId =
      typeof req.body?.installId === 'string' ? req.body.installId : null;

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

    // Build the filename so the event name, the RECORDER's username, and the
    // session HOST's name all ride along with the file. The gallery parses:
    //   - event name  -> shown as the title
    //   - username    -> whose feed this is (shown in details)
    //   - host        -> who may DELETE this video (host-of-this-session only)
    // Format: {room}/{EventName}__{Username}__{Host}__{timestamp}.mp4
    // The double underscore "__" is the separator the app looks for. Timestamp
    // stays LAST so date parsing is unaffected. Older 3-part names
    // (Event__Username__timestamp) still parse (no host segment -> not
    // deletable by anyone, safe default).
    const stamp = Date.now();
    const safeEvent = safeToken((eventNames[room] || '').trim(), 60);
    const safeUser = safeToken(username, 40);
    const safeHost = safeToken((hostNames[room] || '').trim(), 40);
    const eventPart = safeEvent.length > 0 ? safeEvent : room;
    const userPart = safeUser.length > 0 ? safeUser : 'user';
    const hostPart = safeHost.length > 0 ? safeHost : 'host';
    // Recordings live under recordings/{room}/... so the 24h lifecycle rule can
    // target the recordings/ prefix while leaving reports/ (evidence) alone.
    const filepath = `${RECORDINGS_PREFIX}${room}/${eventPart}__${userPart}__${hostPart}__${stamp}.mp4`;

    // svc is used both here (to read the host's InstallID) and further down for
    // the Nearby composite decision. Created once here so we don't build it
    // twice.
    const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);

    // Stamp the recorder's and host's InstallID onto the recording as R2 object
    // metadata. The recorder's comes from the request body; the host's is read
    // from the host participant's published LiveKit metadata. This lets the
    // gallery hide a blocked person's recordings by InstallID (exact) instead
    // of by username (collision-prone). Both are best-effort — if either is
    // missing, the recording is still made, just without that stamp.
    let hostInstallId = null;
    try {
      const hostIdentityForStamp = hostNames[room];
      if (hostIdentityForStamp) {
        hostInstallId = await getParticipantInstallId(svc, room, hostIdentityForStamp);
      }
    } catch (e) {
      console.log('Host InstallId stamp note:', e?.message || e);
    }

    // R2/S3 custom metadata must be string values. Only include keys we actually
    // have, so we never write "null" strings.
    const uploadMetadata = {};
    if (recorderInstallId) uploadMetadata.installid = recorderInstallId;
    if (hostInstallId) uploadMetadata.hostinstallid = hostInstallId;

    console.log(
      `[record-stamp] room=${room} recorder=${username} ` +
      `recorderInstallId=${recorderInstallId || 'NONE'} ` +
      `hostInstallId=${hostInstallId || 'NONE'}`
    );

    const s3UploadOpts = {
      accessKey: r2AccessKey,
      secret: r2Secret,
      bucket: r2Bucket,
      endpoint: r2Endpoint,
      region: 'auto',
      forcePathStyle: true,
    };
    if (Object.keys(uploadMetadata).length > 0) {
      s3UploadOpts.metadata = uploadMetadata;
    }

    const fileOutput = new EncodedFileOutput({
      fileType: EncodedFileType.MP4,
      filepath: filepath,
      output: {
        case: 's3',
        value: new S3Upload(s3UploadOpts),
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
    // NEARBY (soft or hard) + recorder is a JOINER whose mic is actually
    // muted: the joiner's own audio is silent, so we composite the joiner's
    // VIDEO with the HOST's AUDIO (the one unmuted voice) via Track Composite
    // Egress. In SOFT mode a joiner may have overridden and turned their own
    // mic back on (they walked out of the echo zone) — in that case their mic
    // is live, so we record their OWN feed normally. We decide by checking the
    // joiner's actual audio-track mute state at record-start (no mid-recording
    // swap), which is exactly the rule we want.
    // (svc was created earlier in this handler for the InstallID stamp.)
    const nearbyMode = nearbyModes[room] || 'off';
    const hostIdentity = hostNames[room];

    let info;
    let usedComposite = false;

    // Is this recorder the host? The host records their own feed normally (they
    // have their own live audio). Only a muted JOINER needs host audio composited.
    const recorderIsHost = hostIdentity && hostIdentity === username;

    // COMPOSITE TRIGGER: the phone told us this recorder is muted (soft/hard
    // Nearby), so recording their own feed would be silent. We use the app's
    // own flag rather than LiveKit's unreliable source-side muted state. Host
    // never composites (they have their own live audio).
    const recorderMicMuted = clientSaysMuted;

    // ALWAYS-ON DECISION LOG: prints for EVERY recording, muted or not, so we
    // can always see what the server received. If clientSaysMuted is false the
    // phone either isn't muted OR isn't sending the flag (old app build).
    console.log(
      `[record-decision] room=${room} recorder=${username} nearbyFlag=${nearbyMode} ` +
      `clientSaysMuted=${clientSaysMuted} recorderIsHost=${!!recorderIsHost} ` +
      `storedHost=${hostIdentity || 'NONE'} willComposite=${recorderMicMuted && !recorderIsHost}`
    );

    if (recorderMicMuted && !recorderIsHost) {
      // Look up the joiner's video track (their own feed, which we always keep).
      const joinerTracks = await getParticipantTrackSids(svc, room, username);

      // Keep joinerMicMuted for logging clarity (same as recorderMicMuted here).
      const joinerMicMuted = recorderMicMuted;

      // FIND LIVE HOST AUDIO — the fix for silent joiner recordings.
      // Instead of blindly trusting hostNames[room] (which can go stale after a
      // solo/Home session reuses the shared room and never re-registers the
      // host, leaving a dead identity whose audio track SID records SILENCE),
      // we scan the room's CURRENT participants for a real, unmuted, live mic.
      // We still prefer the stored host identity IF it's actually connected and
      // talking; otherwise we fall back to whoever is actually the live voice in
      // the room (excluding the muted joiner who's recording).
      const liveAudio = await findLiveAudioPublisher(
        svc, room, username /* exclude the joiner */, hostIdentity /* prefer stored host */
      );

      // DIAGNOSTIC: log exactly what the composite decision sees, including the
      // live-audio result so a silent recording is immediately explainable.
      console.log(
        `[record-decision] room=${room} recorder=${username} nearbyFlag=${nearbyMode} ` +
        `recorderMicMuted=${joinerMicMuted} storedHost=${hostIdentity || 'NONE'} ` +
        `joinerVideoSid=${joinerTracks.videoSid || 'NONE'} ` +
        `liveAudioFrom=${liveAudio.identity || 'NONE'} ` +
        `liveAudioSid=${liveAudio.audioSid || 'NONE'}`
      );

      if (joinerMicMuted && joinerTracks.videoSid && liveAudio.audioSid) {
        // Track Composite: joiner video + a VERIFIED LIVE host/voice audio -> MP4.
        try {
          info = await egressClient.startTrackCompositeEgress(
            room,
            {
              file: fileOutput,
              encodingOptions: encoding,
            },
            {
              audioTrackId: liveAudio.audioSid,
              videoTrackId: joinerTracks.videoSid,
            }
          );
          usedComposite = true;
          console.log(
            `[record-decision] started COMPOSITE egress ${info.egressId} ` +
            `(joiner video ${joinerTracks.videoSid} + live audio ${liveAudio.audioSid} ` +
            `from ${liveAudio.identity})`
          );
        } catch (compErr) {
          // If the composite call fails, log it loudly and fall through to the
          // normal participant egress so at least SOMETHING records.
          console.error('[record-decision] COMPOSITE egress failed:', compErr);
        }
      } else {
        console.log(
          `[record-decision] composite condition NOT met -> falling back to ` +
          `normal participant egress (recording will use joiner's own mic)`
        );
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

    // List everything under BOTH the new recordings/{room}/ location and the
    // legacy {room}/ location, so recordings made before the prefix change
    // still appear until they age out. Merge the two.
    const [listedNew, listedLegacy] = await Promise.all([
      s3.send(
        new ListObjectsV2Command({
          Bucket: r2Bucket,
          Prefix: `${RECORDINGS_PREFIX}${room}/`,
        })
      ),
      s3.send(
        new ListObjectsV2Command({
          Bucket: r2Bucket,
          Prefix: `${room}/`,
        })
      ),
    ]);

    const objects = [
      ...(listedNew.Contents || []),
      ...(listedLegacy.Contents || []),
    ];

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

    // Build a temporary signed URL (valid 1 hour) for each one, and read back
    // the InstallID metadata we stamped at record time (recorder + host) so the
    // app can hide a blocked person's recordings by InstallID. Metadata isn't
    // returned by ListObjects, so we HEAD each object. Recording counts are
    // small, so the extra calls are cheap; a HEAD failure just yields no stamp.
    const out = [];
    for (const v of media) {
      const url = await getSignedUrl(
        s3,
        new GetObjectCommand({ Bucket: r2Bucket, Key: v.Key }),
        { expiresIn: 3600 }
      );
      const isPhoto = v.Key.endsWith('.jpg') || v.Key.endsWith('.jpeg');

      let installId = null;
      let hostInstallId = null;
      try {
        const head = await s3.send(
          new HeadObjectCommand({ Bucket: r2Bucket, Key: v.Key })
        );
        // S3/R2 lowercases custom metadata keys and exposes them under Metadata.
        const md = head?.Metadata || {};
        installId = md.installid || null;
        hostInstallId = md.hostinstallid || null;
      } catch (e) {
        // No metadata / HEAD failed — leave both null.
      }

      out.push({
        key: v.Key,
        url: url,
        size: v.Size,
        modified: v.LastModified,
        type: isPhoto ? 'photo' : 'video',
        installId,
        hostInstallId,
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
// Stored as {room}/{EventName}__Snap__{Host}__{msTimestamp}.jpg — the SAME
// 4-part shape as video recordings (Event__Username__Host__timestamp), so the
// gallery's host-based delete rule applies to photos too. The "Snap"
// placeholder fills the username slot (a snapshot isn't tied to one feed's
// user), and the host is looked up from hostNames[room] so only the session
// host can delete it. Covered by the same 24h auto-delete lifecycle rule.
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

    // 4-part name matching videos: {room}/{Event}__Snap__{Host}__{stamp}.jpg
    // Use a millisecond timestamp (not ISO) so the gallery parses the date the
    // same way it does for videos (Double(lastSegment) / 1000).
    const safeEvent = safeToken((event || '').trim(), 60);
    const safeHost = safeToken((hostNames[room] || '').trim(), 40);
    const eventPart = safeEvent.length > 0 ? safeEvent : 'GwoVi';
    const hostPart = safeHost.length > 0 ? safeHost : 'host';
    const stamp = Date.now();
    const key = `${room}/${eventPart}__Snap__${hostPart}__${stamp}.jpg`;

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
// ---- Submit a report (harassment, hate speech, nudity, etc.) ----
//
// Anyone can report — including reporting the session host. That is deliberate:
// if only hosts could report, an abusive host would be unreportable, which is
// exactly the hole Apple looks for in a UGC app.
//
// Body:
//   reason        (required) one of the REPORT_REASONS below
//   comment       (optional) free text from the reporter
//   room          (optional) which session
//   event         (optional) the event name
//   reporterId    (required) the reporter's InstallID — NOT their username
//   reporterName  (optional) their display name, for a human-readable log
//   accusedId     (optional) InstallID of the person being reported
//   accusedName   (optional) their display name
//   recordingKey  (optional) the R2 key of the recording being reported
//
// WHY InstallID AND NOT THE USERNAME:
// Usernames are self-typed and collide — two people can both be "Mike". A
// report naming "Mike" is unactionable. The InstallID is unique per install, so
// a report actually points at somebody. It is not bulletproof (reinstalling
// mints a new ID) but it is the difference between a report you can act on and
// a complaint you cannot.
//
// EVIDENCE PRESERVATION:
// Normal recordings live under {room}/ and are auto-deleted after 24h by an R2
// bucket LIFECYCLE RULE — which runs on Cloudflare's side, not ours. We cannot
// tell that rule to skip an object. So if someone reports a recording at hour
// 23, the evidence would evaporate before anyone looked at it.
//
// Instead we COPY the reported object into reports/evidence/ the moment the
// report lands. That prefix must be EXCLUDED from the 24h lifecycle rule in the
// Cloudflare dashboard (otherwise the copy dies too — see setup note below).
// The original still expires on schedule, so normal ephemerality is untouched.
const REPORT_REASONS = [
  'harassment',
  'hate_speech',
  'threats',
  'nudity',
  'spam',
  'other',
];

app.post('/report', async (req, res) => {
  try {
    const {
      reason,
      comment,
      room,
      event,
      reporterId,
      reporterName,
      accusedId,
      accusedName,
      recordingKey,
    } = req.body || {};

    if (!reason || !REPORT_REASONS.includes(reason)) {
      return res.status(400).json({
        error: 'A valid reason is required.',
        allowed: REPORT_REASONS,
      });
    }
    if (!reporterId) {
      return res.status(400).json({ error: 'reporterId is required.' });
    }

    const s3 = makeR2Client();
    const r2Bucket = process.env.R2_BUCKET;
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    const now = Date.now();
    const reportId = `${now}_${Math.random().toString(36).slice(2, 10)}`;

    // Preserve the evidence BEFORE writing the report, so the report can record
    // whether we actually managed to keep a copy. If the copy fails we still
    // file the report — a report with no video beats no report at all.
    let evidenceKey = null;
    let evidenceError = null;
    if (recordingKey) {
      try {
        const fileName = recordingKey.split('/').pop();
        evidenceKey = `reports/evidence/${reportId}__${fileName}`;
        await s3.send(
          new CopyObjectCommand({
            Bucket: r2Bucket,
            CopySource: `${r2Bucket}/${recordingKey}`,
            Key: evidenceKey,
          })
        );
        console.log(
          `[report] evidence preserved: ${recordingKey} -> ${evidenceKey}`
        );
      } catch (copyErr) {
        evidenceKey = null;
        evidenceError = String(copyErr && copyErr.message ? copyErr.message : copyErr);
        console.error('[report] evidence copy FAILED:', evidenceError);
      }
    }

    const report = {
      id: reportId,
      status: 'pending',            // pending | reviewing | closed
      createdAt: new Date(now).toISOString(),
      reason,
      comment: (comment || '').slice(0, 2000),
      room: room || null,
      event: event || null,
      reporter: {
        installId: reporterId,
        name: reporterName || null,
      },
      accused: {
        installId: accusedId || null,
        name: accusedName || null,
      },
      // The original — will be gone after 24h.
      recordingKey: recordingKey || null,
      // Our retained copy — this is the one that survives.
      evidenceKey,
      evidenceError,
    };

    await s3.send(
      new PutObjectCommand({
        Bucket: r2Bucket,
        Key: `reports/${reportId}.json`,
        Body: JSON.stringify(report, null, 2),
        ContentType: 'application/json',
      })
    );

    console.log(
      `[report] FILED id=${reportId} reason=${reason} ` +
      `reporter=${reporterId} accused=${accusedId || 'NONE'} ` +
      `room=${room || 'NONE'} evidence=${evidenceKey ? 'YES' : 'NO'}`
    );

    // The reporter gets a plain acknowledgement. We never tell them what action
    // was or wasn't taken against the other person — that is not their business
    // and telling them invites retaliation.
    res.json({
      ok: true,
      id: reportId,
      message: 'Thank you. We received your report and will review it as soon as possible.',
    });
  } catch (err) {
    console.error('Report error:', err);
    res.status(500).json({ error: 'Failed to file report' });
  }
});

// ---- Admin: list reports ----
//
// Deliberately NOT a pretty dashboard — this is the smallest thing that lets a
// human actually read what came in. A report system nobody reads is theater.
//
// Protected by ADMIN_TOKEN (set it in Render's environment). Without that env
// var set, this endpoint refuses to serve anything at all rather than defaulting
// to open — a wide-open list of abuse reports would be its own privacy incident.
//
// Usage:  GET /admin/reports?token=YOUR_ADMIN_TOKEN
app.get('/admin/reports', async (req, res) => {
  try {
    const adminToken = process.env.ADMIN_TOKEN;
    if (!adminToken) {
      return res.status(503).json({
        error: 'Admin access is not configured (ADMIN_TOKEN is not set).',
      });
    }
    if (req.query.token !== adminToken) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const s3 = makeR2Client();
    const r2Bucket = process.env.R2_BUCKET;
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    const listed = await s3.send(
      new ListObjectsV2Command({ Bucket: r2Bucket, Prefix: 'reports/' })
    );
    const files = (listed.Contents || []).filter(
      (o) => o.Key && o.Key.endsWith('.json')
    );
    files.sort((a, b) => new Date(b.LastModified) - new Date(a.LastModified));

    const out = [];
    for (const f of files) {
      try {
        const obj = await s3.send(
          new GetObjectCommand({ Bucket: r2Bucket, Key: f.Key })
        );
        const body = await obj.Body.transformToString();
        const parsed = JSON.parse(body);

        // Signed link to the retained evidence so it can actually be watched.
        if (parsed.evidenceKey) {
          parsed.evidenceUrl = await getSignedUrl(
            s3,
            new GetObjectCommand({ Bucket: r2Bucket, Key: parsed.evidenceKey }),
            { expiresIn: 3600 }
          );
        }
        out.push(parsed);
      } catch (e) {
        console.error('Could not read report', f.Key, e);
      }
    }

    res.json({ count: out.length, reports: out });
  } catch (err) {
    console.error('Admin reports error:', err);
    res.status(500).json({ error: 'Failed to list reports' });
  }
});

// ---- Admin: ban / unban / list bans -----------------------------------------
// All three require the same ADMIN_TOKEN as /admin/reports. A ban keys on
// InstallID; once banned, /token refuses that install (see the ban check
// there). Workflow: review at /admin/reports, copy the accused installId, ban
// it here.
app.post('/admin/ban', async (req, res) => {
  try {
    const adminToken = process.env.ADMIN_TOKEN;
    if (!adminToken) {
      return res.status(503).json({
        error: 'Admin access is not configured (ADMIN_TOKEN is not set).',
      });
    }
    const provided = req.query.token || (req.body && req.body.token);
    if (provided !== adminToken) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { installId, reason, reportId } = req.body || {};
    if (!installId || typeof installId !== 'string') {
      return res.status(400).json({ error: 'installId is required' });
    }

    const s3 = makeR2Client();
    const r2Bucket = process.env.R2_BUCKET;
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    const bans = await readBans(s3, r2Bucket);
    bans[installId] = {
      reason: typeof reason === 'string' ? reason.slice(0, 500) : 'unspecified',
      ts: new Date().toISOString(),
      reportId: reportId || null,
    };
    await writeBans(s3, r2Bucket, bans);
    console.log(`[admin] banned installId=${installId}`);
    res.json({ ok: true, installId, banned: true });
  } catch (err) {
    console.error('Admin ban error:', err);
    res.status(500).json({ error: 'Failed to ban' });
  }
});

app.post('/admin/unban', async (req, res) => {
  try {
    const adminToken = process.env.ADMIN_TOKEN;
    if (!adminToken) {
      return res.status(503).json({
        error: 'Admin access is not configured (ADMIN_TOKEN is not set).',
      });
    }
    const provided = req.query.token || (req.body && req.body.token);
    if (provided !== adminToken) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { installId } = req.body || {};
    if (!installId || typeof installId !== 'string') {
      return res.status(400).json({ error: 'installId is required' });
    }

    const s3 = makeR2Client();
    const r2Bucket = process.env.R2_BUCKET;
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    const bans = await readBans(s3, r2Bucket);
    if (bans[installId]) {
      delete bans[installId];
      await writeBans(s3, r2Bucket, bans);
      console.log(`[admin] unbanned installId=${installId}`);
    }
    res.json({ ok: true, installId, banned: false });
  } catch (err) {
    console.error('Admin unban error:', err);
    res.status(500).json({ error: 'Failed to unban' });
  }
});

app.get('/admin/bans', async (req, res) => {
  try {
    const adminToken = process.env.ADMIN_TOKEN;
    if (!adminToken) {
      return res.status(503).json({
        error: 'Admin access is not configured (ADMIN_TOKEN is not set).',
      });
    }
    if (req.query.token !== adminToken) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const s3 = makeR2Client();
    const r2Bucket = process.env.R2_BUCKET;
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    const bans = await readBans(s3, r2Bucket);
    const list = Object.entries(bans).map(([installId, meta]) => ({
      installId,
      ...meta,
    }));
    list.sort((a, b) => new Date(b.ts) - new Date(a.ts));
    res.json({ count: list.length, bans: list });
  } catch (err) {
    console.error('Admin bans list error:', err);
    res.status(500).json({ error: 'Failed to list bans' });
  }
});

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
