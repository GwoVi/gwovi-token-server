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
import crypto from 'node:crypto';

// ---- SESSION TOKENS (added Jul 30, privacy incident) -----------------------
//
// WHY THIS EXISTS. The earlier hotfix filtered /recordings by an installId sent
// in the query string. That is not authorization, because installIds are NOT
// secret: StreamManager publishes each participant's installId in their LiveKit
// participant metadata (deliberately — it's what makes block-by-installId work).
// So anyone who shared a session with you could read your installId and then ask
// for your media. Filtering on a value the caller supplies is a filter, not a
// lock.
//
// The fix: the server issues a signed token at /token, and every endpoint that
// touches media verifies it and reads room + installId FROM THE VERIFIED
// PAYLOAD — never from the query string or body. A caller can no longer name
// somebody else.
//
// Token shape: base64url(JSON payload) + "." + base64url(HMAC-SHA256 of that).
// Stateless on purpose — nothing to persist, so a Render redeploy can't lose it.
//
// FAILS CLOSED: if SESSION_SECRET isn't set, verification always fails and the
// protected endpoints return 401. That is intentional. A privacy fix that
// silently degrades to "allow everything" when misconfigured is not a fix.
const SESSION_SECRET = process.env.SESSION_SECRET;

// TWENTY-FIVE HOURS — deliberately one hour LONGER than media survives.
//
// This was six hours, matched to the LiveKit streaming token. That was a bug,
// not a policy. Recordings live 24 hours in R2, so a token that died at six
// left an 18-hour window where a session's files existed but nobody could read
// them: /recordings returned 401, the gallery skipped the section, and it
// looked exactly like the recordings had been deleted early. Confirmed Jul 31
// by opening the bucket — the .mp4s were all still there.
//
// An access token should never expire before the thing it protects. It grants
// nothing new: the media is gone at 24 hours regardless, and the token only
// ever unlocks a room the holder was admitted to.
//
// NOTE: this is the SESSION token (media access), not the LiveKit streaming
// token, which stays at six hours.
const SESSION_TTL_MS = 25 * 60 * 60 * 1000;

// ...but WRITES stay on the old six-hour clock.
//
// Reads are safe to keep alive for a full day. Writes are not the same thing:
// /start-recording kicks off a LiveKit egress, which costs money and drops a
// new file into a session that has probably moved on without you. A token
// that's a day old should not be able to do that. So the long TTL buys back
// the gallery without also handing out a 25-hour write window.
//
// Applies to /start-recording and /upload-snapshot. NOT to /stop-recording (a
// recording started in the window must always be stoppable) and NOT to
// /delete-recording (already bounded by an ownership check, and you should be
// able to delete your own clip for as long as it exists).
const SESSION_WRITE_MAX_AGE_MS = 6 * 60 * 60 * 1000;

function makeSessionToken({ installId, room, role }) {
  if (!SESSION_SECRET) return null;
  const now = Date.now();
  const payload = {
    installId,
    room,
    role: role === 'host' ? 'host' : 'joiner',
    // iat is what makes the write-freshness check possible. Tokens minted
    // before this change don't carry it — see requireFreshSession.
    iat: now,
    exp: now + SESSION_TTL_MS,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');
  return `${body}.${sig}`;
}

// Returns the verified payload, or null if anything is wrong. Never throws.
function verifySessionToken(token) {
  if (!SESSION_SECRET) return null;
  if (typeof token !== 'string' || token.length === 0) return null;

  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;

  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');

  // Constant-time compare so the signature can't be brute-forced a byte at a
  // time by measuring how long the comparison takes.
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  if (typeof payload.installId !== 'string' || !payload.installId) return null;
  if (typeof payload.room !== 'string' || !payload.room) return null;
  return payload;
}

// Route guard. Pulls the token from the header (preferred), or from the query
// string / body as a fallback so the app can send it whichever way is easiest
// at each call site. Responds 401 and returns null when it doesn't verify —
// callers should `if (!session) return;` immediately.
function requireSession(req, res) {
  const raw =
    req.get('X-GwoVi-Session') ||
    req.query?.sessionToken ||
    (req.body && req.body.sessionToken);
  const payload = verifySessionToken(raw);
  if (!payload) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }
  return payload;
}

// Stricter guard for the endpoints that CREATE things. Everything
// requireSession checks, plus: the token must have been issued recently.
//
// Legacy tokens (minted before iat existed) carried a six-hour TTL, so any one
// still unexpired is by definition less than six hours old — those pass. This
// is a real inference, not a courtesy: a token that can't prove its age but
// couldn't have been older than the limit anyway is fine.
function requireFreshSession(req, res) {
  const payload = requireSession(req, res);
  if (!payload) return null;

  if (typeof payload.iat === 'number') {
    const age = Date.now() - payload.iat;
    if (age > SESSION_WRITE_MAX_AGE_MS) {
      // 401 rather than 403 so the app's existing "session expired — rejoin"
      // handling fires. The distinct error string is there for the logs and
      // for a future build that wants to say something more precise.
      res.status(401).json({ error: 'session_stale' });
      return null;
    }
  }

  return payload;
}

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
          // Blindly wiping state here was the root cause of silent joiner
          // recordings: hostNames[room] got erased, so at record-time there was
          // no host identity to composite audio from. So before tearing anything
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
// sets the event (goes live). Needed so that a joiner who is recording while
// their own mic is off can have their video composited with the HOST's audio
// track, instead of producing a silent file.
const hostNames = {}; // hostNames[room] = "Joseph"

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
// where we pair a muted joiner's video with the host's audio.
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

// Ages out stale join requests.
//
// PENDING requests expire quickly (2 minutes) — an unanswered knock shouldn't
// sit in the host's list forever.
//
// APPROVED and DENIED entries are kept far longer, because /token now consults
// them: a joiner is only issued a session token if the host actually approved
// them, so throwing the approval away after two minutes would lock out anyone
// who took a moment to connect, or who dropped and rejoined mid-session. They
// are cleared wholesale when the room finishes (clearRoomState).
const PENDING_TTL_MS = 2 * 60 * 1000;        // 2 minutes
const DECISION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function pruneOld(room) {
  const now = Date.now();
  const list = roomRequests(room);
  for (const name of Object.keys(list)) {
    const entry = list[name];
    const ttl = entry.status === 'pending' ? PENDING_TTL_MS : DECISION_TTL_MS;
    if (now - entry.ts > ttl) {
      delete list[name];
    }
  }
}

// Whether this username has been approved to join this room. Used by /token.
// Note this is in-memory: a Render restart clears it, and the joiner would need
// the host to approve again. The room's event name lives in memory too and
// vanishes on the same restart, so the code stops resolving anyway — the two
// fail together rather than leaving a confusing half-state.
function isApprovedJoiner(room, username) {
  if (!room || !username) return false;
  const entry = requests[room]?.[username];
  return entry?.status === 'approved';
}

// Arms the "abandoned room" cleanup timer for a room. Its ONLY job is to clean
// up rooms nobody is using anymore (free-tier cost protection). After
// SESSION_LIMIT_MS it CHECKS whether anyone is still connected:
//   - If the room is EMPTY (or gone), it deletes it and clears state.
//   - If people are STILL CONNECTED, it does NOT kill the live session — it
//     reschedules the check for another SESSION_LIMIT_MS later.
// This fixes the core bug behind silent recordings and dropped sessions: the
// old timer deleted the room after 10 minutes no matter what, which tore down
// ACTIVE sessions mid-use. Every teardown wiped host identity and
// forced phones to reconnect, which reset the joiner's mic and broke the audio
// composite. By only cleaning up genuinely empty rooms, an in-use session (and
// all its host/recording state) now survives as long as people are in it.
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
    } catch (e) {
      console.log('Session auto-end note:', e?.message || e);
      delete sessionTimers[room];
      delete recordings[room];
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
// host app perform admin actions on other participants. V1 doesn't use it —
// host-enforced muting is a planned paid-tier feature — but the grant is kept
// so that tier doesn't need a token change. Joiners never receive it.
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

    // APPROVAL GATE — this is what makes session-wide gallery access safe.
    //
    // A session token unlocks everything recorded in its room, so issuing one
    // on nothing more than a room name would mean a forwarded join code was
    // enough to see the whole session's media. Approval was already required by
    // the app's join flow; enforcing it here moves it from a UI convention to
    // something the server actually checks.
    //
    // Hosts are exempt (they created the room). Solo/Home rooms are exempt
    // too — they're derived from the caller's own InstallID, so there is nobody
    // to approve them and nobody else who could ask for that room.
    const isSoloRoom = typeof room === 'string' && room.startsWith('solo-');
    if (isHost !== true && !isSoloRoom) {
      pruneOld(room);
      if (!isApprovedJoiner(room, username)) {
        console.log(
          `[token] REFUSED ${username} for ${room} — no host approval on record`
        );
        return res.status(403).json({ error: 'not_approved' });
      }
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

    // HOST ONLY: roomAdmin lets this participant perform LiveKit admin actions
    // on other participants. Unused in V1; reserved for paid-tier host
    // moderation. Only the host ever receives this; joiners never do.
    if (isHost === true) {
      grant.roomAdmin = true;
    }

    at.addGrant(grant);

    const token = await at.toJwt();

    // Mint the companion session token. This is what authorizes the media
    // endpoints (/recordings, /upload-snapshot, /start-recording,
    // /stop-recording, /delete-recording). It binds this caller to THIS room
    // and THIS installId, so those endpoints never have to trust a room or
    // installId the client claims later.
    //
    // Note: a session token is only issued here, and reaching here means the
    // caller already passed the ban check and the capacity check. For joiners
    // the app only calls /token after the host approves them, so approval
    // remains the real gate — the room code alone gets you nothing.
    const sessionToken = makeSessionToken({
      installId: installId || null,
      room,
      role: isHost === true ? 'host' : 'joiner',
    });

    if (!sessionToken) {
      // SESSION_SECRET missing. Say so loudly rather than handing back a token
      // that won't work and letting it fail confusingly three calls later.
      console.error(
        '[token] SESSION_SECRET is not set — cannot mint session tokens. ' +
        'Media endpoints will reject every request until it is configured.'
      );
    }

    res.json({ token, sessionToken });
  } catch (err) {
    console.error('Token error:', err);
    res.status(500).json({ error: 'Failed to create token' });
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
    // FRESH session required: starting a recording launches a paid egress and
    // writes a new file into the room. A day-old token can read the gallery
    // but must not be able to do this.
    const session = requireFreshSession(req, res);
    if (!session) return;

    const room = session.room;
    const { username } = req.body || {};
    if (!username) {
      return res.status(400).json({ error: 'username is required' });
    }
    // The phone tells us directly whether THIS recorder's mic is off right now
    // (joiners start muted and may not have unmuted). We trust this flag from
    // the app instead of trying to read LiveKit's source-side track "muted"
    // state, which proved unreliable: the joiner's mute happens locally on
    // their phone and doesn't consistently reflect in listParticipants(), so
    // the server saw them as unmuted and skipped compositing host audio =
    // silent recordings. The app KNOWS its own mic state, so it sends
    // it. Accepts { muted: true|false }; defaults to false if absent.
    const clientSaysMuted = req.body?.muted === true;

    // The recorder's InstallID now comes from the VERIFIED session token, not
    // from the request body. Stamped onto the recording as R2 object metadata,
    // which is what /recordings and /delete-recording check ownership against —
    // so it has to be a value the client can't forge.
    const recorderInstallId = session.installId;

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
    // the composite decision. Created once here so we don't build it
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

    // Recording dimensions.
    //
    // PORTRAIT, deliberately — corrected Aug 3. The camera CAPTURES landscape
    // 1920x1080 (see captureDimensions in StreamManager, kept landscape because
    // forcing portrait broke pinch-to-zoom), but the phone is held upright, so
    // rotation is applied and the track LiveKit actually receives is PORTRAIT.
    // The LiveKit dashboard confirms it: the published layers are
    // 180x320 / 360x640 / 1080x1920.
    //
    // The old value here was landscape 1920x1080, matching the capture rather
    // than the published track. That was never tested in anger, because the
    // options weren't reaching egress at all (see the call sites below) — every
    // recording was silently made with egress's default 720p preset. Now that
    // the options land, the dimensions have to match the real track or the
    // compositor will letterbox or squeeze it.
    //
    // NOTE FOR WHOEVER TESTS THIS: the Jul 27 fix supposedly cured a squeezed
    // composite recording by switching this from portrait to landscape. That
    // can't have been the mechanism if the options never arrived, so treat the
    // Jul 27 conclusion as unverified and watch the shape of the first
    // composite recording after this deploy. If it comes out stretched, this
    // constant is the first thing to flip back.
    //
    // At 1080x1920 the file is already 9:16, so cropToPortrait in GalleryView
    // has nothing to trim and saves land at full 1080x1920.
    const encoding = new EncodingOptions({
      width: 1080,
      height: 1920,
      framerate: 30,
      videoBitrate: 4500, // kbps
      videoCodec: 0,      // H.264 baseline default for broad compatibility
    });

    // Decide which kind of recording to start.
    //
    // NORMAL (mic live, OR the recorder is the host): record this one
    // participant's own feed (their video + their own audio) via Participant
    // Egress.
    //
    // MUTED JOINER: joiners start muted on entry, so a joiner who records
    // before unmuting would produce a silent file. In that case we composite
    // the joiner's VIDEO with the HOST's AUDIO via Track Composite Egress. A
    // joiner who HAS unmuted records their own feed normally. The decision is
    // made once at record-start from the mic state the app reports — no
    // mid-recording swap.
    // (svc was created earlier in this handler for the InstallID stamp.)
    const hostIdentity = hostNames[room];

    let info;
    let usedComposite = false;

    // Is this recorder the host? The host records their own feed normally (they
    // have their own live audio). Only a muted JOINER needs host audio composited.
    const recorderIsHost = hostIdentity && hostIdentity === username;

    // COMPOSITE TRIGGER: the phone told us this recorder's mic is off, so
    // recording their own feed would be silent. We use the app's
    // own flag rather than LiveKit's unreliable source-side muted state. Host
    // never composites (they have their own live audio).
    const recorderMicMuted = clientSaysMuted;

    // ALWAYS-ON DECISION LOG: prints for EVERY recording, muted or not, so we
    // can always see what the server received. If clientSaysMuted is false the
    // phone either isn't muted OR isn't sending the flag (old app build).
    console.log(
      `[record-decision] room=${room} recorder=${username} ` +
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
        `[record-decision] room=${room} recorder=${username} ` +
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
            },
            {
              audioTrackId: liveAudio.audioSid,
              videoTrackId: joinerTracks.videoSid,
              // BUG FIXED Aug 3: encodingOptions used to sit in the OUTPUT
              // argument above, next to `file`. The SDK's output type only
              // understands file/stream/segments/image, so it silently dropped
              // it — the egress request recorded in the LiveKit dashboard
              // contained no options at all, and egress fell back to its
              // default H264_720P_30 preset. That is where every 1280x720
              // recording came from. It belongs HERE, in the options argument.
              encodingOptions: encoding,
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
        },
        {
          // Same fix as the composite path above: options go in their own
          // argument, not folded into the output object.
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
    // Deliberately NOT requireFreshSession. Anything that was legitimately
    // started must stay stoppable, or a long recording could outlive its
    // token's write window and be stranded running.
    const session = requireSession(req, res);
    if (!session) return;

    const room = session.room;
    const { username } = req.body || {};
    if (!username) {
      return res.status(400).json({ error: 'username is required' });
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
    // AUTHORIZATION, not filtering. Room and identity both come from the
    // signed token — a caller cannot ask for a room they weren't issued a
    // token for, and cannot name someone else's installId.
    const session = requireSession(req, res);
    if (!session) return;

    const room = session.room;

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

    // ---- SESSION-WIDE LISTING ----
    //
    // Everything in this room is returned, not just the caller's own files.
    // That IS the product: several people record the same moment from different
    // angles and the group ends up with all of them. A gallery that handed each
    // person only their own recording back would defeat the point of the app.
    //
    // What makes that safe now is the room, not a per-file filter. Every session
    // has its own room named by the host's join code, a joiner only gets a token
    // after the host approves them, and /token refuses to mint one otherwise. So
    // "everyone in the room sees the room's media" is a statement about a group
    // that was individually let in — which is different in kind from the shared
    // `test-room` that caused the July 30 incident, where "the room" meant every
    // install on earth.
    //
    // The InstallIDs still ride along in the response so the app can hide a
    // blocked person's recordings locally.
    const out = [];
    for (const v of media) {
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
        // No metadata / HEAD failed — leave both null. The file is still shown;
        // it's in this room, which is what authorizes it.
      }

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
    // FRESH session required — same reasoning as /start-recording: this writes
    // a new object into the room's storage.
    const session = requireFreshSession(req, res);
    if (!session) return;

    const room = session.room;
    const { event, image } = req.body || {};
    if (!image) {
      return res.status(400).json({ error: 'image is required' });
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
    // BUG FIXED Jul 30: this used to write to the bare `${room}/...` path.
    // Two consequences, both bad:
    //   1. The R2 24-hour lifecycle rule is scoped to the `recordings/` prefix,
    //      so snapshots written outside it NEVER auto-deleted — contradicting
    //      both the Privacy Policy and the app's own promise.
    //   2. No ownership metadata was stamped, so once /recordings started
    //      filtering by owner, snapshots could never match anyone.
    // Writing under RECORDINGS_PREFIX fixes the retention hole; stamping
    // installid/hostinstallid below fixes the ownership hole.
    const key = `${RECORDINGS_PREFIX}${room}/${eventPart}__Snap__${hostPart}__${stamp}.jpg`;

    // Same ownership stamps videos get, so the gallery filter treats photos and
    // videos identically. The uploader's ID comes from the VERIFIED session,
    // not from the request body — a client can't claim to be someone else.
    const snapMetadata = { installid: session.installId };
    try {
      const hostIdentityForStamp = hostNames[room];
      if (hostIdentityForStamp) {
        const apiKey = process.env.LIVEKIT_API_KEY;
        const apiSecret = process.env.LIVEKIT_API_SECRET;
        if (apiKey && apiSecret) {
          const svc = new RoomServiceClient(LIVEKIT_HOST, apiKey, apiSecret);
          const hostInstallId = await getParticipantInstallId(
            svc,
            room,
            hostIdentityForStamp
          );
          if (hostInstallId) snapMetadata.hostinstallid = hostInstallId;
        }
      }
    } catch (e) {
      console.log('Snapshot host stamp note:', e?.message || e);
    }

    await s3.send(
      new PutObjectCommand({
        Bucket: r2Bucket,
        Key: key,
        Body: buffer,
        ContentType: 'image/jpeg',
        Metadata: snapMetadata,
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
    // Was previously UNAUTHENTICATED and UNSCOPED: any caller who knew (or
    // guessed) a key could delete anyone's media, guarded only by a check that
    // the key looked like a media file. Now the caller must present a valid
    // session token, and may only delete media that belongs to them.
    //
    // Deliberately NOT requireFreshSession: this is already bounded by an
    // ownership check against the object's own metadata, and you should be
    // able to delete your own clip for as long as that clip exists.
    const session = requireSession(req, res);
    if (!session) return;

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

    // The key must belong to the room this session was issued for. Blocks
    // reaching sideways into another room's media with a valid token.
    const inNewPath = key.startsWith(`${RECORDINGS_PREFIX}${session.room}/`);
    const inLegacyPath = key.startsWith(`${session.room}/`);
    if (!inNewPath && !inLegacyPath) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const r2Bucket = process.env.R2_BUCKET;
    const s3 = makeR2Client();
    if (!s3 || !r2Bucket) {
      return res.status(500).json({ error: 'Server missing R2 credentials' });
    }

    // Ownership check against the object's own metadata. The recorder may
    // delete their own file; the session host may delete anything from the
    // session they hosted (which is the delete authority the gallery already
    // shows). Anything unstamped fails closed.
    let ownerId = null;
    let hostId = null;
    try {
      const head = await s3.send(
        new HeadObjectCommand({ Bucket: r2Bucket, Key: key })
      );
      const md = head?.Metadata || {};
      ownerId = md.installid || null;
      hostId = md.hostinstallid || null;
    } catch (e) {
      return res.status(404).json({ error: 'not found' });
    }

    if (ownerId !== session.installId && hostId !== session.installId) {
      return res.status(403).json({ error: 'forbidden' });
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
    // Remember who the host is (their LiveKit identity) so a muted joiner's
    // recording can borrow host audio. The app sends this when the host goes live.
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
  if (!SESSION_SECRET) {
    console.error(
      '*** SESSION_SECRET is NOT set. Session tokens cannot be issued or ' +
      'verified, so /recordings, /upload-snapshot, /start-recording, ' +
      '/stop-recording and /delete-recording will reject EVERY request with ' +
      '401. Set SESSION_SECRET in the Render environment. ***'
    );
  }
});
