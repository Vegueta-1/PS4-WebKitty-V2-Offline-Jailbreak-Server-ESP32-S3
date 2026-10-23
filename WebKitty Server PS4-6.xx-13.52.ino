#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
#include <esp_wifi.h>

#include "wk_inflate.h"
#include "wk_names.h"

/*
 * WebKitty 13.52 - packed-asset serving firmware
 *
 * The LittleFS image is built by tools/wkpack.py from the data/ folder and
 * holds every original file in one of three forms:
 *
 *   <path>.gz   gzip(level 9) copy of <path>          (codec: deflate)
 *   <path>.zk   WKBC derived entry built from a base  (codec: wkbc)
 *   <path>      stored as-is, only when gzip would not shrink it
 *
 * Serving policy for a request to <path>:
 *
 *   1. <path>.zk  exists  -> reconstruct on the fly: stream the (gzip)
 *                            base file through wk_inflate while applying the
 *                            literal/copy/skip op list. Nothing is held in
 *                            RAM beyond a 1 kB scratch buffer + decoder.
 *   2. <path>.gz  exists  -> if the client advertises "Accept-Encoding: gzip"
 *                            (every browser, including the PS4's) the bytes
 *                            are handed over untouched with
 *                            Content-Encoding: gzip: zero CPU on the ESP32.
 *                            Otherwise wk_inflate streams them out decoded.
 *   3. <path>     exists  -> stored plain, stream it directly.
 *
 * wk_inflate is the host-tested streaming DEFLATE/gzip decoder in
 * wk_inflate.c (see extras/host_test: 2665 conformance checks).
 */

const char* ssid = "ESP32-S3 Exploit-PS4";
const char* password = "password";
const int apChannel = 1;

WebServer server(80);
DNSServer dnsServer;

IPAddress apIP(192, 168, 1, 1);

// single decoder instance (~40 kB); the WebServer handles one client at a time
static wk_inflate_t *gInf = nullptr;

// shared scratch buffer for .zk reconstruction (avoids deep stack usage)
static uint8_t gScratch[1024];

// set once response headers go out; after that a 500 must never be sent,
// since it would append junk to an already-started body
static bool gResponseStarted = false;

// one in-flight .zk reconstruction state (base + op list being streamed)
struct ZkStream {
  File ops;        // the .zk file, positioned at the op list
  File base;       // base file (gzip-compressed unless baseRaw)
  bool baseRaw;
  wk_inflate_t *inf;
  uint8_t buf[1024];
  size_t len, pos;
};

// ---------------------------------------------------------------- content --
String getContentType(const String& filename) {
  if (filename.endsWith(".html") || filename.endsWith(".htm")) return "text/html";
  if (filename.endsWith(".css")) return "text/css";
  if (filename.endsWith(".js") || filename.endsWith(".mjs")) return "application/javascript";
  if (filename.endsWith(".json")) return "application/json";
  if (filename.endsWith(".png")) return "image/png";
  if (filename.endsWith(".gif")) return "image/gif";
  if (filename.endsWith(".ico")) return "image/x-icon";
  if (filename.endsWith(".svg")) return "image/svg+xml";
  if (filename.endsWith(".woff2")) return "font/woff2";
  if (filename.endsWith(".woff")) return "font/woff";
  if (filename.endsWith(".ttf")) return "font/ttf";
  if (filename.endsWith(".bin")) return "application/octet-stream";
  if (filename.endsWith(".xml")) return "text/xml";
  return "text/plain";
}

static bool clientWantsGzip() {
  for (size_t i = 0; i < server.headers(); i++) {
    String k = server.headerName(i);
    k.toLowerCase();
    if (k == "accept-encoding") {
      String v = server.header(i);
      v.toLowerCase();
      return v.indexOf("gzip") >= 0;
    }
  }
  return false;
}

// -------------------------------------------------------- inflate piping --
static size_t fileFill(void *ctx, uint8_t *buf, size_t cap) {
  File *f = (File *)ctx;
  size_t n = f->read(buf, cap);
  return n;
}

// push callback: hand decompressed bytes to the socket; a short write means
// the client is gone and halts the decoder
static size_t socketPush(void *ctx, const uint8_t *buf, size_t len) {
  (void)ctx;
  if (!server.client().connected()) return 0;
  server.sendContent((const char *)buf, len);
  return server.client().connected() ? len : 0;
}

// --------------------------------------------------------------- telemetry --
// The PS4-side exploit JS calls post(tag, detail), which XHRs a form-encoded
// body to `t` relative to the current page (/document/en/ps4/t). That stream is
// the exploit's entire progress/error log, so answer it and print it instead of
// letting it fall through to the 404 branch.
static String urlDecode(const String &s) {
  String out;
  out.reserve(s.length());
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < s.length()) {
      char hex[3] = {s[i + 1], s[i + 2], 0};
      out += (char)strtol(hex, nullptr, 16);
      i += 2;
    } else {
      out += c;
    }
  }
  return out;
}

// pull "key=value" out of a &-separated body
static String formField(const String &body, const char *key) {
  String k = String(key) + "=";
  int p = body.indexOf(k);
  if (p < 0) return "";
  p += k.length();
  int e = body.indexOf('&', p);
  if (e < 0) e = body.length();
  return urlDecode(body.substring(p, e));
}

static void handleTelemetry() {
  String tag = server.arg("tag");
  String detail = server.arg("detail");
  String body = server.arg("plain");

  if (!tag.length() && body.length()) {
    // WebServer did not split the body (e.g. unexpected content-type) --
    // parse the raw form string ourselves: "PS4-JB&tag=...&detail=..."
    if (!tag.length()) tag = formField(body, "tag");
    if (!detail.length()) detail = formField(body, "detail");
  }

  // tag carries the exploit-chain prefix (PS4-JB / PS4-S4Q / PS4-S10 / ...)
  Serial.printf("[PS4] %s | %s\n", tag.c_str(), detail.c_str());
  server.send(200, "text/plain", "OK");
}

// ------------------------------------------------------------- responders --
// stream a plain (already uncompressed) file
static bool servePlain(File &f, const String &ct) {
  server.streamFile(f, ct);   // sends 200 + headers internally
  gResponseStarted = true;
  f.close();
  return true;
}

// hand a .gz over untouched; the client decompresses it natively
static bool serveGzipPassthrough(File &gz, const String &ct) {
  server.sendHeader("Content-Encoding", "gzip");
  server.setContentLength(gz.size());
  server.send(200, ct, "");
  gResponseStarted = true;
  while (gz.available()) {
    size_t n = gz.read(gScratch, sizeof(gScratch));
    if (!n) break;
    server.sendContent((const char *)gScratch, n);
    if (!server.client().connected()) break;    // client vanished
  }
  gz.close();
  return true;
}

// decode a .gz on the ESP32 and stream the original bytes (chunked,
// because the uncompressed size is not known up front)
static bool serveGzipInflated(File &gz, const String &ct) {
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, ct, "");
  gResponseStarted = true;

  wk_inflate_setup(gInf, fileFill, &gz, socketPush, nullptr, true);
  int rc = wk_inflate_run(gInf);

  server.sendContent("");        // terminating 0-chunk

  uint32_t out = wk_inflate_out_size(gInf);
  gz.close();

  if (rc == WK_INFLATE_STOPPED) {
    // client hung up mid-body (e.g. the PS4 update-check probe aborts as soon
    // as it has seen enough) -- the stream was fine, the reader just left.
    Serial.printf("  client closed early (%u bytes)\n", (unsigned)out);
    return true;
  }
  if (rc != WK_INFLATE_OK) {
    Serial.printf("  inflate failed rc=%d after %u bytes\n", rc, (unsigned)out);
    return false;
  }
  return true;
}

// ------------------------------------------------------------------- .zk ---
static size_t zkBaseFill(void *ctx, uint8_t *buf, size_t cap) {
  ZkStream *z = (ZkStream *)ctx;
  return z->base.read(buf, cap);
}

// read (or discard, out == nullptr) `n` decoded bytes of the base file
static bool zkBaseRead(ZkStream *z, uint8_t *out, size_t n) {
  while (n) {
    if (z->pos >= z->len) {
      if (z->baseRaw) {
        z->len = z->base.read(z->buf, sizeof(z->buf));
        z->pos = 0;
        if (!z->len) return false;                // base ended too early
      } else {
        long got = wk_inflate_pull(z->inf, z->buf, sizeof(z->buf));
        if (got <= 0) return false;
        z->len = (size_t)got;
        z->pos = 0;
      }
    }
    size_t take = n;
    if (take > z->len - z->pos) take = z->len - z->pos;
    if (out) memcpy(out, z->buf + z->pos, take);
    z->pos += take;
    n -= take;
  }
  return true;
}

static bool zkSend(const uint8_t *p, size_t n) {
  while (n) {
    size_t c = (n > 1460) ? 1460 : n;
    server.sendContent((const char *)p, c);
    if (!server.client().connected()) return false;
    p += c;
    n -= c;
  }
  return true;
}

// rebuild <path> from <path>.zk + its base, streaming straight to the client
static bool serveZk(const String &zkPath, const String &ct) {
  File zk = LittleFS.open(zkPath, "r");
  if (!zk) return false;

  uint8_t hdr[10];
  if (zk.read(hdr, 10) != 10 || memcmp(hdr, "WK1", 3) != 0 || hdr[3] != 1) {
    zk.close();
    Serial.printf("  bad .zk header: %s\n", zkPath.c_str());
    return false;
  }
  uint32_t usize = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                   ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
  uint16_t baseLen = (uint16_t)hdr[8] | ((uint16_t)hdr[9] << 8);
  if (baseLen == 0 || baseLen > 255) { zk.close(); return false; }

  char basePath[256];
  if (zk.read((uint8_t *)basePath, baseLen) != baseLen) { zk.close(); return false; }
  basePath[baseLen] = 0;

  uint8_t ol[4];
  if (zk.read(ol, 4) != 4) { zk.close(); return false; }
  uint32_t opsLen = (uint32_t)ol[0] | ((uint32_t)ol[1] << 8) |
                    ((uint32_t)ol[2] << 16) | ((uint32_t)ol[3] << 24);

  ZkStream z;
  z.len = z.pos = 0;
  z.inf = gInf;

  // wkpack stores the exact on-flash base path in the header (already
  // carrying its .gz suffix, and shortened if it was over 32 chars)
  String bp = flashPath(String(basePath));
  z.baseRaw = true;
  if (bp.endsWith(".gz")) {
    z.baseRaw = false;
  } else if (LittleFS.exists(bp + ".gz")) {
    bp += ".gz";
    z.baseRaw = false;
  }
  z.base = LittleFS.open(bp, "r");
  if (!z.base) {
    zk.close();
    Serial.printf("  .zk base missing: %s\n", bp.c_str());
    return false;
  }
  if (!z.baseRaw) wk_inflate_setup(gInf, zkBaseFill, &z, nullptr, nullptr, true);

  server.setContentLength(usize);
  server.send(200, ct, "");
  gResponseStarted = true;

  z.ops = zk;
  uint32_t remaining = opsLen;
  bool ok = true;

  while (ok && remaining >= 5) {
    uint8_t oph[5];
    if (z.ops.read(oph, 5) != 5) break;
    remaining -= 5;
    uint8_t kind = oph[0];
    uint32_t n = (uint32_t)oph[1] | ((uint32_t)oph[2] << 8) |
                 ((uint32_t)oph[3] << 16) | ((uint32_t)oph[4] << 24);

    if (kind == 0) {                            // literal: bytes from .zk
      while (ok && n) {
        uint32_t c = (n > sizeof(gScratch)) ? (uint32_t)sizeof(gScratch) : n;
        if (z.ops.read(gScratch, c) != c) { ok = false; break; }
        ok = zkSend(gScratch, c);
        n -= c;
      }
    } else if (kind == 1) {                     // copy: decoded base bytes
      while (ok && n) {
        uint32_t c = (n > sizeof(gScratch)) ? (uint32_t)sizeof(gScratch) : n;
        if (!zkBaseRead(&z, gScratch, c)) { ok = false; break; }
        ok = zkSend(gScratch, c);
        n -= c;
      }
    } else if (kind == 2) {                     // skip: advance the base
      if (!zkBaseRead(&z, nullptr, n)) ok = false;
    } else {
      ok = false;                               // unknown op
    }
  }

  z.ops.close();
  z.base.close();
  if (!ok) {
    if (!server.client().connected()) {
      Serial.printf("  client closed early (.zk): %s\n", zkPath.c_str());
    } else {
      Serial.printf("  .zk stream aborted: %s\n", zkPath.c_str());
    }
  }
  return ok;
}

// mklittlefs silently drops path components longer than 32 chars, so wkpack
// stores a few files under a shortened name; map them back before lookup
static String flashPath(const String &path) {
  for (size_t i = 0; i < sizeof(wk_renames) / sizeof(wk_renames[0]); i++) {
    if (path == wk_renames[i].req) return String(wk_renames[i].flash);
  }
  return path;
}

// ---------------------------------------------------------------- router ---
bool handleFile(String path) {
  gResponseStarted = false;
  if (path.endsWith("/")) path += "index.html";
  int q = path.indexOf('?');
  if (q >= 0) path = path.substring(0, q);
  int hs = path.indexOf('#');
  if (hs >= 0) path = path.substring(0, hs);
  if (path.indexOf("..") >= 0) return false;

  String ct = getContentType(path);
  path = flashPath(path);

  // 1. WKBC derived entry
  if (LittleFS.exists(path + ".zk")) {
    Serial.printf("Served(zk):    %s\n", path.c_str());
    return serveZk(path + ".zk", ct);
  }

  // 2. gzip copy: passthrough when the client can inflate it itself
  if (LittleFS.exists(path + ".gz")) {
    File gz = LittleFS.open(path + ".gz", "r");
    if (!gz) return false;
    if (clientWantsGzip()) {
      Serial.printf("Served(gz):    %s\n", path.c_str());
      return serveGzipPassthrough(gz, ct);
    }
    Serial.printf("Served(infl):  %s\n", path.c_str());
    return serveGzipInflated(gz, ct);
  }

  // 3. stored plain
  if (LittleFS.exists(path)) {
    File f = LittleFS.open(path, "r");
    if (!f) return false;
    Serial.printf("Served(plain): %s\n", path.c_str());
    return servePlain(f, ct);
  }

  return false;
}

void serveIndex() {
  if (!handleFile("/index.html") && !gResponseStarted) {
    server.send(500, "text/plain", "index.html missing!");
  }
}

// ---------------------------------------------------------------- regions --
// The PS4 User Guide is served from /document/<region>/ps4/ where <region>
// depends on the console (en, gb, us, jp, kr, cn, zh-hant, ...). Instead of
// hardcoding one code, recognise the shape and strip it so every region lands
// on the same asset tree.
//   /document/gb/ps4/includes/js/app.js -> /includes/js/app.js
//   /document/jp/ps4/                   -> /
//   /document/kr/ps4                    -> /
static bool stripDocumentPrefix(const String &uri, String &out) {
  if (!uri.startsWith("/document/")) return false;

  const int docLen = 10;                       // strlen("/document/")
  int regionEnd = uri.indexOf('/', docLen);
  if (regionEnd < 0) return false;

  int regionLen = regionEnd - docLen;
  if (regionLen < 2 || regionLen > 8) return false;   // en .. zh-hant

  int ps4End = uri.indexOf('/', regionEnd + 1);
  String seg = (ps4End < 0) ? uri.substring(regionEnd + 1)
                            : uri.substring(regionEnd + 1, ps4End);
  if (!seg.equalsIgnoreCase("ps4")) return false;

  out = (ps4End < 0) ? String("/") : uri.substring(ps4End);
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(800);

  btStop();

  if (!LittleFS.begin(true)) {
    Serial.println("FATAL: LittleFS mount failed!");
    while (true) delay(1000);
  }
  Serial.println("LittleFS OK");

  gInf = wk_inflate_alloc();
  if (!gInf) {
    Serial.println("FATAL: inflate state alloc failed!");
    while (true) delay(1000);
  }

  WiFi.mode(WIFI_OFF);
  delay(300);
  WiFi.mode(WIFI_AP);
  delay(300);

  esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G);
  esp_wifi_set_max_tx_power(78);

  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ssid, password, apChannel, 0, 4);
  WiFi.setSleep(WIFI_PS_NONE);

  delay(200);

  Serial.println();
  Serial.println("=================================");
  Serial.printf("SSID     : %s (open)\n", ssid);
  Serial.printf("Channel  : %d\n", WiFi.channel());
  Serial.printf("IP       : %s\n", WiFi.softAPIP().toString().c_str());
  Serial.println("=================================");
  Serial.println();

  dnsServer.start(53, "*", apIP);

  // needed to inspect Accept-Encoding for the gzip passthrough decision
  const char *headerKeys[] = {"Accept-Encoding"};
  server.collectHeaders(headerKeys, 1);

  // Root
  server.on("/", HTTP_GET, []() {
    serveIndex();
  });

  // Exploit telemetry (POST). Register both spellings so the body parser runs
  // as a POST handler and `tag`/`detail` end up in server.arg().
  server.on("/t", HTTP_POST, handleTelemetry);
  server.on("/document/en/ps4/t", HTTP_POST, handleTelemetry);

  // Everything else
  server.onNotFound([]() {
    String uri = server.uri();

    // telemetry POST that did not match the exact routes above
    if (server.method() == HTTP_POST && uri.endsWith("/t")) {
      handleTelemetry();
      return;
    }

    Serial.printf("Request: %s\n", uri.c_str());

    // 1. Sony update check → index
    if (uri.indexOf("ps4-updatelist.xml") >= 0 || uri.indexOf("/update/ps4/") >= 0) {
      Serial.println("→ Update check → index.html");
      serveIndex();
      return;
    }

    // 2. User Guide, ANY region: /document/<region>/ps4/...
    //    <region> is whatever the console sends (en, gb, us, jp, kr, cn,
    //    zh-hant, ...), so match the shape rather than one hardcoded code.
    String mapped;
    if (stripDocumentPrefix(uri, mapped)) {
      Serial.printf("→ Region path → %s\n", mapped.c_str());
      if (handleFile(mapped)) {
        return;
      }
      server.send(404, "text/plain", "Mapped file not found: " + mapped);
      return;
    }

    // 3. Normal requests (when using the browser directly)
    if (handleFile(uri)) {
      return;
    }

    // 4. Last resort: an unfamiliar layout that still contains a /ps4/ segment.
    //    Serve whatever follows the last one, so a region we have never seen
    //    reaches the assets instead of dying on a 404.
    int ps4 = uri.lastIndexOf("/ps4/");
    if (ps4 >= 0) {
      String tail = uri.substring(ps4 + 4);   // keep the leading '/'
      Serial.printf("→ ps4 fallback → %s\n", tail.c_str());
      if (handleFile(tail)) {
        return;
      }
    }

    // 5. Real 404
    server.send(404, "text/plain", "File not found: " + uri);
  });

  server.begin();
  Serial.println("HTTP server ready");
  Serial.println("Open Settings → User's Guide on PS4");
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();
}
