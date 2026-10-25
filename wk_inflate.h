/*
 * wk_inflate.h - minimal streaming DEFLATE / gzip decoder (RFC 1950/1951/1952)
 *
 * Written for WebKitty so the ESP32-S3 can serve files that are stored on
 * LittleFS in compressed form even when the client does not advertise
 * "Accept-Encoding: gzip" (curl, tools, PS4 payload loaders, ...).
 *
 * Pure C, no allocation inside (the caller provides the state), no libc
 * streaming dependencies - so it can be unit tested on the host.
 *
 * Usage:
 *     wk_inflate_t *s = wk_inflate_alloc();
 *     wk_inflate_setup(s, fill_cb, fill_ctx, push_cb, push_ctx, is_gzip);
 *     int rc = wk_inflate_run(s);
 *     wk_inflate_free(s);
 *
 * fill() must return 0 on end-of-stream.
 * push() returns the number of bytes accepted; returning less than `len`
 * halts the decoder (used when a consumer only needs part of a stream).
 */
#ifndef WK_INFLATE_H
#define WK_INFLATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* return codes of wk_inflate_run() */
#define WK_INFLATE_OK          0   /* stream decoded and checksums verified  */
#define WK_INFLATE_ERR_FORMAT -1   /* malformed deflate stream              */
#define WK_INFLATE_ERR_TRUNC  -2   /* input ended in the middle of a stream  */
#define WK_INFLATE_ERR_CHECK  -3   /* gzip CRC32 / ISIZE mismatch            */
#define WK_INFLATE_ERR_MEM    -4
#define WK_INFLATE_STOPPED     1   /* consumer stopped pulling data          */

/* read up to `cap` bytes, return how many were written, 0 = end of stream */
typedef size_t (*wk_fill_fn)(void *ctx, uint8_t *buf, size_t cap);
/* consume `len` bytes, return how many were accepted (short = stop) */
typedef size_t (*wk_push_fn)(void *ctx, const uint8_t *buf, size_t len);

typedef struct wk_inflate_s wk_inflate_t;

/* allocate / release the decoder state (~40 kB) */
wk_inflate_t *wk_inflate_alloc(void);
void wk_inflate_free(wk_inflate_t *s);

/* configure a freshly allocated (or reused) state */
void wk_inflate_setup(wk_inflate_t *s,
                      wk_fill_fn fill, void *fill_ctx,
                      wk_push_fn push, void *push_ctx,
                      int is_gzip);

/* decode the whole stream; returns one of the codes above */
int wk_inflate_run(wk_inflate_t *s);

/* Pull-mode API: decode and return up to `cap` bytes into `buf`.
 * Returns the byte count (0 = end of stream) or a negative WK_INFLATE_ERR_*.
 * Resumable: call repeatedly with the same state until it returns 0.        */
long wk_inflate_pull(wk_inflate_t *s, uint8_t *buf, size_t cap);

/* bytes pushed out so far (valid during/after the run) */
uint32_t wk_inflate_out_size(const wk_inflate_t *s);

/* helpers shared with the firmware (also used to parse gzip footers) */
uint32_t wk_crc32(uint32_t crc, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WK_INFLATE_H */
