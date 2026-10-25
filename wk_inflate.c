/*
 * wk_inflate.c - minimal streaming DEFLATE / gzip decoder (RFC 1951 / 1952)
 *
 * Design notes
 * ------------
 *  - blocking decode driven by two callbacks: fill() pulls compressed bytes,
 *    push() hands decompressed bytes to the consumer (HTTP socket, test file).
 *    No suspend/resume state machine is needed, which keeps the code small
 *    and easy to prove correct on the host.
 *  - 32 kB history window + 2 kB input buffer + 4 kB output staging buffer,
 *    all inside the (malloc'ed) state, so ~39 kB of RAM per active decode.
 *  - canonical Huffman decoding in the style of puff.c (Mark Adler, public
 *    domain): read one bit at a time and walk the (count, symbol) tables.
 *  - gzip headers/trailers are parsed and the CRC32/ISIZE are verified, so a
 *    corrupted LittleFS image is detected instead of being sent to the PS4.
 */
#include "wk_inflate.h"

#include <stdlib.h>
#include <string.h>

#define WK_MAXBITS   15
#define WK_WINBITS   15
#define WK_WINDOW    (1u << WK_WINBITS)   /* 32768, deflate max distance      */
#define WK_IN_BUF    2048
#define WK_OUT_BUF   4096

/* ---------------------------------------------------------------- crc32 -- */

static uint32_t wk_crc_tbl[256];
static int      wk_crc_ready = 0;

static void wk_crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        wk_crc_tbl[i] = c;
    }
    wk_crc_ready = 1;
}

/* continuing CRC32: pass 0 for the first block, the result of the previous
 * call for every following block (same convention as zlib's crc32())        */
uint32_t wk_crc32(uint32_t crc, const uint8_t *buf, size_t len)
{
    if (!wk_crc_ready) wk_crc_init();
    crc ^= 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = wk_crc_tbl[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ---------------------------------------------------------------- huffman - */

typedef struct {
    short count[WK_MAXBITS + 1];   /* number of codes of each length        */
    short symbol[288];             /* symbols sorted by (length, symbol)    */
} wk_huff;

/* Build canonical tables from a list of code lengths (0 = unused).
 * Returns 0, or -1 when the code is over-subscribed. Incomplete tables are
 * tolerated on purpose: every .gz we store is CRC checked afterwards, and
 * the "single distance code" case of RFC 1951 is incomplete by design.      */
static int wk_huff_build(wk_huff *h, const uint8_t *lengths, int n)
{
    int symbol, len;
    short offs[WK_MAXBITS + 1];

    memset(h->count, 0, sizeof(h->count));
    for (symbol = 0; symbol < n; symbol++)
        h->count[lengths[symbol]]++;
    if (h->count[0] == n) return 0;            /* no codes at all           */

    /* over-subscribed? */
    {
        int left = 1;
        for (len = 1; len <= WK_MAXBITS; len++) {
            left <<= 1;
            left -= h->count[len];
            if (left < 0) return -1;
        }
    }

    offs[1] = 0;
    for (len = 1; len < WK_MAXBITS; len++)
        offs[len + 1] = (short)(offs[len] + h->count[len]);

    for (symbol = 0; symbol < n; symbol++)
        if (lengths[symbol])
            h->symbol[offs[lengths[symbol]]++] = (short)symbol;
    return 0;
}

/* ------------------------------------------------------------- bit reader - */

struct wk_inflate_s {
    wk_fill_fn fill;   void *fill_ctx;
    wk_push_fn push;   void *push_ctx;

    uint8_t  in[WK_IN_BUF];
    size_t   in_len, in_pos;
    uint8_t  out[WK_OUT_BUF];
    size_t   out_len;
    uint8_t  window[WK_WINDOW];
    uint32_t wpos;          /* total bytes written to the window            */

    uint64_t bitbuf;
    int      bitcnt;
    int      used_mod8;     /* bits consumed so far, modulo 8               */

    int      eof;           /* fill() returned 0                            */
    int      halted;        /* consumer refused more data                   */
    int      is_gzip;
    int      member_started;/* current gzip member header already parsed     */
    int      done;          /* whole stream decoded and checksummed          */

    /* block decoder state - lives in the struct so a consumer that halts
     * mid-block (short push) can be resumed without losing its position  */
    int      blk_state;     /* 0=header, 1=stored body, 2=coded body        */
    int      blk_final;     /* BFINAL of the block being decoded            */
    uint32_t blk_left;      /* bytes left in a stored block                 */
    int      body_done;     /* all blocks of the member decoded             */
    wk_huff  lencode, distcode;  /* tables of the block in progress         */
    uint32_t rep_dist;      /* interrupted length/distance copy             */
    uint32_t rep_left;

    uint32_t crc;           /* gzip running CRC32                           */
    uint32_t misize;        /* uncompressed size of the current gzip member  */
    uint32_t total;         /* uncompressed size of everything decoded       */

    /* pull-mode sink: set by wk_inflate_pull(), filled by wk_sink_push()    */
    int      pending_err;   /* sticky error from a previous pull             */
    uint8_t *sink_buf;      /* destination the caller asked for              */
    size_t   sink_cap;
    size_t   sink_len;      /* bytes placed into sink_buf so far             */
    int      sink_pushed;   /* push callback has been wired to wk_sink_push  */
};

/* pull more input; returns 0 on success, 1 on end of stream */
static int wk_refill(wk_inflate_t *s)
{
    if (s->in_pos < s->in_len) return 0;
    if (s->eof) return 1;
    s->in_len = s->fill ? s->fill(s->fill_ctx, s->in, WK_IN_BUF) : 0;
    s->in_pos = 0;
    if (s->in_len == 0) { s->eof = 1; return 1; }
    return 0;
}

/* read `need` bits (<= 30) into *out, LSB first */
static int wk_bits(wk_inflate_t *s, int need, uint32_t *out)
{
    uint64_t v = s->bitbuf;
    int n = s->bitcnt;

    while (n < need) {
        if (wk_refill(s)) return WK_INFLATE_ERR_TRUNC;
        v |= (uint64_t)s->in[s->in_pos++] << n;
        n += 8;
    }
    if (need == 32) *out = (uint32_t)v;
    else            *out = (uint32_t)(v & ((1u << need) - 1u));
    s->bitbuf = v >> need;
    s->bitcnt = n - need;
    s->used_mod8 = (s->used_mod8 + need) & 7;
    return 0;
}

/* skip the padding bits of the current byte (stored blocks / gzip trailer) */
static int wk_byte_align(wk_inflate_t *s)
{
    int pad = (8 - s->used_mod8) & 7;

    if (pad) {
        if (s->bitcnt < pad) {
            while (s->bitcnt < pad) {
                if (wk_refill(s)) return WK_INFLATE_ERR_TRUNC;
                s->bitbuf |= (uint64_t)s->in[s->in_pos++] << s->bitcnt;
                s->bitcnt += 8;
            }
        }
        s->bitbuf   >>= pad;
        s->bitcnt    -= pad;
        s->used_mod8  = 0;
    }
    return 0;
}

/* decode one symbol using a canonical table */
static int wk_decode(wk_inflate_t *s, const wk_huff *h, short *sym)
{
    int len, code = 0, first = 0, index = 0;

    for (len = 1; len <= WK_MAXBITS; len++) {
        uint32_t b;
        int rc = wk_bits(s, 1, &b);
        if (rc) return rc;
        code |= (int)b;
        {
            int count = h->count[len];
            if (code - first < count) { *sym = h->symbol[index + (code - first)]; return 0; }
            index += count;
            first += count;
            first <<= 1;
            code   <<= 1;
        }
    }
    return WK_INFLATE_ERR_FORMAT;
}

/* ----------------------------------------------------------- output path -- */

/* Push whatever is staged to the consumer. The consumer may accept only part
 * of it (a .zk patch handler that has reached its byte budget); the rest is
 * shifted to the front of the buffer so the decoder can be resumed later.  */
static int wk_flush(wk_inflate_t *s)
{
    size_t n = s->out_len;
    if (!n) return 0;

    if (!s->push) { s->out_len = 0; return 0; }

    {
        size_t got = s->push(s->push_ctx, s->out, n);
        if (got != n) {
            memmove(s->out, s->out + got, n - got);
            s->out_len = n - got;
            s->halted = 1;
            return WK_INFLATE_STOPPED;
        }
    }
    s->out_len = 0;
    return 0;
}

/* push callback used in pull mode: copy staged bytes into the caller's
 * buffer, up to its capacity. Accepting fewer bytes makes wk_flush() keep the
 * remainder staged and halt, which is exactly what we want when the caller's
 * buffer is smaller than what the decoder produced in this pass.            */
static size_t wk_sink_push(void *ctx, const uint8_t *buf, size_t len)
{
    wk_inflate_t *s = (wk_inflate_t *)ctx;
    size_t room = (s->sink_len < s->sink_cap) ? (s->sink_cap - s->sink_len) : 0;
    size_t n = (len < room) ? len : room;
    if (n) memcpy(s->sink_buf + s->sink_len, buf, n);
    s->sink_len += n;
    return n;
}

static int wk_put(wk_inflate_t *s, uint8_t b)
{
    s->window[s->wpos & (WK_WINDOW - 1)] = b;
    s->wpos++;
    s->misize++;
    s->total++;
    /* CRC is folded in per byte so that a flush that is only partly consumed
     * (resumed later) never double counts or loses bytes.                     */
    if (s->is_gzip) s->crc = wk_crc32(s->crc, &b, 1);
    s->out[s->out_len++] = b;
    if (s->out_len == WK_OUT_BUF) return wk_flush(s);
    return 0;
}

/* start a length/distance copy; a consumer halt in the middle leaves the
 * remainder in s->rep_*, which wk_codes() finishes on the next resume      */
static int wk_put_repeat(wk_inflate_t *s, uint32_t dist, uint32_t len)
{
    if (dist == 0 || dist > s->wpos) return WK_INFLATE_ERR_FORMAT;
    s->rep_dist = dist;
    s->rep_left = len;
    while (s->rep_left) {
        uint8_t b = s->window[(s->wpos - s->rep_dist) & (WK_WINDOW - 1)];
        int rc;
        s->rep_left--;          /* the byte is committed once wk_put ran    */
        rc = wk_put(s, b);
        if (rc) return rc;
    }
    return 0;
}

/* --------------------------------------------------------------- blocks --- */

static const uint16_t wk_len_base[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
static const uint8_t wk_len_extra[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
static const uint16_t wk_dist_base[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
static const uint8_t wk_dist_extra[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };

/* code lengths for the code-length alphabet (RFC 1951, section 3.2.7) */
static const uint8_t wk_clen_order[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

/* stored block body; s->blk_left holds the remaining byte count so a halted
 * consumer resumes in the middle instead of re-reading the block header     */
static int wk_stored(wk_inflate_t *s)
{
    uint32_t b;
    int rc;

    while (s->blk_left) {
        rc = wk_bits(s, 8, &b);
        if (rc) return rc;
        s->blk_left--;          /* the byte is committed once wk_put ran    */
        rc = wk_put(s, (uint8_t)b);
        if (rc) return rc;
    }
    return 0;
}

/* read a stored block header (byte align + LEN/NLEN) into s->blk_left */
static int wk_stored_header(wk_inflate_t *s)
{
    uint32_t len, nlen;
    int rc;

    rc = wk_byte_align(s);
    if (rc) return rc;

    rc = wk_bits(s, 16, &len);  if (rc) return rc;
    rc = wk_bits(s, 16, &nlen); if (rc) return rc;
    if ((len ^ 0xFFFFu) != nlen) return WK_INFLATE_ERR_FORMAT;

    s->blk_left = len;
    return 0;
}

static int wk_codes(wk_inflate_t *s, const wk_huff *lencode, const wk_huff *distcode)
{
    /* finish a copy interrupted by a consumer halt before decoding more */
    if (s->rep_left) {
        int rc = wk_put_repeat(s, s->rep_dist, s->rep_left);
        if (rc) return rc;
    }

    for (;;) {
        short sym;
        int rc = wk_decode(s, lencode, &sym);
        if (rc) return rc;

        if (sym < 256) {
            rc = wk_put(s, (uint8_t)sym);
            if (rc) return rc;
        } else if (sym == 256) {
            return 0;                                  /* end of block      */
        } else {
            uint32_t extra, dist;
            int li = (int)sym - 257;
            if (li > 28) return WK_INFLATE_ERR_FORMAT;

            rc = wk_bits(s, wk_len_extra[li], &extra);
            if (rc) return rc;
            {
                uint32_t length = wk_len_base[li] + extra;

                short dsym;
                rc = wk_decode(s, distcode, &dsym);
                if (rc) return rc;
                if (dsym > 29) return WK_INFLATE_ERR_FORMAT;

                rc = wk_bits(s, wk_dist_extra[dsym], &extra);
                if (rc) return rc;
                dist = wk_dist_base[dsym] + extra;

                rc = wk_put_repeat(s, dist, length);
                if (rc) return rc;
            }
        }
    }
}

static int wk_fixed_tables(wk_huff *lencode, wk_huff *distcode)
{
    uint8_t lengths[288];
    int i;

    for (i = 0; i < 144; i++) lengths[i] = 8;
    for (; i < 256; i++)      lengths[i] = 9;
    for (; i < 280; i++)      lengths[i] = 7;
    for (; i < 288; i++)      lengths[i] = 8;
    if (wk_huff_build(lencode, lengths, 288)) return WK_INFLATE_ERR_FORMAT;

    for (i = 0; i < 30; i++) lengths[i] = 5;
    if (wk_huff_build(distcode, lengths, 30)) return WK_INFLATE_ERR_FORMAT;
    return 0;
}

static int wk_dynamic_tables(wk_inflate_t *s, wk_huff *lencode, wk_huff *distcode)
{
    uint8_t lengths[320];
    wk_huff codelen;
    uint32_t hlit, hdist, hclen;
    int n, rc;

    rc = wk_bits(s, 5, &hlit);  if (rc) return rc;
    rc = wk_bits(s, 5, &hdist); if (rc) return rc;
    rc = wk_bits(s, 4, &hclen); if (rc) return rc;

    hlit += 257;
    hdist += 1;
    hclen += 4;
    if (hlit > 286 || hdist > 30) return WK_INFLATE_ERR_FORMAT;

    memset(lengths, 0, sizeof(lengths));
    for (n = 0; n < (int)hclen; n++) {
        uint32_t l;
        rc = wk_bits(s, 3, &l); if (rc) return rc;
        lengths[wk_clen_order[n]] = (uint8_t)l;
    }
    for (; n < 19; n++) lengths[wk_clen_order[n]] = 0;

    if (wk_huff_build(&codelen, lengths, 19)) return WK_INFLATE_ERR_FORMAT;

    n = 0;
    while (n < (int)(hlit + hdist)) {
        short sym;
        rc = wk_decode(s, &codelen, &sym);
        if (rc) return rc;

        if (sym < 16) {
            lengths[n++] = (uint8_t)sym;
        } else {
            uint32_t rep;
            uint8_t value = 0;
            int len = 0;
            if (sym == 16) {
                if (n == 0) return WK_INFLATE_ERR_FORMAT;
                value = lengths[n - 1];
                rc = wk_bits(s, 2, &rep); if (rc) return rc;
                len = 3 + (int)rep;
            } else if (sym == 17) {
                rc = wk_bits(s, 3, &rep); if (rc) return rc;
                len = 3 + (int)rep;
            } else {                          /* 18 */
                rc = wk_bits(s, 7, &rep); if (rc) return rc;
                len = 11 + (int)rep;
            }
            if (n + len > (int)(hlit + hdist)) return WK_INFLATE_ERR_FORMAT;
            while (len--) lengths[n++] = value;
        }
    }
    if (lengths[256] == 0) return WK_INFLATE_ERR_FORMAT;  /* need EOB code */

    if (wk_huff_build(lencode,  lengths, (int)hlit))           return WK_INFLATE_ERR_FORMAT;
    if (wk_huff_build(distcode, lengths + (int)hlit, (int)hdist)) return WK_INFLATE_ERR_FORMAT;
    return 0;
}

/* ---------------------------------------------------------- gzip wrapper -- */

static int wk_gzip_header(wk_inflate_t *s)
{
    uint32_t v;
    int rc;

    rc = wk_bits(s, 16, &v); if (rc) return rc;   /* ID1 | ID2<<8            */
    if ((v & 0xFFFFu) != 0x8B1Fu) return WK_INFLATE_ERR_FORMAT;
    rc = wk_bits(s, 8, &v);  if (rc) return rc;   /* CM                     */
    if (v != 8) return WK_INFLATE_ERR_FORMAT;
    rc = wk_bits(s, 8, &v);  if (rc) return rc;   /* FLG                    */
    {
        uint32_t flg = v;

        rc = wk_bits(s, 32, &v); if (rc) return rc;  /* MTIME (4 bytes)       */
        rc = wk_bits(s, 8, &v);  if (rc) return rc;  /* XFL                   */
        rc = wk_bits(s, 8, &v);  if (rc) return rc;  /* OS                    */

        if (flg & 0x04) {                          /* FEXTRA                 */
            uint32_t xlen;
            rc = wk_bits(s, 16, &xlen); if (rc) return rc;
            while (xlen--) { rc = wk_bits(s, 8, &v); if (rc) return rc; }
        }
        if (flg & 0x08) {                          /* FNAME                  */
            do { rc = wk_bits(s, 8, &v); if (rc) return rc; } while (v);
        }
        if (flg & 0x10) {                          /* FCOMMENT               */
            do { rc = wk_bits(s, 8, &v); if (rc) return rc; } while (v);
        }
        if (flg & 0x02) {                          /* FHCRC                  */
            rc = wk_bits(s, 16, &v); if (rc) return rc;
        }
        if (flg & 0xE0) return WK_INFLATE_ERR_FORMAT;   /* reserved bits     */
    }
    return 0;
}

static int wk_gzip_footer(wk_inflate_t *s)
{
    uint32_t crc_stored, isize_stored;
    int rc;

    rc = wk_byte_align(s);
    if (rc == WK_INFLATE_ERR_TRUNC) return WK_INFLATE_OK;   /* no trailer    */

    /* 32 bits LSB first == little endian field order */
    rc = wk_bits(s, 32, &crc_stored);  if (rc == WK_INFLATE_ERR_TRUNC) return WK_INFLATE_OK;
    rc = wk_bits(s, 32, &isize_stored); if (rc == WK_INFLATE_ERR_TRUNC) return WK_INFLATE_OK;
    if (rc) return rc;

    if (crc_stored != s->crc)    return WK_INFLATE_ERR_CHECK;
    if (isize_stored != s->misize) return WK_INFLATE_ERR_CHECK;
    return 0;
}

/* ---------------------------------------------------------------- public -- */

wk_inflate_t *wk_inflate_alloc(void)
{
    if (!wk_crc_ready) wk_crc_init();
    return (wk_inflate_t *)calloc(1, sizeof(wk_inflate_t));
}

void wk_inflate_free(wk_inflate_t *s)
{
    free(s);
}

void wk_inflate_setup(wk_inflate_t *s,
                      wk_fill_fn fill, void *fill_ctx,
                      wk_push_fn push, void *push_ctx,
                      int is_gzip)
{
    memset(s, 0, sizeof(*s));
    s->fill = fill; s->fill_ctx = fill_ctx;
    s->push = push; s->push_ctx = push_ctx;
    s->is_gzip = is_gzip;
    s->crc = 0;                        /* wk_crc32() does the conditioning  */
}

uint32_t wk_inflate_out_size(const wk_inflate_t *s)
{
    return s ? s->total : 0;
}

/* decode one gzip member / deflate stream (up to and including its footer).
 * The block state lives in the struct, so halting in the middle of any block
 * and resuming later continues exactly where the decode stopped.            */
static int wk_member(wk_inflate_t *s)
{
    int rc;

    for (;;) {
        if (s->blk_state == 0) {                /* block header            */
            uint32_t bfinal, btype;

            if (s->body_done) break;

            rc = wk_bits(s, 1, &bfinal); if (rc) return rc;
            rc = wk_bits(s, 2, &btype);  if (rc) return rc;
            s->blk_final = (int)bfinal;

            switch (btype) {
            case 0:                                    /* stored           */
                rc = wk_stored_header(s);
                if (rc) return rc;
                s->blk_state = 1;
                break;
            case 1:                                    /* fixed            */
                rc = wk_fixed_tables(&s->lencode, &s->distcode);
                if (rc) return rc;
                s->blk_state = 2;
                break;
            case 2:                                    /* dynamic          */
                rc = wk_dynamic_tables(s, &s->lencode, &s->distcode);
                if (rc) return rc;
                s->blk_state = 2;
                break;
            default:                                   /* reserved         */
                return WK_INFLATE_ERR_FORMAT;
            }
        } else if (s->blk_state == 1) {          /* stored body           */
            rc = wk_stored(s);
            if (rc) return rc;
            s->blk_state = 0;
        } else {                                   /* coded body           */
            rc = wk_codes(s, &s->lencode, &s->distcode);
            if (rc) return rc;
            s->blk_state = 0;
        }

        if (s->blk_final) s->body_done = 1;
    }

    rc = wk_flush(s);                              /* flush the staging buf */
    if (rc) return rc;

    if (s->is_gzip) rc = wk_gzip_footer(s);
    return rc;
}

/* true when the input still holds bytes that were not decoded yet */
static int wk_more_input(wk_inflate_t *s)
{
    if (s->bitcnt >= 8) return 1;                  /* buffered whole bytes   */
    return wk_refill(s) == 0;
}

int wk_inflate_run(wk_inflate_t *s)
{
    int rc;

    if (!s) return WK_INFLATE_ERR_MEM;
    if (s->done) return WK_INFLATE_OK;
    s->halted = 0;                 /* a resumed consumer may keep pulling     */

    /* resume: hand any staged output to the (possibly new) sink before
     * decoding more, otherwise a full staging buffer would stall forever  */
    if (s->out_len) {
        int rc0 = wk_flush(s);
        if (rc0) return rc0;
    }

    for (;;) {
        if (s->is_gzip && !s->member_started) {
            rc = wk_gzip_header(s);
            if (rc) return rc;
            s->member_started = 1;
            s->crc = 0;            /* every member carries its own CRC/size   */
            s->misize = 0;
            s->blk_state = 0;      /* fresh block decoder state               */
            s->body_done = 0;
            s->blk_left = 0;
            s->rep_left = 0;
        }
        rc = wk_member(s);
        if (rc == WK_INFLATE_STOPPED) return rc; /* keep state for the resume */
        if (rc) return rc;
        s->member_started = 0;
        s->blk_state = 0;          /* ready for the next member               */
        s->body_done = 0;
        s->rep_left = 0;
        /* concatenated gzip members are legal ("cat a.gz b.gz") */
        if (!s->is_gzip || !wk_more_input(s)) break;
    }
    s->done = 1;
    return WK_INFLATE_OK;
}

/* Pull up to `cap` decompressed bytes. Returns the byte count, 0 at end of
 * stream, or a negative WK_INFLATE_ERR_* code. Safe to call repeatedly: the
 * decoder resumes exactly where the previous call stopped.                   */
long wk_inflate_pull(wk_inflate_t *s, uint8_t *buf, size_t cap)
{
    if (!s || !buf) return WK_INFLATE_ERR_MEM;
    if (s->pending_err) return s->pending_err;

    s->sink_buf = buf;
    s->sink_cap = cap;
    s->sink_len = 0;

    if (!s->sink_pushed) {
        s->push = wk_sink_push;
        s->push_ctx = s;
        s->sink_pushed = 1;
    }

    int rc = wk_inflate_run(s);
    if (rc != WK_INFLATE_OK && rc != WK_INFLATE_STOPPED) {
        s->pending_err = rc;
        return rc;
    }
    if (rc == WK_INFLATE_OK && s->out_len) {
        /* stream ended with bytes still staged: hand them over first */
        size_t n = s->out_len;
        if (n > cap - s->sink_len) n = cap - s->sink_len;
        memcpy(buf + s->sink_len, s->out, n);
        s->sink_len += n;
        memmove(s->out, s->out + n, s->out_len - n);
        s->out_len -= n;
    }
    s->halted = 0;                 /* ready for the next pull                 */
    return (long)s->sink_len;
}
