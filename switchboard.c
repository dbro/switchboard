/*
 * switchboard — local WebSocket pub/sub broker
 *
 * WebSocket endpoint:  ws://127.0.0.1:PORT/ws
 *
 * Subscriber connects and registers interest in one or more channels:
 *   send: {"type":"subscribe","channels":["id1","id2",...]}
 *
 * Publisher connects and sends a message to a channel:
 *   send: {"type":"publish","channel":"id","replyTo":"n","url":"u","ecdh":"e","sig":"s","pub":"p","ts":N}
 *   recv: {"type":"reply","replyTo":"n","payload":"..."} or {"type":"error","message":"..."}
 *
 * Subscriber receives forwarded publishes and sends replies:
 *   recv: {"type":"publish",...}
 *   send: {"type":"reply","replyTo":"n","payload":"..."}
 *
 * HTTP (non-upgraded):
 *   GET  /status → 200 "ok"
 *   POST /clear  → disconnect all WebSocket clients, 200 "ok"
 *
 * Build with cosmocc for a portable APE binary:
 *   cosmocc -O2 -o switchboard switchboard.c
 *
 * Build natively:
 *   cc -O2 -o switchboard switchboard.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef int socklen_t;
#  define close(s) closesocket(s)
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <sys/select.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <signal.h>
#endif

/* ── Configuration ────────────────────────────────────────────────────────── */

static int cfg_port  = 7577;
static int cfg_conns = 32;    /* max concurrent connections              */
static int cfg_blob  = 16384; /* max single message size in bytes        */
static int cfg_ttl   = 60;    /* relay.html idle timeout (0 = no limit)  */

/* ── SHA-1 (for WebSocket Sec-WebSocket-Accept) ──────────────────────────── */

typedef struct { uint32_t h[5]; uint64_t n; uint8_t b[64]; int nb; } SHA1Ctx;
#define ROL32(v,s) (((v)<<(s))|((v)>>(32-(s))))

static void sha1_compress(SHA1Ctx *s) {
    uint32_t w[80], a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],t;
    int i;
    for (i=0;i<16;i++) w[i]=((uint32_t)s->b[i*4]<<24)|((uint32_t)s->b[i*4+1]<<16)|
                             ((uint32_t)s->b[i*4+2]<<8)|(uint32_t)s->b[i*4+3];
    for (i=16;i<80;i++) w[i]=ROL32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    for (i=0;i<80;i++) {
        if      (i<20) t=ROL32(a,5)+((b&c)|(~b&d))+e+0x5A827999u+w[i];
        else if (i<40) t=ROL32(a,5)+(b^c^d)+e+0x6ED9EBA1u+w[i];
        else if (i<60) t=ROL32(a,5)+((b&c)|(b&d)|(c&d))+e+0x8F1BBCDCu+w[i];
        else           t=ROL32(a,5)+(b^c^d)+e+0xCA62C1D6u+w[i];
        e=d; d=c; c=ROL32(b,30); b=a; a=t;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d; s->h[4]+=e;
}

static void sha1(const char *data, size_t len, uint8_t out[20]) {
    SHA1Ctx s = {{0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u},0,{0},0};
    const uint8_t *p = (const uint8_t *)data;
    while (len) {
        int take = len < (size_t)(64-s.nb) ? (int)len : 64-s.nb;
        memcpy(s.b+s.nb, p, take); s.nb+=take; p+=take; len-=take;
        if (s.nb==64) { sha1_compress(&s); s.n+=64; s.nb=0; }
    }
    s.n += s.nb;
    s.b[s.nb++]=0x80;
    if (s.nb>56) { memset(s.b+s.nb,0,64-s.nb); sha1_compress(&s); s.nb=0; }
    memset(s.b+s.nb,0,56-s.nb);
    uint64_t bits=s.n*8;
    for (int i=0;i<8;i++) s.b[56+i]=(uint8_t)(bits>>((7-i)*8));
    sha1_compress(&s);
    for (int i=0;i<5;i++) {
        out[i*4]=(uint8_t)(s.h[i]>>24); out[i*4+1]=(uint8_t)(s.h[i]>>16);
        out[i*4+2]=(uint8_t)(s.h[i]>>8); out[i*4+3]=(uint8_t)s.h[i];
    }
}

/* ── Base64 encode ───────────────────────────────────────────────────────── */

static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64enc(const uint8_t *in, int len, char *out) {
    int j=0;
    for (int i=0;i<len;i+=3) {
        uint32_t v=((uint32_t)in[i]<<16)|(i+1<len?(uint32_t)in[i+1]<<8:0)|(i+2<len?(uint32_t)in[i+2]:0);
        out[j++]=B64[(v>>18)&63]; out[j++]=B64[(v>>12)&63];
        out[j++]=(i+1<len)?B64[(v>>6)&63]:'='; out[j++]=(i+2<len)?B64[v&63]:'=';
    }
    out[j]='\0';
}

/* ── Connection table ────────────────────────────────────────────────────── */

#define MAX_CHANNELS 32   /* max channel IDs per subscriber connection */

typedef enum { CONN_FREE, CONN_HTTP, CONN_WS, CONN_SUBSCRIBER, CONN_PUBLISHER } ConnType;

typedef struct {
    int      fd;
    ConnType type;
    time_t   born;
    char    *rbuf;              /* heap, size cfg_blob+4096                */
    int      rlen;
    /* CONN_SUBSCRIBER */
    int      nchannels;
    char     channels[MAX_CHANNELS][128]; /* registered channel IDs        */
    /* CONN_PUBLISHER */
    char     channel[128];      /* channel this publish is for             */
    char     reply_to[128];     /* replyTo, for routing reply              */
} Conn;

static Conn *conns;  /* allocated in main() */

/* ── Connection management ───────────────────────────────────────────────── */

static Conn *conn_alloc(int fd) {
    for (int i = 0; i < cfg_conns; i++) {
        if (conns[i].type != CONN_FREE) continue;
        memset(&conns[i], 0, sizeof(conns[i]));
        conns[i].fd   = fd;
        conns[i].type = CONN_HTTP;
        conns[i].born = time(NULL);
        conns[i].rbuf = (char *)malloc((size_t)cfg_blob + 4096);
        if (!conns[i].rbuf) { close(fd); return NULL; }
        return &conns[i];
    }
    close(fd);
    return NULL;
}

static void conn_free(Conn *c) {
    if (!c || c->type == CONN_FREE) return;
    close(c->fd);
    free(c->rbuf);
    memset(c, 0, sizeof(*c));
}

static Conn *find_subscriber(const char *channel) {
    for (int i = 0; i < cfg_conns; i++) {
        if (conns[i].type != CONN_SUBSCRIBER) continue;
        for (int j = 0; j < conns[i].nchannels; j++)
            if (strcmp(conns[i].channels[j], channel) == 0) return &conns[i];
    }
    return NULL;
}

static Conn *find_publisher(const char *reply_to) {
    for (int i = 0; i < cfg_conns; i++)
        if (conns[i].type == CONN_PUBLISHER && strcmp(conns[i].reply_to, reply_to) == 0)
            return &conns[i];
    return NULL;
}

/* ── HTTP response ───────────────────────────────────────────────────────── */

static void http_respond(int fd, int code, const char *status,
                         const char *body, size_t blen) {
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        code, status, blen);
    send(fd, hdr, hlen, 0);
    if (body && blen) send(fd, body, (int)blen, 0);
}

/* ── JSON field extractor ────────────────────────────────────────────────── */

static int json_str(const char *json, const char *key, char *out, int maxlen) {
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t') p++;  /* skip optional whitespace */
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < maxlen-1) out[i++] = *p++;
    out[i] = '\0';
    return *p == '"' && i > 0;
}

/* ── WebSocket helpers ───────────────────────────────────────────────────── */

static int ws_upgrade(int fd, const char *req) {
    const char *p = strstr(req, "Sec-WebSocket-Key:");
    if (!p) p = strstr(req, "sec-websocket-key:");
    if (!p) return -1;
    p += 18;
    while (*p == ' ') p++;
    const char *end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    if (end == p || end-p > 60) return -1;

    char combined[128];
    int klen = (int)(end-p);
    memcpy(combined, p, klen);
    strcpy(combined+klen, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    uint8_t hash[20];
    sha1(combined, strlen(combined), hash);
    char accept[32];
    b64enc(hash, 20, accept);

    char resp[256];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    send(fd, resp, rlen, 0);
    return 0;
}

static void ws_send(int fd, const char *text, size_t len) {
    uint8_t hdr[4];
    int hlen;
    hdr[0] = 0x81;
    if (len <= 125)      { hdr[1]=(uint8_t)len; hlen=2; }
    else if (len<=65535) { hdr[1]=126; hdr[2]=(uint8_t)(len>>8); hdr[3]=(uint8_t)len; hlen=4; }
    else return;
    send(fd, hdr, hlen, 0);
    send(fd, text, (int)len, 0);
}

static void ws_error(int fd, const char *msg) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "{\"type\":\"error\",\"message\":\"%s\"}", msg);
    ws_send(fd, buf, (size_t)n);
}

/* ── WebSocket message dispatch ──────────────────────────────────────────── */

static void ws_dispatch(Conn *c, char *payload, size_t plen) {
    if (plen == 0 || plen >= (size_t)cfg_blob) return;
    payload[plen] = '\0';

    char type[32] = {0};
    json_str(payload, "type", type, sizeof(type));

    if (strcmp(type, "subscribe") == 0) {
        c->type = CONN_SUBSCRIBER;
        c->nchannels = 0;
        const char *p = strstr(payload, "\"channels\":");
        if (p) {
            p += 11;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '[') p++;
            while (*p && *p != ']' && c->nchannels < MAX_CHANNELS) {
                if (*p == '"') {
                    p++;
                    char *dst = c->channels[c->nchannels];
                    int i = 0;
                    while (*p && *p != '"' && i < 127) dst[i++] = *p++;
                    dst[i] = '\0';
                    if (i > 0) c->nchannels++;
                }
                if (*p) p++;
            }
        }
        return;
    }

    if (strcmp(type, "publish") == 0) {
        char channel[128]={0}, reply_to[128]={0};
        if (!json_str(payload,"channel",channel,sizeof(channel)) ||
            !json_str(payload,"replyTo",reply_to,sizeof(reply_to))) return;
        c->type = CONN_PUBLISHER;
        snprintf(c->channel,  sizeof(c->channel),  "%s", channel);
        snprintf(c->reply_to, sizeof(c->reply_to), "%s", reply_to);
        Conn *sub = find_subscriber(channel);
        if (!sub) { ws_error(c->fd, "No subscriber for that channel"); return; }
        ws_send(sub->fd, payload, plen);
        return;
    }

    if (strcmp(type, "reply") == 0) {
        if (c->type != CONN_SUBSCRIBER) return;
        char reply_to[128]={0};
        if (!json_str(payload,"replyTo",reply_to,sizeof(reply_to))) return;
        Conn *pub = find_publisher(reply_to);
        if (pub) ws_send(pub->fd, payload, plen);
        return;
    }
}

/* ── WebSocket frame consumer ────────────────────────────────────────────── */

static int ws_consume(Conn *c) {
    uint8_t *buf = (uint8_t *)c->rbuf;
    int      len = c->rlen;
    if (len < 2) return 0;

    int    masked = (buf[1] & 0x80) != 0;
    size_t plen   = buf[1] & 0x7F;
    int    hdr    = 2;

    if (plen == 126) {
        if (len < 4) return 0;
        plen = ((size_t)buf[2]<<8)|buf[3]; hdr = 4;
    } else if (plen == 127) {
        if (len < 10) return 0;
        plen = 0;
        for (int i=0;i<8;i++) plen=(plen<<8)|buf[2+i];
        hdr = 10;
        if (plen > (size_t)cfg_blob) return -1;
    }
    if (masked) hdr += 4;
    if (len < hdr + (int)plen) return 0;

    int opcode = buf[0] & 0x0F;

    if (masked) {
        uint8_t *mask = buf + hdr - 4;
        uint8_t *data = buf + hdr;
        for (size_t i=0;i<plen;i++) data[i] ^= mask[i&3];
    }

    if      (opcode == 0x8) { conn_free(c); return 1; }
    else if (opcode == 0x9) { uint8_t pong[2]={0x8A,0x00}; send(c->fd,pong,2,0); }
    else if (opcode == 0x1 || opcode == 0x2)
        ws_dispatch(c, (char *)(buf+hdr), plen);

    int consumed = hdr + (int)plen;
    memmove(buf, buf+consumed, (size_t)(len-consumed));
    c->rlen -= consumed;
    return 1;
}

/* ── HTTP request handler ────────────────────────────────────────────────── */

static void handle_http(Conn *c) {
    char method[16]={0}, path[256]={0};
    if (sscanf(c->rbuf, "%15s %255s", method, path) != 2)
        { http_respond(c->fd,400,"Bad Request",NULL,0); conn_free(c); return; }

    if (strcmp(method,"GET")==0 && strcmp(path,"/ws")==0 &&
        (strstr(c->rbuf,"Upgrade: websocket")||strstr(c->rbuf,"upgrade: websocket"))) {
        if (ws_upgrade(c->fd, c->rbuf) == 0) { c->type=CONN_WS; c->rlen=0; }
        else { http_respond(c->fd,400,"Bad Request",NULL,0); conn_free(c); }
        return;
    }

    if (strcmp(method,"OPTIONS")==0)
        { http_respond(c->fd,204,"No Content",NULL,0); conn_free(c); return; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/status")==0)
        { http_respond(c->fd,200,"OK","ok",2); conn_free(c); return; }
    if (strcmp(method,"POST")==0 && strcmp(path,"/clear")==0) {
        for (int i=0;i<cfg_conns;i++)
            if (conns[i].type==CONN_SUBSCRIBER||conns[i].type==CONN_PUBLISHER||conns[i].type==CONN_WS)
                conn_free(&conns[i]);
        http_respond(c->fd,200,"OK","ok",2); conn_free(c); return;
    }
    http_respond(c->fd,404,"Not Found",NULL,0); conn_free(c);
}

/* ── CLI ─────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --port N       listening port                         (default: %d)\n"
        "  --max-conns N  max concurrent connections             (default: %d)\n"
        "  --max-blob N   max message size in bytes              (default: %d)\n"
        "  --ttl N        relay connection timeout in seconds; 0 = no limit  (default: %d)\n"
        "  --help\n",
        prog, cfg_port, cfg_conns, cfg_blob, cfg_ttl);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    for (int i=1;i<argc;i++) {
        if      (!strcmp(argv[i],"--port")     &&i+1<argc) cfg_port  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--max-conns")&&i+1<argc) cfg_conns = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--max-blob") &&i+1<argc) cfg_blob  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--ttl")      &&i+1<argc) cfg_ttl   = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")) { usage(argv[0]); return 0; }
        else { fprintf(stderr,"unknown option: %s\n\n",argv[i]); usage(argv[0]); return 1; }
    }
    if (cfg_port<1||cfg_port>65535||cfg_conns<1||cfg_blob<1||cfg_ttl<0)
        { fprintf(stderr,"invalid option value\n\n"); usage(argv[0]); return 1; }

    conns = (Conn *)calloc((size_t)cfg_conns, sizeof(Conn));
    if (!conns) { perror("calloc"); return 1; }

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    int srv = socket(AF_INET,SOCK_STREAM,0);
    if (srv<0) { perror("socket"); return 1; }
    int yes=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)cfg_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0) { perror("bind"); return 1; }
    listen(srv,16);

    fprintf(stderr,"switchboard listening on 127.0.0.1:%d "
            "(conns=%d blob=%d ttl=%d)\n",
            cfg_port,cfg_conns,cfg_blob,cfg_ttl);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv,&rfds);
        int maxfd=srv;
        for (int i=0;i<cfg_conns;i++) {
            if (conns[i].type==CONN_FREE) continue;
            FD_SET(conns[i].fd,&rfds);
            if (conns[i].fd>maxfd) maxfd=conns[i].fd;
        }

        /* 5s timeout for periodic TTL expiry */
        struct timeval tv={5,0};
        if (select(maxfd+1,&rfds,NULL,NULL,&tv)<0) continue;

        /* Expire stale publisher connections */
        if (cfg_ttl>0) {
            time_t now=time(NULL);
            for (int i=0;i<cfg_conns;i++)
                if (conns[i].type==CONN_PUBLISHER && now-conns[i].born>(time_t)cfg_ttl) {
                    ws_error(conns[i].fd,"Request timed out");
                    conn_free(&conns[i]);
                }
        }

        /* Accept new connection */
        if (FD_ISSET(srv,&rfds)) {
            int fd=accept(srv,NULL,NULL);
            if (fd>=0) conn_alloc(fd);
        }

        /* Service existing connections */
        for (int i=0;i<cfg_conns;i++) {
            Conn *c=&conns[i];
            if (c->type==CONN_FREE||!FD_ISSET(c->fd,&rfds)) continue;

            int n=recv(c->fd, c->rbuf+c->rlen, cfg_blob+4095-c->rlen, 0);
            if (n<=0) { conn_free(c); continue; }
            c->rlen+=n;
            c->rbuf[c->rlen]='\0';

            if (c->type==CONN_HTTP) {
                if (!strstr(c->rbuf,"\r\n\r\n")) continue;
                handle_http(c);
            } else if (c->type==CONN_WS||c->type==CONN_SUBSCRIBER||c->type==CONN_PUBLISHER) {
                int r;
                do { r=ws_consume(c); } while (r>0 && c->type!=CONN_FREE);
                if (r<0) conn_free(c);
            }
        }
    }
}
