/**
 * tools/note_admin.c — NoteDaemon Admin CLI (C, no dependencies)
 * ================================================================
 *
 * Tiny C utility that talks to NoteDaemon over its Unix socket using
 * the raw NoteBytes wire protocol. No Python, no libraries beyond libc.
 *
 * Wire format: [1B type][4B length BE][data...]
 *   Type 11 = STRING (UTF-8)
 *   Type 12 = OBJECT (key-value pairs)
 *   Type 3  = INTEGER (int32 BE)
 *
 * Build:
 *   gcc -o note_admin note_admin.c
 *
 * Usage:
 *   ./note_admin ping                          # Handshake test
 *   ./note_admin setup <admin-key>             # Full admin init
 *   ./note_admin set-api-key <key>             # Just set admin API key
 *   ./note_admin auth <key>                    # Admin auth → session
 *   ./note_admin add-client <id> <api-key>     # Create client
 *   ./note_admin list-clients                  # List clients
 *   ./note_admin put <client> <path> <json>    # Write file as JSON
 *   ./note_admin get <client> <path>           # Read file
 *
 * Socket path: /run/netnotes/notedaemon.sock (default)
 * Override:    NOTE_SOCKET=/custom/path ./note_admin ping
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#define METADATA_SIZE 5
#define TYPE_STRING  11
#define TYPE_OBJECT  12
#define TYPE_INTEGER 3
#define TYPE_RAW     0
#define MAX_RESPONSE (256 * 1024)  // 256KB max response

static const char *socket_path = "/run/netnotes/notedaemon.sock";

// ── NoteBytes encoding helpers ──────────────────────────────────────────────

// Write a big-endian uint32 to buf, return bytes written
static int write_u32be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
    return 4;
}

// Encode a STRING: [0x0B][4B len][data]
static int encode_string(uint8_t *buf, const char *str) {
    int len = strlen(str);
    buf[0] = TYPE_STRING;
    write_u32be(buf + 1, len);
    memcpy(buf + 5, str, len);
    return 5 + len;
}

// Encode an INTEGER: [0x03][4B len=4][4B val]
static int encode_int(uint8_t *buf, int32_t val) {
    buf[0] = TYPE_INTEGER;
    write_u32be(buf + 1, 4);
    write_u32be(buf + 5, val);
    return 9;
}

// Encode RAW_BYTES: [0x00][4B len][data]
static int encode_raw(uint8_t *buf, const uint8_t *data, int len) {
    buf[0] = TYPE_RAW;
    write_u32be(buf + 1, len);
    memcpy(buf + 5, data, len);
    return 5 + len;
}

// Build an OBJECT from key-value pairs. Pairs are encoded inline.
// Returns total packet size.
static int build_object(uint8_t *packet, const uint8_t *body, int body_len) {
    packet[0] = TYPE_OBJECT;
    write_u32be(packet + 1, body_len);
    memcpy(packet + 5, body, body_len);
    return 5 + body_len;
}

// ── Socket I/O ──────────────────────────────────────────────────────────────

static int connect_socket(void) {
    const char *path = getenv("NOTE_SOCKET");
    if (!path) path = socket_path;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "connect(%s) failed: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

// Send a full OBJECT packet and read the response.
// Returns malloc'd response buffer (caller frees), or NULL on error.
// Sets *resp_len to the response body length (after OBJECT header).
static uint8_t *send_and_recv(const uint8_t *packet, int packet_len,
                               int *resp_len) {
    int fd = connect_socket();
    if (fd < 0) return NULL;

    // Send
    ssize_t sent = write(fd, packet, packet_len);
    if (sent != packet_len) {
        fprintf(stderr, "write() failed: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    // Read 5-byte header
    uint8_t header[5];
    ssize_t n = 0;
    while (n < 5) {
        ssize_t r = read(fd, header + n, 5 - n);
        if (r <= 0) {
            fprintf(stderr, "read() header failed: %s\n", strerror(errno));
            close(fd);
            return NULL;
        }
        n += r;
    }

    uint32_t length = (header[1] << 24) | (header[2] << 16) |
                      (header[3] << 8)  | header[4];

    if (length > MAX_RESPONSE) {
        fprintf(stderr, "Response too large: %u bytes\n", length);
        close(fd);
        return NULL;
    }

    // Allocate: header + body
    uint8_t *resp = malloc(5 + length);
    if (!resp) {
        fprintf(stderr, "malloc() failed\n");
        close(fd);
        return NULL;
    }
    memcpy(resp, header, 5);

    // Read body
    n = 0;
    while ((uint32_t)n < length) {
        ssize_t r = read(fd, resp + 5 + n, length - n);
        if (r <= 0) break;
        n += r;
    }

    close(fd);

    if ((uint32_t)n < length) {
        fprintf(stderr, "Incomplete response: %zd/%u bytes\n", n, length);
        free(resp);
        return NULL;
    }

    *resp_len = length;
    return resp;
}

// ── Response parsing ────────────────────────────────────────────────────────

// Find a field value in an OBJECT body. Returns pointer to value data,
// sets *vlen to value data length, *vtype to value type.
// Returns NULL if not found.
static const uint8_t *find_field(const uint8_t *body, int body_len,
                                  const char *key, int *vlen, uint8_t *vtype) {
    int pos = 0;
    while (pos < body_len) {
        // Read key
        uint8_t kt = body[pos];
        uint32_t kl = (body[pos+1] << 24) | (body[pos+2] << 16) |
                      (body[pos+3] << 8)  | body[pos+4];
        pos += 5;

        int match = 0;
        if (kt == TYPE_STRING && (int)kl == (int)strlen(key) &&
            memcmp(body + pos, key, kl) == 0) {
            match = 1;
        }

        pos += kl;

        // Read value
        uint8_t vt = body[pos];
        uint32_t vl = (body[pos+1] << 24) | (body[pos+2] << 16) |
                      (body[pos+3] << 8)  | body[pos+4];
        pos += 5;

        if (match) {
            *vlen = vl;
            *vtype = vt;
            return body + pos;
        }

        pos += vl;
    }
    return NULL;
}

// Get a string field from an OBJECT body. Returns malloc'd string or NULL.
static char *get_string(const uint8_t *body, int body_len, const char *key) {
    int vlen; uint8_t vtype;
    const uint8_t *val = find_field(body, body_len, key, &vlen, &vtype);
    if (!val || vtype != TYPE_STRING) return NULL;
    char *s = malloc(vlen + 1);
    if (!s) return NULL;
    memcpy(s, val, vlen);
    s[vlen] = '\0';
    return s;
}

// Get an integer field from an OBJECT body. Returns 0 if not found.
static int32_t get_int(const uint8_t *body, int body_len, const char *key) {
    int vlen; uint8_t vtype;
    const uint8_t *val = find_field(body, body_len, key, &vlen, &vtype);
    if (!val || vtype != TYPE_INTEGER || vlen < 4) return 0;
    return (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
}

// Print the full response body as key: value pairs (debugging)
static void dump_response(const uint8_t *body, int body_len) {
    int pos = 0;
    while (pos < body_len) {
        /* uint8_t kt = */ body[pos];
        uint32_t kl = (body[pos+1] << 24) | (body[pos+2] << 16) |
                      (body[pos+3] << 8)  | body[pos+4];
        pos += 5;

        char *key = malloc(kl + 1);
        memcpy(key, body + pos, kl);
        key[kl] = '\0';
        pos += kl;

        uint8_t vt = body[pos];
        uint32_t vl = (body[pos+1] << 24) | (body[pos+2] << 16) |
                      (body[pos+3] << 8)  | body[pos+4];
        pos += 5;

        if (vt == TYPE_STRING) {
            char *val = malloc(vl + 1);
            memcpy(val, body + pos, vl);
            val[vl] = '\0';
            printf("  %s: \"%s\"\n", key, val);
            free(val);
        } else if (vt == TYPE_INTEGER && vl >= 4) {
            int32_t iv = (body[pos] << 24) | (body[pos+1] << 16) |
                         (body[pos+2] << 8)  | body[pos+3];
            printf("  %s: %d\n", key, iv);
        } else {
            printf("  %s: <type=%d, len=%u>\n", key, vt, vl);
        }

        free(key);
        pos += vl;
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

// Allocate a buffer for building messages
static uint8_t *msg_buf(int size) {
    return malloc(size);
}

static int cmd_ping(void) {
    // Build HELLO: {"event": "hello", "version": "1.0.0"}
    uint8_t body[256];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "hello");
    pos += encode_string(body + pos, "version");
    pos += encode_string(body + pos, "1.0.0");

    uint8_t packet[512];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *event = get_string(resp + 5, resp_len, "event");
    int ok = event && strcmp(event, "accept") == 0;
    printf("%s Handshake %s\n", ok ? "✓" : "✗",
           ok ? "accepted" : (event ? event : "failed"));
    free(event);
    free(resp);
    return ok ? 0 : 1;
}

static int cmd_set_api_key(const char *key) {
    uint8_t body[512];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "set_admin_api_key");
    pos += encode_string(body + pos, "password");
    pos += encode_string(body + pos, key);

    uint8_t packet[1024];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *status = get_string(resp + 5, resp_len, "status");
    int ok = status && strcmp(status, "ok") == 0;
    printf("%s set_admin_api_key: %s\n", ok ? "✓" : "✗",
           ok ? "ok" : (status ? status : "no status"));
    if (!ok) dump_response(resp + 5, resp_len);
    free(status);
    free(resp);
    return ok ? 0 : 1;
}

static int cmd_auth(const char *key) {
    uint8_t body[512];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "admin_auth");
    pos += encode_string(body + pos, "password");
    pos += encode_string(body + pos, key);

    uint8_t packet[1024];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *session = get_string(resp + 5, resp_len, "session_id");
    if (session) {
        printf("✓ Authenticated — session: %.12s...\n", session);
        free(session);
        free(resp);
        return 0;
    }
    printf("✗ Auth failed\n");
    dump_response(resp + 5, resp_len);
    free(resp);
    return 1;
}

static int cmd_add_client(const char *client_id, const char *api_key) {
    uint8_t body[512];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "add_client");
    pos += encode_string(body + pos, "client_id");
    pos += encode_string(body + pos, client_id);
    pos += encode_string(body + pos, "api_key");
    pos += encode_string(body + pos, api_key);

    uint8_t packet[1024];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *status = get_string(resp + 5, resp_len, "status");
    int ok = status && strcmp(status, "ok") == 0;
    printf("%s add_client '%s': %s\n", ok ? "✓" : "✗",
           client_id, ok ? "created" : (status ? status : "failed"));
    free(status);
    free(resp);
    return ok ? 0 : 1;
}

static int cmd_list_clients(void) {
    uint8_t body[128];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "list_clients");

    uint8_t packet[256];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *err = get_string(resp + 5, resp_len, "msg");
    if (err) {
        printf("✗ %s\n", err);
        free(err);
        free(resp);
        return 1;
    }

    dump_response(resp + 5, resp_len);
    free(resp);
    return 0;
}

static int cmd_setup(const char *key) {
    printf("── Setting up NoteDaemon admin ──\n\n");

    printf("[1/3] Set admin API key...\n");
    if (cmd_set_api_key(key) != 0) {
        fprintf(stderr, "Failed to set admin API key\n");
        return 1;
    }

    printf("[2/3] Authenticate...\n");
    if (cmd_auth(key) != 0) {
        fprintf(stderr, "Authentication failed\n");
        return 1;
    }

    printf("[3/3] Create dnd-server client...\n");
    if (cmd_add_client("dnd-server", "sk-dnd-server-001") != 0) {
        printf("  (may already exist — continuing)\n");
    }

    printf("\n✓ Admin setup complete\n");
    return 0;
}

static int cmd_put(const char *client_id, const char *path, const char *json) {
    // Build the data as raw NoteBytes pairs (theme=dark, lang=en, ver=2)
    // For simplicity, we store the JSON string as a single "json" key
    uint8_t data_body[1024];
    int dpos = 0;
    dpos += encode_string(data_body + dpos, "json");
    dpos += encode_string(data_body + dpos, json);

    // Encode data as RAW_BYTES
    uint8_t data_encoded[2048];
    int data_enc_len = encode_raw(data_encoded, data_body, dpos);

    // Build outer message
    uint8_t body[4096];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "put_file");
    pos += encode_string(body + pos, "client_id");
    pos += encode_string(body + pos, client_id);
    pos += encode_string(body + pos, "path");
    pos += encode_string(body + pos, path);
    pos += encode_string(body + pos, "data");
    memcpy(body + pos, data_encoded + 1, data_enc_len - 1);  // skip RAW type byte
    pos += data_enc_len - 1;

    uint8_t *packet = msg_buf(8192);
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    free(packet);
    if (!resp) return 1;

    char *status = get_string(resp + 5, resp_len, "status");
    printf("%s put_file %s/%s: %s\n",
           (status && strcmp(status, "ok") == 0) ? "✓" : "✗",
           client_id, path, status ? status : "no status");
    free(status);
    free(resp);
    return 0;
}

static int cmd_get(const char *client_id, const char *path) {
    uint8_t body[512];
    int pos = 0;
    pos += encode_string(body + pos, "event");
    pos += encode_string(body + pos, "get_file");
    pos += encode_string(body + pos, "client_id");
    pos += encode_string(body + pos, client_id);
    pos += encode_string(body + pos, "path");
    pos += encode_string(body + pos, path);

    uint8_t packet[1024];
    int packet_len = build_object(packet, body, pos);

    int resp_len;
    uint8_t *resp = send_and_recv(packet, packet_len, &resp_len);
    if (!resp) return 1;

    char *err = get_string(resp + 5, resp_len, "msg");
    if (err) {
        printf("✗ %s\n", err);
        free(err);
        free(resp);
        return 1;
    }

    // Find the "data" field (RAW_BYTES) and parse it as a NoteBytes object
    int vlen; uint8_t vtype;
    const uint8_t *data_val = find_field(resp + 5, resp_len, "data", &vlen, &vtype);
    if (data_val) {
        // Parse data as inner key-value pairs
        dump_response(data_val, vlen);
    } else {
        printf("(no data field)\n");
        dump_response(resp + 5, resp_len);
    }

    free(resp);
    return 0;
}

// ── Main ─────────────────────────────────────────────────────────────────────

static void usage(const char *prog) {
    printf("NoteDaemon Admin CLI (C)\n\n");
    printf("Usage: %s <command> [args...]\n\n", prog);
    printf("Commands:\n");
    printf("  ping                          Test handshake\n");
    printf("  setup <admin-key>             Full admin initialization\n");
    printf("  set-api-key <key>             Set admin API key\n");
    printf("  auth <key>                    Authenticate as admin\n");
    printf("  add-client <id> <key>         Create a client\n");
    printf("  list-clients                  List all clients\n");
    printf("  put <client> <path> <json>    Write file\n");
    printf("  get <client> <path>           Read file\n");
    printf("\nSocket: %s (override with NOTE_SOCKET env var)\n", socket_path);
    printf("Build:  gcc -o note_admin note_admin.c\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "ping") == 0) {
        return cmd_ping();
    } else if (strcmp(cmd, "setup") == 0 && argc >= 3) {
        return cmd_setup(argv[2]);
    } else if (strcmp(cmd, "set-api-key") == 0 && argc >= 3) {
        return cmd_set_api_key(argv[2]);
    } else if (strcmp(cmd, "auth") == 0 && argc >= 3) {
        return cmd_auth(argv[2]);
    } else if (strcmp(cmd, "add-client") == 0 && argc >= 4) {
        return cmd_add_client(argv[2], argv[3]);
    } else if (strcmp(cmd, "list-clients") == 0) {
        return cmd_list_clients();
    } else if (strcmp(cmd, "put") == 0 && argc >= 5) {
        return cmd_put(argv[2], argv[3], argv[4]);
    } else if (strcmp(cmd, "get") == 0 && argc >= 4) {
        return cmd_get(argv[2], argv[3]);
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
