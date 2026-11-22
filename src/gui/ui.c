#include <SDL3/SDL.h>
#include <SDL3_ttf/SDL_ttf.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ui.h"

/* ------------------------------------------------------------------ config */
#define LOG_CAP 2000
#define FND_CAP 2000
#define FND_TXT 1024

/* STOP escalation: SIGTERM first, SIGKILL this many seconds later,
 * re-arming so a stubborn process group gets repeated SIGKILLs. */
#define STOP_KILL_SECS 5

static const SDL_Color C_BG     = {0x0e,0x0f,0x13,0xff};
static const SDL_Color C_PANEL  = {0x14,0x16,0x1c,0xff};
static const SDL_Color C_TOP    = {0x12,0x14,0x1a,0xff};
static const SDL_Color C_BORDER = {0x2a,0x2d,0x36,0xff};
static const SDL_Color C_FG     = {0xdd,0xdd,0xdd,0xff};
static const SDL_Color C_DIM    = {0x88,0x88,0x88,0xff};
static const SDL_Color C_ACCENT = {0x4a,0x8c,0xff,0xff};
static const SDL_Color C_OK     = {0x5a,0xdc,0x6e,0xff};
static const SDL_Color C_ERR    = {0xeb,0x5a,0x5a,0xff};
static const SDL_Color C_WARN   = {0xf0,0xc8,0x46,0xff};
static const SDL_Color C_CRIT   = {0xff,0x30,0x30,0xff};
static const SDL_Color C_HIGH   = {0xeb,0x5a,0x5a,0xff};
static const SDL_Color C_MED    = {0xf0,0xc8,0x46,0xff};
static const SDL_Color C_LOW    = {0x78,0xbe,0xff,0xff};
static const SDL_Color C_RUN    = {0x2a,0x5c,0x3a,0xff};
static const SDL_Color C_STOP   = {0x5c,0x2a,0x2a,0xff};
static const SDL_Color C_BTN    = {0x20,0x24,0x2c,0xff};

/* ------------------------------------------------------------------ types */
typedef enum {
    SEV_INFO, SEV_OK, SEV_WARN, SEV_ERR, SEV_CRIT, SEV_HIGH, SEV_MED, SEV_LOW
} Severity;

typedef struct {
    char        *text;
    SDL_Texture *tex;
    int          tex_w, tex_h;
    SDL_Color    color;
} LogLine;

typedef struct {
    char      sev[16];
    char      tool[64];
    char      text[FND_TXT];
    SDL_Color color;
} Finding;

typedef enum { TAB_LOG = 0, TAB_FINDINGS = 1 } TabId;

typedef struct {
    char  buf[512];
    int   len;
    int   cursor;
    bool  focused;
    float x, y, w, h;
} TextEntry;

typedef struct { float x, y, w, h; bool hover, down; } Rect;

typedef struct PendingLine {
    struct PendingLine *next;
    char *text;
} PendingLine;

typedef struct {
    SDL_Window   *win;
    SDL_Renderer *ren;
    TTF_Font     *font;
    int           line_h;

    TextEntry e_outdir, e_target, e_proxy;
    Rect      r_mode, r_xss, r_deepblue, r_tor, r_elite, r_run, r_stop;
    Rect      r_tab_log, r_tab_find, r_log_area, r_find_area;

    const char *modes[8];
    int         mode_count, mode_idx;
    bool        flag_xss, flag_deepblue, flag_tor, flag_elite;

    TabId     active_tab;

    LogLine   log[LOG_CAP];
    int       log_count, log_scroll;
    bool      log_autoscroll;

    Finding   findings[FND_CAP];
    int       findings_count, findings_scroll;

    pid_t     child_pid;
    int       child_stdout;
    pthread_t reader_thread;
    bool      reader_running;
    bool      running;
    int       exit_code;

    bool      stop_requested;        /* B7 */
    time_t    stop_requested_at;     /* B7 */

    pthread_mutex_t q_lock;
    PendingLine    *q_head, *q_tail;

    char status[256];
} App;

/* ------------------------------------------------------------------ state */
static volatile sig_atomic_t g_child = 0;

static void on_signal(int sig) {
    if (g_child > 0) kill(-(pid_t)g_child, sig);
    _exit(128 + sig);
}

/* ------------------------------------------------------------------ utils */
static void set_status(App *a, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(a->status, sizeof(a->status), fmt, ap);
    va_end(ap);
}

/* B2: anchor severity matches so info chatter can't flood the
 * Findings tab. "vulnerab" alone no longer maps to low; only an
 * explicit "low:" / "severity: low" does. */
static Severity classify(const char *s) {
    if (!s) return SEV_INFO;
    if (s[0] == '[' && s[1]) {
        switch (s[1]) {
            case '+': return SEV_OK;
            case '-': return SEV_ERR;
            case '!': return SEV_WARN;
        }
    }
    char low[512];
    size_t i = 0;
    for (; s[i] && i < sizeof(low) - 1; i++)
        low[i] = (char)tolower((unsigned char)s[i]);
    low[i] = '\0';
    if (strstr(low, "critical") || strstr(low, "cvss 9") ||
        strstr(low, "cvss 10"))                                    return SEV_CRIT;
    if (strstr(low, "high") || strstr(low, "cve-"))                return SEV_HIGH;
    if (strstr(low, "medium"))                                     return SEV_MED;
    if (strstr(low, "low:") || strstr(low, "severity: low"))       return SEV_LOW;
    return SEV_INFO;
}

static SDL_Color sev_color(Severity s) {
    switch (s) {
        case SEV_OK:   return C_OK;
        case SEV_ERR:  return C_ERR;
        case SEV_WARN: return C_WARN;
        case SEV_CRIT: return C_CRIT;
        case SEV_HIGH: return C_HIGH;
        case SEV_MED:  return C_MED;
        case SEV_LOW:  return C_LOW;
        default:       return C_FG;
    }
}

static bool sev_is_finding(Severity s) {
    return s == SEV_CRIT || s == SEV_HIGH || s == SEV_MED || s == SEV_LOW;
}

static const char *sev_name(Severity s) {
    switch (s) {
        case SEV_CRIT: return "critical";
        case SEV_HIGH: return "high";
        case SEV_MED:  return "medium";
        case SEV_LOW:  return "low";
        default:       return "info";
    }
}

/* --------------------------------------------------------------- logbuffer */
static void log_free(LogLine *l) {
    if (l->tex) SDL_DestroyTexture(l->tex);
    free(l->text);
    memset(l, 0, sizeof(*l));
}

/* B1: scroll state is owned exclusively by render_log(); this function
 * no longer touches log_scroll. B11: strdup failure is guarded. */
static void log_append(App *a, const char *line) {
    if (!line) return;
    Severity sev = classify(line);
    if (a->log_count == LOG_CAP) {
        log_free(&a->log[0]);
        memmove(&a->log[0], &a->log[1], sizeof(LogLine) * (LOG_CAP - 1));
        a->log_count--;
        if (a->log_autoscroll) a->log_scroll = 0; /* render_log re-pins to bottom */
    }
    char *dup = strdup(line);
    if (!dup) return;
    LogLine *l = &a->log[a->log_count++];
    l->text  = dup;
    l->tex   = NULL;
    l->tex_w = l->tex_h = 0;
    l->color = sev_color(sev);

    if (sev_is_finding(sev)) {
        if (a->findings_count == FND_CAP) {
            memmove(&a->findings[0], &a->findings[1],
                    sizeof(Finding) * (FND_CAP - 1));
            a->findings_count--;
        }
        Finding *f = &a->findings[a->findings_count++];
        snprintf(f->sev,  sizeof(f->sev),  "%s", sev_name(sev));
        snprintf(f->tool, sizeof(f->tool), "sentinel");
        snprintf(f->text, sizeof(f->text), "%s", line);
        f->color = l->color;
    }
}

/* ------------------------------------------------------------ reader thread */
static void enqueue(App *a, const char *text) {
    PendingLine *p = calloc(1, sizeof(*p));
    if (!p) return;
    p->text = strdup(text);
    if (!p->text) { free(p); return; }
    pthread_mutex_lock(&a->q_lock);
    if (a->q_tail) a->q_tail->next = p; else a->q_head = p;
    a->q_tail = p;
    pthread_mutex_unlock(&a->q_lock);
}

static void *reader_main(void *arg) {
    App *a = arg;
    char buf[8192];
    int  used = 0;
    int  fd   = a->child_stdout;
    for (;;) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - used - 1);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        used += (int)n;
        buf[used] = '\0';
        char *start = buf, *nl;
        while ((nl = strchr(start, '\n'))) {
            *nl = '\0';
            size_t L = strlen(start);
            if (L && start[L - 1] == '\r') start[L - 1] = '\0';
            enqueue(a, start);
            start = nl + 1;
        }
        used = (int)strlen(start);
        if (used) memmove(buf, start, used + 1);
    }
    if (used) enqueue(a, buf);
    return NULL;
}

/* ------------------------------------------------------------- process mngmt */
static const char *self_exe(void) {
    static char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; return buf; }
    return "sentinel";
}

static bool spawn_scan(App *a) {
    if (a->running) return false;

    char *argv[64]; int n = 0;
    argv[n++] = (char *)self_exe();
    argv[n++] = a->e_outdir.buf;
    argv[n++] = (char *)a->modes[a->mode_idx];
    argv[n++] = a->e_target.buf;
    if (!a->flag_xss)       argv[n++] = "--xss-no";
    if (a->flag_deepblue)   argv[n++] = "--deepblue";
    if (a->flag_tor)        argv[n++] = "--tor";
    else if (a->flag_elite) argv[n++] = "--elite";
    /* B13: explicit precedence — tor/elite win, proxy file is ignored
     * rather than silently overriding tor depending on argv order */
    if (!a->flag_tor && !a->flag_elite && a->e_proxy.len) {
        argv[n++] = "--proxy"; argv[n++] = a->e_proxy.buf;
    }
    argv[n++] = "--no-ui";
    argv[n]   = NULL;

    int pfd[2];
    if (pipe(pfd) != 0) { set_status(a, "pipe: %s", strerror(errno)); return false; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]); close(pfd[1]);
        set_status(a, "fork: %s", strerror(errno));
        return false;
    }
    if (pid == 0) {
        setsid();
        /* B5: never inherit the GUI's terminal as stdin */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "[-] execvp: %s\n", strerror(errno));
        _exit(127);
    }
    close(pfd[1]);
    /* B4: arm the signal handler before anything else can race */
    g_child           = pid;
    a->child_pid      = pid;
    a->child_stdout   = pfd[0];
    a->running        = true;
    a->exit_code      = 0;
    a->stop_requested = false;
    /* B3: check pthread_create; degrade gracefully if it fails */
    a->reader_running = (pthread_create(&a->reader_thread, NULL,
                                        reader_main, a) == 0);
    if (!a->reader_running)
        log_append(a, "[!] log reader thread failed to start (scan still runs)");

    char line[2048] = "[*] $";
    for (int i = 0; i < n; i++) {
        strncat(line, " ", sizeof(line) - strlen(line) - 1);
        strncat(line, argv[i], sizeof(line) - strlen(line) - 1);
    }
    log_append(a, line);
    set_status(a, "running: %s", a->modes[a->mode_idx]);
    return true;
}

/* B7: SIGTERM, then escalate to SIGKILL after STOP_KILL_SECS,
 * re-arming so a process group that ignores signals keeps getting hit. */
static void stop_scan(App *a) {
    if (!a->running || a->child_pid <= 0) return;
    kill(-a->child_pid, SIGTERM);
    if (!a->stop_requested) {
        a->stop_requested = true;
        a->stop_requested_at = time(NULL);
    }
    set_status(a, "stopping...");
}

static void stop_escalate(App *a) {
    if (!a->running || !a->stop_requested || a->child_pid <= 0) return;
    if (time(NULL) - a->stop_requested_at < STOP_KILL_SECS) return;
    kill(-a->child_pid, SIGKILL);
    a->stop_requested = false;   /* if it survives even SIGKILL, re-arm */
    a->stop_requested_at = time(NULL);
    log_append(a, "[!] sent SIGKILL to scan process group");
}

static void drain_pending(App *a) {
    pthread_mutex_lock(&a->q_lock);
    PendingLine *p = a->q_head;
    a->q_head = a->q_tail = NULL;
    pthread_mutex_unlock(&a->q_lock);
    while (p) {
        PendingLine *nx = p->next;
        log_append(a, p->text);
        free(p->text); free(p);
        p = nx;
    }
}

static void reap_children(App *a) {
    if (!a->running || a->child_pid <= 0) return;
    int st;
    pid_t r = waitpid(a->child_pid, &st, WNOHANG);
    if (r != a->child_pid) return;
    if (a->reader_running) {
        pthread_join(a->reader_thread, NULL);
        a->reader_running = false;
    }
    close(a->child_stdout);
    drain_pending(a);
    a->child_pid = -1;
    a->running   = false;
    g_child      = 0;
    a->stop_requested = false;
    a->exit_code = WIFEXITED(st)   ? WEXITSTATUS(st) :
                   WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1;
    /* B6: literal format strings only */
    char msg[128];
    if (a->exit_code == 0)
        snprintf(msg, sizeof(msg), "[+] job finished (rc=0) \xe2\x80\x94 UI stays open");
    else
        snprintf(msg, sizeof(msg), "[-] job finished (rc=%d)", a->exit_code);
    log_append(a, msg);
    if (a->exit_code == 0)
        set_status(a, "done (rc=0)");
    else
        set_status(a, "done (rc=%d)", a->exit_code);
    a->log_autoscroll = true;
}

/* ---------------------------------------------------------- text entry ops */
static void te_insert(TextEntry *t, const char *s) {
    size_t add = strlen(s);
    if (t->len + (int)add >= (int)sizeof(t->buf) - 1)
        add = sizeof(t->buf) - 1 - t->len;
    if (!add) return;
    memmove(t->buf + t->cursor + add, t->buf + t->cursor,
            t->len - t->cursor + 1);
    memcpy(t->buf + t->cursor, s, add);
    t->len    += (int)add;
    t->cursor += (int)add;
}
static void te_back(TextEntry *t) {
    if (t->cursor <= 0) return;
    memmove(t->buf + t->cursor - 1, t->buf + t->cursor,
            t->len - t->cursor + 1);
    t->cursor--; t->len--;
}
static void te_del(TextEntry *t) {
    if (t->cursor >= t->len) return;
    memmove(t->buf + t->cursor, t->buf + t->cursor + 1,
            t->len - t->cursor);
    t->len--;
}

/* ------------------------------------------------------------------ drawing */
static void draw_rect(SDL_Renderer *r, float x, float y, float w, float h, SDL_Color c) {
    SDL_FRect rr = {x, y, w, h};
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderFillRect(r, &rr);
}
static void draw_border(SDL_Renderer *r, float x, float y, float w, float h,
                        SDL_Color c, int t) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    for (int i = 0; i < t; i++) {
        SDL_FRect top = {x, y + i, w, 1};
        SDL_FRect bot = {x, y + h - 1 - i, w, 1};
        SDL_FRect lft = {x + i, y, 1, h};
        SDL_FRect rgt = {x + w - 1 - i, y, 1, h};
        SDL_RenderFillRect(r, &top);
        SDL_RenderFillRect(r, &bot);
        SDL_RenderFillRect(r, &lft);
        SDL_RenderFillRect(r, &rgt);
    }
}
static SDL_Texture *render_text(SDL_Renderer *r, TTF_Font *f,
                                const char *s, SDL_Color c,
                                int *ow, int *oh) {
    if (!s || !*s) s = " ";
    SDL_Surface *surf = TTF_RenderText_Blended(f, s, strlen(s), c);
    if (!surf) return NULL;
    SDL_Texture *t = SDL_CreateTextureFromSurface(r, surf);
    *ow = surf->w;
    *oh = surf->h;
    SDL_DestroySurface(surf);
    return t;
}
static float text_width(TTF_Font *f, const char *s) {
    int w = 0, h = 0;
    if (TTF_GetStringSize(f, s, strlen(s), &w, &h)) return (float)w;
    return 0;
}
static void draw_text(SDL_Renderer *r, TTF_Font *f, const char *s,
                      float x, float y, SDL_Color c) {
    int w, h;
    SDL_Texture *t = render_text(r, f, s, c, &w, &h);
    if (!t) return;
    SDL_FRect dst = {x, y, (float)w, (float)h};
    SDL_RenderTexture(r, t, NULL, &dst);
    SDL_DestroyTexture(t);
}
static void draw_text_clip(SDL_Renderer *r, TTF_Font *f, const char *s,
                           float x, float y, float maxw, SDL_Color c) {
    if (!s || !*s || maxw <= 0) return;
    int w, h;
    SDL_Texture *t = render_text(r, f, s, c, &w, &h);
    if (!t) return;
    SDL_FRect dst = {x, y, (float)w, (float)h};
    if (w > maxw) {
        SDL_FRect src = {0, 0, maxw, (float)h};
        dst.w = maxw;
        SDL_RenderTexture(r, t, &src, &dst);
    } else {
        SDL_RenderTexture(r, t, NULL, &dst);
    }
    SDL_DestroyTexture(t);
}

/* ---------------------------------------------------------------- widgets */
static void draw_entry(App *a, TextEntry *te, const char *placeholder) {
    draw_rect(a->ren, te->x, te->y, te->w, te->h, C_PANEL);
    draw_border(a->ren, te->x, te->y, te->w, te->h,
                te->focused ? C_ACCENT : C_BORDER, te->focused ? 2 : 1);
    float tx = te->x + 8;
    float ty = te->y + (te->h - a->line_h) * 0.5f;

    if (te->len == 0) {
        if (placeholder) draw_text(a->ren, a->font, placeholder, tx, ty, C_DIM);
    } else {
        float view_w = te->w - 16;
        char  tmp[512];
        int   cl = te->cursor < (int)sizeof(tmp) - 1 ? te->cursor
                                                     : (int)sizeof(tmp) - 1;
        memcpy(tmp, te->buf, cl); tmp[cl] = 0;
        float cur_x = text_width(a->font, tmp);
        int off = 0;
        if (cur_x > view_w) {
            int lo = 0, hi = te->cursor;
            while (lo < hi) {
                int mid = (lo + hi + 1) / 2;
                memcpy(tmp, te->buf, mid); tmp[mid] = 0;
                if (text_width(a->font, tmp) <= cur_x - view_w) lo = mid;
                else hi = mid - 1;
            }
            off = lo;
        }
        draw_text_clip(a->ren, a->font, te->buf + off, tx, ty, view_w, C_FG);
        if (te->focused) {
            memcpy(tmp, te->buf + off, te->cursor - off);
            tmp[te->cursor - off] = 0;
            draw_rect(a->ren, tx + text_width(a->font, tmp),
                      ty, 2, (float)a->line_h, C_FG);
        }
    }
}

static void draw_button(App *a, Rect *r, const char *lbl, bool enabled, SDL_Color base) {
    SDL_Color bg = enabled ? base : (SDL_Color){0x22,0x24,0x2a,0xff};
    if (enabled && r->down)
        bg = (SDL_Color){(Uint8)(base.r * 3 / 5), (Uint8)(base.g * 3 / 5), (Uint8)(base.b * 3 / 5), 0xff};
    else if (enabled && r->hover)
        bg = (SDL_Color){(Uint8)(base.r * 4 / 5), (Uint8)(base.g * 4 / 5), (Uint8)(base.b * 4 / 5), 0xff};
    draw_rect(a->ren, r->x, r->y, r->w, r->h, bg);
    SDL_Color fg = enabled ? C_FG : C_DIM;
    float tw = text_width(a->font, lbl);
    draw_text(a->ren, a->font, lbl,
              r->x + (r->w - tw) * 0.5f,
              r->y + (r->h - a->line_h) * 0.5f, fg);
}

static void draw_checkbox(App *a, Rect *r, const char *label, bool on) {
    float bs = (float)a->line_h;
    float bx = r->x;
    float by = r->y + (r->h - bs) * 0.5f;
    draw_rect(a->ren, bx, by, bs, bs, C_PANEL);
    draw_border(a->ren, bx, by, bs, bs, C_BORDER, 1);
    if (on) draw_rect(a->ren, bx + 4, by + 4, bs - 8, bs - 8, C_ACCENT);
    draw_text(a->ren, a->font, label, bx + bs + 6,
              r->y + (r->h - a->line_h) * 0.5f, C_FG);
}

/* --------------------------------------------------------------- layout */
static void layout(App *a, int W, int H) {
    const int pad = 12, cw = 100;
    int y0 = pad;
    int lh = a->line_h + 6;

    a->e_outdir.x = pad + 80;            a->e_outdir.y = y0;
    a->e_outdir.w = 180;                 a->e_outdir.h = (float)lh;

    a->r_mode.x = a->e_outdir.x + a->e_outdir.w + 60;
    a->r_mode.y = y0;
    a->r_mode.w = 180;                   a->r_mode.h = (float)lh;

    a->e_proxy.x = a->r_mode.x + a->r_mode.w + 60;
    a->e_proxy.y = y0;
    a->e_proxy.w = 220;                  a->e_proxy.h = (float)lh;

    a->e_target.x = pad + 80;
    a->e_target.y = y0 + lh + 8;
    a->e_target.w = (float)(W - 12) - a->e_target.x;
    a->e_target.h = (float)lh;

    float fy = a->e_target.y + lh + 8;
    a->r_xss.x      = pad + 80;                a->r_xss.y      = fy;
    a->r_deepblue.x = a->r_xss.x + cw;         a->r_deepblue.y = fy;
    a->r_tor.x      = a->r_deepblue.x + cw;    a->r_tor.y      = fy;
    a->r_elite.x    = a->r_tor.x + cw;         a->r_elite.y    = fy;
    a->r_xss.w      = a->r_deepblue.w = a->r_tor.w = a->r_elite.w = (float)cw;
    a->r_xss.h      = a->r_deepblue.h = a->r_tor.h = a->r_elite.h = (float)lh;

    a->r_run.x  = (float)(W - 220); a->r_run.y  = fy;
    a->r_run.w  = 100;              a->r_run.h  = (float)lh;
    a->r_stop.x = (float)(W - 110); a->r_stop.y = fy;
    a->r_stop.w = 100;              a->r_stop.h = (float)lh;

    float ty = fy + lh + 10;
    a->r_tab_log.x  = pad;          a->r_tab_log.y  = ty;
    a->r_tab_log.w  = 120;          a->r_tab_log.h  = (float)lh;
    a->r_tab_find.x = pad + 130;    a->r_tab_find.y = ty;
    a->r_tab_find.w = 160;          a->r_tab_find.h = (float)lh;

    float cy = ty + lh + 4;
    a->r_log_area.x = pad;
    a->r_log_area.y = cy;
    a->r_log_area.w = (float)(W - 2 * pad);
    a->r_log_area.h = (float)(H - cy - 36);
    a->r_find_area  = a->r_log_area;
}

/* --------------------------------------------------------------- rendering */
static void render_log(App *a) {
    SDL_Rect clip = {(int)a->r_log_area.x, (int)a->r_log_area.y,
                     (int)a->r_log_area.w, (int)a->r_log_area.h};
    SDL_SetRenderClipRect(a->ren, &clip);

    int   lh      = a->line_h + 2;
    float content = (float)(a->log_count * lh);
    float view    = a->r_log_area.h;
    float maxscr  = content > view ? content - view : 0;
    if (a->log_autoscroll) a->log_scroll = (int)maxscr;   /* sole scroll owner */
    if (a->log_scroll < 0) a->log_scroll = 0;
    if ((float)a->log_scroll > maxscr) a->log_scroll = (int)maxscr;

    int first   = a->log_scroll / lh;
    int visible = (int)(view / lh) + 2;
    for (int i = 0; i < visible && first + i < a->log_count; i++) {
        LogLine *l = &a->log[first + i];
        float ly = a->r_log_area.y + (float)((first + i) * lh) - (float)a->log_scroll;
        if (ly + lh < a->r_log_area.y || ly > a->r_log_area.y + view) continue;
        if (!l->tex)
            l->tex = render_text(a->ren, a->font, l->text, l->color,
                                 &l->tex_w, &l->tex_h);
        if (!l->tex) continue;
        float maxw = a->r_log_area.w - 16;
        SDL_FRect dst = {a->r_log_area.x + 6, ly,
                         (float)l->tex_w, (float)l->tex_h};
        if ((float)l->tex_w > maxw) {
            SDL_FRect src = {0, 0, maxw, (float)l->tex_h};
            dst.w = maxw;
            SDL_RenderTexture(a->ren, l->tex, &src, &dst);
        } else {
            SDL_RenderTexture(a->ren, l->tex, NULL, &dst);
        }
    }

    if (content > view) {
        float sw = 8;
        float th = view * view / content;
        if (th < 20) th = 20;
        float ty = a->r_log_area.y + (view - th) * (maxscr > 0
                  ? a->log_scroll / maxscr : 0);
        draw_rect(a->ren, a->r_log_area.x + a->r_log_area.w - sw,
                  a->r_log_area.y, sw, view,
                  (SDL_Color){0x1a,0x1c,0x22,0xff});
        draw_rect(a->ren, a->r_log_area.x + a->r_log_area.w - sw,
                  ty, sw, th, (SDL_Color){0x3a,0x3d,0x46,0xff});
    }
    SDL_SetRenderClipRect(a->ren, NULL);
}

static void render_findings(App *a) {
    SDL_Rect clip = {(int)a->r_find_area.x, (int)a->r_find_area.y,
                     (int)a->r_find_area.w, (int)a->r_find_area.h};
    SDL_SetRenderClipRect(a->ren, &clip);

    int   lh      = a->line_h + 2;
    float content = (float)(a->findings_count * lh);
    float view    = a->r_find_area.h;
    float maxscr  = content > view ? content - view : 0;
    if ((float)a->findings_scroll > maxscr) a->findings_scroll = (int)maxscr;
    if (a->findings_scroll < 0) a->findings_scroll = 0;

    int first   = a->findings_scroll / lh;
    int visible = (int)(view / lh) + 2;
    for (int i = 0; i < visible && first + i < a->findings_count; i++) {
        Finding *f = &a->findings[first + i];
        float ly = a->r_find_area.y + (float)((first + i) * lh)
                 - (float)a->findings_scroll;
        char line[1200];
        snprintf(line, sizeof(line), "%-9s %-10s %s",
                 f->sev, f->tool, f->text);
        draw_text_clip(a->ren, a->font, line,
                       a->r_find_area.x + 6, ly,
                       a->r_find_area.w - 16, f->color);
    }
    SDL_SetRenderClipRect(a->ren, NULL);
}

static void render(App *a) {
    int W, H;
    SDL_GetWindowSize(a->win, &W, &H);
    layout(a, W, H);

    SDL_SetRenderDrawColor(a->ren, C_BG.r, C_BG.g, C_BG.b, 0xff);
    SDL_RenderClear(a->ren);

    draw_rect(a->ren, 0, 0, (float)W, a->r_tab_log.y, C_TOP);

    /* row 0 */
    draw_text(a->ren, a->font, "outdir:", 12, a->e_outdir.y + 3, C_DIM);
    draw_entry(a, &a->e_outdir, "out");
    draw_text(a->ren, a->font, "mode:", a->r_mode.x - 44, a->r_mode.y + 3, C_DIM);
    draw_button(a, &a->r_mode, a->modes[a->mode_idx], true, C_BTN);
    draw_text(a->ren, a->font, "proxy:", a->r_mode.x + a->r_mode.w + 6,
              a->e_proxy.y + 3, C_DIM);
    draw_entry(a, &a->e_proxy, "(none)");

    /* row 1 */
    draw_text(a->ren, a->font, "target:", 12, a->e_target.y + 3, C_DIM);
    draw_entry(a, &a->e_target,
               "https://example.com/path  or  example.com");

    /* row 2 */
    draw_text(a->ren, a->font, "flags:", 12, a->r_xss.y + 3, C_DIM);
    draw_checkbox(a, &a->r_xss,      "xss",      a->flag_xss);
    draw_checkbox(a, &a->r_deepblue, "deepblue", a->flag_deepblue);
    draw_checkbox(a, &a->r_tor,      "tor",      a->flag_tor);
    draw_checkbox(a, &a->r_elite,    "elite",    a->flag_elite);
    draw_button(a, &a->r_run,  "\xe2\x96\xb6 RUN",  !a->running, C_RUN);
    draw_button(a, &a->r_stop, "\xe2\x96\xa0 STOP",  a->running, C_STOP);

    /* tabs */
    draw_rect(a->ren, a->r_tab_log.x, a->r_tab_log.y,
              a->r_tab_log.w, a->r_tab_log.h,
              a->active_tab == TAB_LOG ? C_PANEL : C_BG);
    draw_text(a->ren, a->font, "Log", a->r_tab_log.x + 12,
              a->r_tab_log.y + 4, C_FG);

    char fnd[64];
    snprintf(fnd, sizeof(fnd), "Findings (%d)", a->findings_count);
    draw_rect(a->ren, a->r_tab_find.x, a->r_tab_find.y,
              a->r_tab_find.w, a->r_tab_find.h,
              a->active_tab == TAB_FINDINGS ? C_PANEL : C_BG);
    draw_text(a->ren, a->font, fnd, a->r_tab_find.x + 12,
              a->r_tab_find.y + 4, C_FG);

    /* content box */
    draw_rect(a->ren, a->r_log_area.x, a->r_log_area.y,
              a->r_log_area.w, a->r_log_area.h, C_PANEL);
    draw_border(a->ren, a->r_log_area.x, a->r_log_area.y,
                a->r_log_area.w, a->r_log_area.h, C_BORDER, 1);
    if (a->active_tab == TAB_LOG) render_log(a);
    else                          render_findings(a);

    /* status */
    draw_rect(a->ren, 0, (float)(H - 28), (float)W, 28,
              (SDL_Color){0x0a,0x0b,0x0e,0xff});
    draw_text(a->ren, a->font, a->status, 12, (float)(H - 24),
              a->running ? C_ACCENT : C_DIM);

    SDL_RenderPresent(a->ren);
}

/* ---------------------------------------------------------------- events */
static TextEntry *focused_entry(App *a) {
    if (a->e_outdir.focused) return &a->e_outdir;
    if (a->e_target.focused) return &a->e_target;
    if (a->e_proxy.focused)  return &a->e_proxy;
    return NULL;
}
static void unfocus_all(App *a) {
    a->e_outdir.focused = a->e_target.focused = a->e_proxy.focused = false;
}

static void on_key(App *a, const SDL_KeyboardEvent *ev) {
    SDL_Keycode k    = ev->key;
    bool        ctrl = (ev->mod & SDL_KMOD_CTRL) != 0;
    TextEntry  *t    = focused_entry(a);

    if (t) {
        if (ctrl && k == SDLK_V) {
            char *c = SDL_GetClipboardText();
            if (c) {
                /* B9: strip non-ASCII so a multibyte paste can't leave
                 * an invalid-UTF-8 buffer for the mono font renderer */
                char clean[512];
                size_t j = 0;
                for (size_t i = 0; c[i] && j < sizeof(clean) - 1; i++)
                    if ((unsigned char)c[i] < 0x80 && (unsigned char)c[i] >= 0x20)
                        clean[j++] = c[i];
                clean[j] = '\0';
                te_insert(t, clean);
                SDL_free(c);
            }
            return;
        }
        if (k == SDLK_BACKSPACE) { te_back(t); return; }
        if (k == SDLK_DELETE)    { te_del(t);  return; }
        if (k == SDLK_LEFT)      { if (t->cursor > 0) t->cursor--; return; }
        if (k == SDLK_RIGHT)     { if (t->cursor < t->len) t->cursor++; return; }
        if (k == SDLK_HOME)      { t->cursor = 0; return; }
        if (k == SDLK_END)       { t->cursor = t->len; return; }
        if (k == SDLK_RETURN)    { t->focused = false; return; }
        if (k == SDLK_TAB) {
            TextEntry *es[] = {&a->e_outdir, &a->e_target, &a->e_proxy};
            int cur = 0;
            for (int i = 0; i < 3; i++)
                if (es[i]->focused) { cur = i; es[i]->focused = false; }
            es[(cur + 1) % 3]->focused = true;
            return;
        }
    }
    if (k == SDLK_ESCAPE && a->running) stop_scan(a);
}

static void on_text(App *a, const SDL_TextInputEvent *ev) {
    TextEntry *t = focused_entry(a);
    if (!t) return;
    /* B9: same ASCII filter for typed input */
    if ((unsigned char)ev->text[0] < 0x20 || (unsigned char)ev->text[0] >= 0x80)
        return;
    te_insert(t, ev->text);
}

static void on_mouse_down(App *a, float x, float y, int b) {
    if (b != 1) return;
    Rect *rs[] = {&a->r_run, &a->r_stop};
    for (int i = 0; i < 2; i++) {
        Rect *r = rs[i];
        if (x >= r->x && x < r->x + r->w && y >= r->y && y < r->y + r->h)
            r->down = true;
    }
}

static void on_mouse_up(App *a, float x, float y, int b) {
    if (b != 1) return;
    bool hit_run  = a->r_run.down;
    bool hit_stop = a->r_stop.down;
    a->r_run.down = a->r_stop.down = false;

    /* text entries */
    TextEntry *es[] = {&a->e_outdir, &a->e_target, &a->e_proxy};
    for (int i = 0; i < 3; i++) {
        TextEntry *e = es[i];
        if (x >= e->x && x < e->x + e->w && y >= e->y && y < e->y + e->h) {
            unfocus_all(a);
            e->focused = true;
            float local = x - e->x - 8;
            /* B8: cap measurement so entries beyond tmp[] are clamped
             * instead of silently unmeasurable */
            char  tmp[512];
            int   bi = 0;
            for (int c = 0; c <= e->len && c < (int)sizeof(tmp) - 1; c++) {
                memcpy(tmp, e->buf, c); tmp[c] = 0;
                if (text_width(a->font, tmp) <= local) bi = c;
                else break;
            }
            if (e->len >= (int)sizeof(tmp) - 1 && bi == 0)
                bi = (int)sizeof(tmp) - 2;
            e->cursor = bi;
            return;
        }
    }
    /* click outside the controls: drop focus */
    if (!(x >= a->e_outdir.x && x < a->e_proxy.x + a->e_proxy.w &&
          y >= a->e_outdir.y && y < a->r_stop.y + a->r_stop.h))
        unfocus_all(a);

    /* mode cycle */
    if (x >= a->r_mode.x && x < a->r_mode.x + a->r_mode.w &&
        y >= a->r_mode.y && y < a->r_mode.y + a->r_mode.h) {
        a->mode_idx = (a->mode_idx + 1) % a->mode_count;
        return;
    }
    /* checkboxes */
    Rect *fr[] = {&a->r_xss, &a->r_deepblue, &a->r_tor, &a->r_elite};
    bool *fv[] = {&a->flag_xss, &a->flag_deepblue, &a->flag_tor, &a->flag_elite};
    for (int i = 0; i < 4; i++) {
        if (x >= fr[i]->x && x < fr[i]->x + fr[i]->w &&
            y >= fr[i]->y && y < fr[i]->y + fr[i]->h) {
            *fv[i] = !*fv[i];
            return;
        }
    }
    /* RUN / STOP */
    if (hit_run && !a->running) {
        if (!a->e_target.len) { set_status(a, "target required"); return; }
        if (!a->e_outdir.len) { set_status(a, "outdir required"); return; }
        /* B6-side guard: never let the user inject --no-ui via fields */
        if (strstr(a->e_target.buf, "--no-ui") ||
            strstr(a->e_outdir.buf, "--no-ui")) {
            set_status(a, "'--no-ui' not allowed in fields");
            return;
        }
        spawn_scan(a);
        return;
    }
    if (hit_stop && a->running) { stop_scan(a); return; }

    /* tabs */
    if (x >= a->r_tab_log.x && x < a->r_tab_log.x + a->r_tab_log.w &&
        y >= a->r_tab_log.y && y < a->r_tab_log.y + a->r_tab_log.h) {
        a->active_tab = TAB_LOG;
        return;
    }
    if (x >= a->r_tab_find.x && x < a->r_tab_find.x + a->r_tab_find.w &&
        y >= a->r_tab_find.y && y < a->r_tab_find.y + a->r_tab_find.h) {
        a->active_tab = TAB_FINDINGS;
        return;
    }
}

static void on_motion(App *a, float x, float y) {
    Rect *rs[] = {&a->r_run, &a->r_stop, &a->r_tab_log, &a->r_tab_find};
    for (int i = 0; i < 4; i++) {
        Rect *r = rs[i];
        r->hover = (x >= r->x && x < r->x + r->w &&
                    y >= r->y && y < r->y + r->h);
    }
}

static void on_wheel(App *a, float dy) {
    int step = (a->line_h + 2) * 3;
    if (a->active_tab == TAB_LOG) {
        a->log_scroll -= (int)(dy * step);
        if (a->log_scroll < 0) a->log_scroll = 0;
        a->log_autoscroll = false;
        int   lh      = a->line_h + 2;
        float content = (float)(a->log_count * lh);
        float view    = a->r_log_area.h;
        if (content > view && a->log_scroll >= content - view - 2)
            a->log_autoscroll = true;
    } else {
        a->findings_scroll -= (int)(dy * step);
        if (a->findings_scroll < 0) a->findings_scroll = 0;
    }
}

/* ---------------------------------------------------------------- startup */
static void prefill(App *a, int argc, char **argv) {
    if (argc < 4) return;
    strncpy(a->e_outdir.buf, argv[1], sizeof(a->e_outdir.buf) - 1);
    a->e_outdir.buf[sizeof(a->e_outdir.buf) - 1] = '\0';
    a->e_outdir.len    = (int)strlen(a->e_outdir.buf);
    a->e_outdir.cursor = a->e_outdir.len;

    strncpy(a->e_target.buf, argv[3], sizeof(a->e_target.buf) - 1);
    a->e_target.buf[sizeof(a->e_target.buf) - 1] = '\0';
    a->e_target.len    = (int)strlen(a->e_target.buf);
    a->e_target.cursor = a->e_target.len;

    for (int i = 0; i < a->mode_count; i++)
        if (!strcmp(argv[2], a->modes[i])) { a->mode_idx = i; break; }

    for (int i = 4; i < argc; i++) {
        if      (!strcmp(argv[i], "--xss-no"))   a->flag_xss      = false;
        else if (!strcmp(argv[i], "--deepblue")) a->flag_deepblue = true;
        else if (!strcmp(argv[i], "--tor"))      a->flag_tor      = true;
        else if (!strcmp(argv[i], "--elite"))    a->flag_elite    = true;
        else if (!strcmp(argv[i], "--proxy") && i + 1 < argc) {
            strncpy(a->e_proxy.buf, argv[++i], sizeof(a->e_proxy.buf) - 1);
            a->e_proxy.buf[sizeof(a->e_proxy.buf) - 1] = '\0';
            a->e_proxy.len    = (int)strlen(a->e_proxy.buf);
            a->e_proxy.cursor = a->e_proxy.len;
        }
    }
}

/* B10: extended font probe with a glob-free recursive scan fallback
 * so non-Debian layouts degrade instead of hard-failing. */
static const char *pick_font(void) {
    static char found[512];
    static const char *paths[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        "/usr/share/fonts/misc/unifont.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        NULL
    };
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], R_OK) == 0) return paths[i];

    /* last resort: find any readable .ttf under /usr/share/fonts */
    static const char *dirs[] = {
        "/usr/share/fonts/truetype", "/usr/share/fonts/TTF",
        "/usr/share/fonts/opentype", "/usr/share/fonts/OTF",
        "/usr/share/fonts/misc", "/usr/share/fonts", NULL
    };
    for (int i = 0; dirs[i]; i++) {
        char cmd[600];
        snprintf(cmd, sizeof(cmd),
                 "find %s -maxdepth 3 -name '*.ttf' -print -quit 2>/dev/null",
                 dirs[i]);
        FILE *fp = popen(cmd, "r");
        if (!fp) continue;
        if (fgets(found, sizeof(found), fp)) {
            found[strcspn(found, "\n")] = '\0';
            pclose(fp);
            if (found[0] && access(found, R_OK) == 0) return found;
        } else {
            pclose(fp);
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------- entry */
int ui_run(int argc, char **argv) {
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        return 1;
    }
    if (!TTF_Init()) {
        fprintf(stderr, "TTF_Init: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }

    const char *fp = pick_font();
    if (!fp) {
        fprintf(stderr, "[-] no monospace font found; install DejaVu or Liberation\n");
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    static App a;
    memset(&a, 0, sizeof(a));

    a.win = SDL_CreateWindow("Sentinel \xe2\x80\x94 automated pentest scanner",
                             1100, 700, SDL_WINDOW_RESIZABLE);
    if (!a.win) {
        fprintf(stderr, "CreateWindow: %s\n", SDL_GetError());
        TTF_Quit(); SDL_Quit();
        return 1;
    }
    a.ren = SDL_CreateRenderer(a.win, NULL);
    if (!a.ren) {
        fprintf(stderr, "CreateRenderer: %s\n", SDL_GetError());
        SDL_DestroyWindow(a.win); TTF_Quit(); SDL_Quit();
        return 1;
    }
    a.font = TTF_OpenFont(fp, 14.0f);
    if (!a.font) {
        fprintf(stderr, "TTF_OpenFont(%s): %s\n", fp, SDL_GetError());
        SDL_DestroyRenderer(a.ren); SDL_DestroyWindow(a.win);
        TTF_Quit(); SDL_Quit();
        return 1;
    }
    a.line_h = TTF_GetFontLineSkip(a.font);
    if (a.line_h <= 0) a.line_h = 18;

    /* B14: --gobuster removed until the engine wires it (it currently
     * always fails with rc=1 in run_headless) */
    a.modes[0] = "--scan-url";
    a.modes[1] = "--scan-site";
    a.modes[2] = "--xss-only";
    a.modes[3] = "--url";
    a.modes[4] = "-sub";
    a.modes[5] = "--full-scan";
    a.modes[6] = "--fast-scan";
    a.mode_count = 7;
    a.mode_idx   = 0;
    a.flag_xss   = true;
    a.active_tab = TAB_LOG;
    a.log_autoscroll = true;
    pthread_mutex_init(&a.q_lock, NULL);

    strcpy(a.status, "ready");
    prefill(&a, argc, argv);

    SDL_StartTextInput(a.win);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (argc >= 4) spawn_scan(&a);

    bool quit = false;
    while (!quit) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            switch (ev.type) {
                case SDL_EVENT_QUIT:       quit = true; break;
                case SDL_EVENT_KEY_DOWN:   on_key(&a, &ev.key); break;
                case SDL_EVENT_TEXT_INPUT: on_text(&a, &ev.text); break;
                case SDL_EVENT_MOUSE_BUTTON_DOWN:
                    on_mouse_down(&a, ev.button.x, ev.button.y, ev.button.button);
                    break;
                case SDL_EVENT_MOUSE_BUTTON_UP:
                    on_mouse_up(&a, ev.button.x, ev.button.y, ev.button.button);
                    break;
                case SDL_EVENT_MOUSE_MOTION:
                    on_motion(&a, ev.motion.x, ev.motion.y);
                    break;
                case SDL_EVENT_MOUSE_WHEEL:
                    on_wheel(&a, ev.wheel.y);
                    break;
                default: break;
            }
        }
        stop_escalate(&a);   /* B7 */
        drain_pending(&a);
        reap_children(&a);
        render(&a);
        SDL_Delay(15);
    }

    if (a.running && a.child_pid > 0) {
        kill(-a.child_pid, SIGKILL);
        waitpid(a.child_pid, NULL, 0);
    }
    for (int i = 0; i < a.log_count; i++) log_free(&a.log[i]);
    TTF_CloseFont(a.font);
    SDL_DestroyRenderer(a.ren);
    SDL_DestroyWindow(a.win);
    TTF_Quit();
    SDL_Quit();
    return 0;
}