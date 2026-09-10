#ifndef PROX_H
#define PROX_H

#include <stdbool.h>
#include <sys/types.h>

/*
 * Sentinel multi-mode proxy + tool execution API.
 *
 * Modes (selected with proxy_init before any run_tool call):
 *   PROXY_NONE   — direct connections, no proxy (default; no proxychains)
 *   PROXY_TOR    — pool of MAX_TOR local Tor SOCKS5 instances (9050..)
 *   PROXY_CUSTOM — user-supplied list of >= MIN_CUSTOM proxies, one per
 *                  line in `list_path`:  [proto://]host:port
 *                  (proto: http://, socks4://, socks5://; default socks5)
 *   PROXY_ELITE  — free "elite" proxies fetched live from proxyscrape.com.
 *                  These are PUBLIC proxies: usable, but not trustworthy
 *                  for sensitive traffic — see the printed disclaimer.
 *
 * Thread-safety: all pool state is guarded by an internal mutex. run_tool()
 * and run_tool_out() may be called concurrently — each invocation writes its
 * own unique proxychains config and touches no shared mutable state.
 *
 * NOTE: curl_global_init() (curl_http_init()) must have been called once
 * before any network use (main.c does this).
 */

/* Proxy mode identifiers (shared with global.h via int field). */
enum proxy_mode {
    PROXY_NONE = 0,
    PROXY_TOR,
    PROXY_CUSTOM,
    PROXY_ELITE
};

/* Select the proxy mode and prepare the pool.
 *   list_path: required for PROXY_CUSTOM; optional cache path for
 *              PROXY_ELITE (default: darkshield/proxy/custom/proxyscrape.txt)
 * Returns 0 on success, -1 on failure (too few proxies, fetch failed...).
 * Idempotent for the same mode; switching modes tears the old pool down. */
int proxy_init(int mode, const char *list_path);

/* Tear the pool down (kill Tor children, reset state). Safe repeatedly. */
void proxy_shutdown(void);

/* Compatibility alias: applies the mode already stored in g.proxy_mode. */
void start_proxies(void);

/* Kill and reap all Tor instances spawned by the pool. */
void kill_tor_processes(void);

/* Current healthy proxy URI (socks5h://127.0.0.1:port for Tor, else
 * http://host:port / socks5h://host:port / socks4a://host:port), or NULL
 * in PROXY_NONE mode. Thread-local buffer: valid until next call on the
 * same thread. */
const char *proxy_get_socks(void);

/* Burn the current proxy and rotate to the next healthy one.
 * Returns 0 on success, -1 if the pool had to be restarted. */
int burn_rotate(void);

/* Tool execution (replaces system_proxied; no shell, no injection).
 * argv MUST be NULL-terminated.
 * PROXY_NONE: executed directly. Otherwise wrapped in proxychains4 -f <conf>.
 * Returns: tool exit code, 124 = timed out, 127 = exec failed,
 *          -1 = fork/config error, -2 = proxy pool unavailable. */
int run_tool(char *const argv[]);

/* Same, with stdout+stderr redirected to out_path (O_APPEND if append). */
static int run_tool_impl(char *const argv[], const char *out_path, bool append);

int run_tool_out(char *const argv[], const char *out_path, bool append);

#endif /* PROX_H */