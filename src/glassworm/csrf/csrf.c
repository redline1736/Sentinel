#include "csrf.h"
#include "../../global.h"
#include "../../http/http.h"
#include "../../util/util.h"

/* ============================================================
 * CSRF detection constants
 * ============================================================ */

/* --- Cookie names that indicate a double-submit CSRF defense --- */
static const char *CSRF_COOKIE_NAMES[] = {
    "XSRF-TOKEN",
    "csrftoken",
    "_csrf",
    "csrf_token",
    "CSRF-TOKEN",
    "X-CSRF-TOKEN",
    NULL
};

/* --- Meta tag names that carry a CSRF token to JavaScript --- */
static const char *CSRF_META_NAMES[] = {
    "csrf-token",
    "csrf-param",
    "_csrf",
    "_csrf_header",
    "xsrf-token",
    NULL
};

/* --- Hidden input field names that carry a CSRF token in HTML forms --- */
static const char *CSRF_FORM_FIELDS[] = {
    "csrf_token",
    "_csrf",
    "_token",
    "authenticity_token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "X-CSRF-Token",
    NULL
};

/* --- Response-body phrases that indicate a token check rejected the request --- */
static const char *CSRF_ERROR_PHRASES[] = {
    "CSRF token missing",
    "CSRF verification failed",
    "CSRF token mismatch",
    "Invalid CSRF token",
    "Invalid authenticity token",
    "Can't verify CSRF token authenticity",
    "RequestVerificationToken",
    "Anti-forgery token",
    "anti-forgery",
    "_csrf token required",
    NULL
};

int csrf_token_exists(const char *target_url) {
    request r = {0};

    if (!http_send_post(&r, target_url, false, NULL, false, NULL)) {
        fprintf(stderr, "HTTP POST failed for %s\n", target_url);
        return -1;
    }

    int found = 0;

    /* Cookie names may appear in Set-Cookie lines of the raw response */
    for (int i = 0; CSRF_COOKIE_NAMES[i] && !found; i++) {
        if (find_string_in_file(r.filename, CSRF_COOKIE_NAMES[i]))
            found = 1;
    }

    /* Meta tags and hidden form fields live in the HTML body */
    for (int i = 0; CSRF_META_NAMES[i] && !found; i++) {
        if (find_string_in_file(r.filename, CSRF_META_NAMES[i]))
            found = 1;
    }
    for (int i = 0; CSRF_FORM_FIELDS[i] && !found; i++) {
        if (find_string_in_file(r.filename, CSRF_FORM_FIELDS[i]))
            found = 1;
    }

    /* Error phrases confirm a token check is actually enforced */
    for (int i = 0; CSRF_ERROR_PHRASES[i] && !found; i++) {
        if (find_string_in_file(r.filename, CSRF_ERROR_PHRASES[i]))
            found = 1;
    }

    if (r.filename[0])
        remove(r.filename);

    return found;
}