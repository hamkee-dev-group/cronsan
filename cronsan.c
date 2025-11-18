// cronsan.c - Pure C crontab linter / sanitizer (MVP)
//
// Features:
//  - Parse basic Vixie-style 5-field crontab lines (+ @special entries).
//  - Validate fields and detect invalid syntax / ranges.
//  - Compute next run from "now" for each job.
//  - Detect overlapping jobs within a time window (default: 24h).
//  - Warn about dangerous patterns like "* * * * *" / "*/1 * * * *".
//  - Warn about suspicious env lines.
//
// Notes (for “enterprise-grade-ish” quality):
//  - No dynamic buffers on stack proportional to file size.
//  - Fixed caps for jobs/line length to avoid surprises.
//  - Simple, auditable control flow.
//  - Uses gmtime_r (UTC) for deterministic schedule reasoning.
//  - No self-modifying global state; you can later wrap it as a library.
//
// This is **not** complete cron semantics (no seconds, no non-standard
// extensions), but it’s a solid and safe base that parses real crontabs.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#define CRONSAN_MAX_JOBS 1024
#define CRONSAN_MAX_LINE 4096
#define CRONSAN_MAX_TOKENS 32

// Time ranges
#define MIN_MIN 0
#define MAX_MIN 59
#define MIN_HOUR 0
#define MAX_HOUR 23
#define MIN_DOM 1
#define MAX_DOM 31
#define MIN_MON 1
#define MAX_MON 12
#define MIN_DOW 0
#define MAX_DOW 6

// Bitset macros (we can store up to 64 values per field)
typedef unsigned long long bitset64;

static void bitset_set(bitset64 *bs, int v)
{
    if (v < 0 || v >= 64)
        return;
    *bs |= (1ULL << v);
}
static int bitset_isset(bitset64 bs, int v)
{
    if (v < 0 || v >= 64)
        return 0;
    return (bs >> v) & 1U;
}
static int bitset_isempty(bitset64 bs)
{
    return bs == 0;
}

// A parsed schedule expression
typedef struct
{
    bitset64 minute;
    bitset64 hour;
    bitset64 dom;
    bitset64 mon;
    bitset64 dow;
    int dom_star; // 1 if field was "*"
    int dow_star;
    int is_special; // @reboot, @daily, etc.
    char special[32];
} cron_expr;

// A parsed job
typedef struct
{
    int line_no;
    char *raw_line; // original line (for diagnostics)
    char *command;  // command portion (malloc'ed)
    cron_expr expr;
} cron_job;

// Simple dynamic array of jobs (fixed max for simplicity)
typedef struct
{
    cron_job jobs[CRONSAN_MAX_JOBS];
    size_t count;
} job_list;

// ---- Utility ----

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (!p)
    {
        fprintf(stderr, "cronsan: OOM\n");
        exit(1);
    }
    memcpy(p, s, n);
    return p;
}

static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == 0)
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
    {
        *end = 0;
        end--;
    }
    return s;
}

// ---- Month / DOW names ----

static int mon_name_to_int(const char *s)
{
    // JAN..DEC
    static const char *names[] = {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
    for (int i = 0; i < 12; i++)
    {
        if (strcasecmp(s, names[i]) == 0)
            return i + 1;
    }
    return -1;
}

static int dow_name_to_int(const char *s)
{
    // SUN..SAT
    static const char *names[] = {
        "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
    for (int i = 0; i < 7; i++)
    {
        if (strcasecmp(s, names[i]) == 0)
            return i;
    }
    return -1;
}

// ---- Field parsing ----
//
// Grammar (classic cron):
//  list := item ("," item)*
//  item := "*" ["/" step] | range ["/" step]
//  range := value | value "-" value
//  value := int | name (for MON/DOW)
//
// Values must fall within [lo, hi] inclusive.

static int parse_int(const char *s, int *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return -1;
    if (v < -2147483648L || v > 2147483647L)
        return -1;
    *out = (int)v;
    return 0;
}

static int parse_value(const char *tok, int lo, int hi, int is_mon, int is_dow, int *out)
{
    int v;
    if (parse_int(tok, &v) == 0)
    {
        // For DOW, 7 is also Sunday
        if (is_dow && v == 7)
            v = 0;
    }
    else
    {
        if (is_mon)
        {
            v = mon_name_to_int(tok);
        }
        else if (is_dow)
        {
            v = dow_name_to_int(tok);
        }
        else
        {
            return -1;
        }
        if (v < 0)
            return -1;
    }
    if (v < lo || v > hi)
        return -1;
    *out = v;
    return 0;
}

static int parse_field(const char *field,
                       int lo, int hi,
                       int is_mon, int is_dow,
                       bitset64 *out_bits,
                       int *out_is_star,
                       char *errbuf, size_t errbuf_sz)
{
    bitset64 bits = 0;
    int seen_any = 0;
    int is_star = 0;

    // Work on a copy for strtok-like splitting
    char buf[256];
    if (strlen(field) >= sizeof(buf))
    {
        snprintf(errbuf, errbuf_sz, "field too long");
        return -1;
    }
    strcpy(buf, field);

    char *saveptr = NULL;
    char *item = strtok_r(buf, ",", &saveptr);
    while (item)
    {
        item = trim(item);
        if (*item == '\0')
        {
            snprintf(errbuf, errbuf_sz, "empty list element");
            return -1;
        }

        char *slash = strchr(item, '/');
        char *range_part = item;
        int step = 1;
        if (slash)
        {
            *slash = '\0';
            char *step_str = slash + 1;
            if (*step_str == '\0')
            {
                snprintf(errbuf, errbuf_sz, "empty step value");
                return -1;
            }
            if (parse_int(step_str, &step) != 0 || step <= 0)
            {
                snprintf(errbuf, errbuf_sz, "invalid step '%s'", step_str);
                return -1;
            }
        }

        int r_lo, r_hi;
        if (strcmp(range_part, "*") == 0)
        {
            r_lo = lo;
            r_hi = hi;
            is_star = 1;
        }
        else
        {
            char *dash = strchr(range_part, '-');
            if (!dash)
            {
                // Single value
                if (parse_value(range_part, lo, hi, is_mon, is_dow, &r_lo) != 0)
                {
                    snprintf(errbuf, errbuf_sz, "invalid value '%s'", range_part);
                    return -1;
                }
                r_hi = r_lo;
            }
            else
            {
                *dash = '\0';
                char *b1 = range_part;
                char *b2 = dash + 1;
                if (*b1 == '\0' || *b2 == '\0')
                {
                    snprintf(errbuf, errbuf_sz, "invalid range '%s-%s'", b1, b2);
                    return -1;
                }
                if (parse_value(b1, lo, hi, is_mon, is_dow, &r_lo) != 0 ||
                    parse_value(b2, lo, hi, is_mon, is_dow, &r_hi) != 0)
                {
                    snprintf(errbuf, errbuf_sz, "invalid range values");
                    return -1;
                }
                if (r_lo > r_hi)
                {
                    snprintf(errbuf, errbuf_sz, "range start > end");
                    return -1;
                }
            }
        }

        for (int v = r_lo; v <= r_hi; v += step)
        {
            bitset_set(&bits, v);
            seen_any = 1;
        }

        item = strtok_r(NULL, ",", &saveptr);
    }

    if (!seen_any)
    {
        snprintf(errbuf, errbuf_sz, "empty field");
        return -1;
    }

    *out_bits = bits;
    if (out_is_star)
        *out_is_star = is_star;
    return 0;
}

// ---- Cron line parsing ----

// Tokenize by whitespace into up to CRONSAN_MAX_TOKENS tokens.
// Returns count. Modifies buf in place.
static int split_ws(char *buf, char *tokens[], int max_tokens)
{
    int n = 0;
    char *p = buf;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;
        if (n >= max_tokens)
            break;
        tokens[n++] = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        if (*p)
        {
            *p = '\0';
            p++;
        }
    }
    return n;
}

static int looks_like_env_line(const char *line)
{
    // Heuristic: KEY=VALUE with no leading spaces and KEY is all [A-Z0-9_]
    const char *p = line;
    if (*p == '#' || *p == '\0' || isspace((unsigned char)*p))
        return 0;
    while (*p && (isalnum((unsigned char)*p) || *p == '_'))
        p++;
    if (*p != '=')
        return 0;
    return 1;
}

static int parse_cron_line(int line_no, char *line, cron_job *out_job, char *errbuf, size_t errbuf_sz)
{
    char *orig = xstrdup(line);
    char *s = trim(line);

    if (*s == '\0' || *s == '#')
    {
        free(orig);
        return 1; // empty or comment
    }

    // Env line?
    if (looks_like_env_line(s))
    {
        // For now treat env lines as non-jobs; caller can warn if malformed.
        free(orig);
        return 2;
    }

    // Tokenize
    char *tokens[CRONSAN_MAX_TOKENS];
    int ntok = split_ws(s, tokens, CRONSAN_MAX_TOKENS);
    if (ntok == 0)
    {
        free(orig);
        return 1;
    }

    cron_expr expr;
    memset(&expr, 0, sizeof(expr));

    int first_cmd_tok = -1;

    if (tokens[0][0] == '@')
    {
        // @special form
        if (strcmp(tokens[0], "@reboot") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@reboot", sizeof(expr.special) - 1);
        }
        else if (strcmp(tokens[0], "@yearly") == 0 || strcmp(tokens[0], "@annually") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@yearly", sizeof(expr.special) - 1);
        }
        else if (strcmp(tokens[0], "@monthly") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@monthly", sizeof(expr.special) - 1);
        }
        else if (strcmp(tokens[0], "@weekly") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@weekly", sizeof(expr.special) - 1);
        }
        else if (strcmp(tokens[0], "@daily") == 0 || strcmp(tokens[0], "@midnight") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@daily", sizeof(expr.special) - 1);
        }
        else if (strcmp(tokens[0], "@hourly") == 0)
        {
            expr.is_special = 1;
            strncpy(expr.special, "@hourly", sizeof(expr.special) - 1);
        }
        else
        {
            snprintf(errbuf, errbuf_sz, "unknown @special '%s'", tokens[0]);
            free(orig);
            return -1;
        }
        first_cmd_tok = 1;
    }
    else
    {
        if (ntok < 6)
        {
            snprintf(errbuf, errbuf_sz, "expected at least 6 fields, got %d", ntok);
            free(orig);
            return -1;
        }

        {
            char field_err[128];
            if (parse_field(tokens[0], MIN_MIN, MAX_MIN, 0, 0, &expr.minute, NULL,
                            field_err, sizeof(field_err)) != 0)
            {
                snprintf(errbuf, errbuf_sz, "minute field: %s", field_err);
                free(orig);
                return -1;
            }
            if (parse_field(tokens[1], MIN_HOUR, MAX_HOUR, 0, 0, &expr.hour, NULL,
                            field_err, sizeof(field_err)) != 0)
            {
                snprintf(errbuf, errbuf_sz, "hour field: %s", field_err);
                free(orig);
                return -1;
            }
            if (parse_field(tokens[2], MIN_DOM, MAX_DOM, 0, 0, &expr.dom, &expr.dom_star,
                            field_err, sizeof(field_err)) != 0)
            {
                snprintf(errbuf, errbuf_sz, "dom field: %s", field_err);
                free(orig);
                return -1;
            }
            if (parse_field(tokens[3], MIN_MON, MAX_MON, 1, 0, &expr.mon, NULL,
                            field_err, sizeof(field_err)) != 0)
            {
                snprintf(errbuf, errbuf_sz, "month field: %s", field_err);
                free(orig);
                return -1;
            }
            if (parse_field(tokens[4], MIN_DOW, MAX_DOW, 0, 1, &expr.dow, &expr.dow_star,
                            field_err, sizeof(field_err)) != 0)
            {
                snprintf(errbuf, errbuf_sz, "dow field: %s", field_err);
                free(orig);
                return -1;
            }
        }

        first_cmd_tok = 5;
    }

    if (first_cmd_tok >= ntok)
    {
        snprintf(errbuf, errbuf_sz, "missing command");
        free(orig);
        return -1;
    }

    // Command is rest of the line from tokens[first_cmd_tok]
    size_t cmd_len = 0;
    for (int i = first_cmd_tok; i < ntok; i++)
    {
        cmd_len += strlen(tokens[i]) + 1;
    }
    char *cmd = (char *)malloc(cmd_len + 1);
    if (!cmd)
    {
        fprintf(stderr, "cronsan: OOM\n");
        exit(1);
    }
    cmd[0] = '\0';
    for (int i = first_cmd_tok; i < ntok; i++)
    {
        strcat(cmd, tokens[i]);
        if (i + 1 < ntok)
            strcat(cmd, " ");
    }

    out_job->line_no = line_no;
    out_job->raw_line = orig;
    out_job->command = cmd;
    out_job->expr = expr;
    return 0;
}

// ---- Schedule matching / next-run ----

static int cron_matches(const cron_expr *e, const struct tm *tm)
{
    if (e->is_special)
    {
        // For now, only handle @hourly/@daily/@weekly/@monthly/@yearly.
        // These are converted into equivalent expressions here.
        int m = tm->tm_min;
        int h = tm->tm_hour;
        int dom = tm->tm_mday;
        int mon = tm->tm_mon + 1;
        int dow = tm->tm_wday;
        if (strcmp(e->special, "@hourly") == 0)
        {
            return (m == 0);
        }
        else if (strcmp(e->special, "@daily") == 0)
        {
            return (m == 0 && h == 0);
        }
        else if (strcmp(e->special, "@weekly") == 0)
        {
            return (m == 0 && h == 0 && dow == 0);
        }
        else if (strcmp(e->special, "@monthly") == 0)
        {
            return (m == 0 && h == 0 && dom == 1);
        }
        else if (strcmp(e->special, "@yearly") == 0)
        {
            return (m == 0 && h == 0 && dom == 1 && mon == 1);
        }
        else if (strcmp(e->special, "@reboot") == 0)
        {
            // @reboot is not time-based; skip in next-run logic.
            return 0;
        }
        return 0;
    }

    int m = tm->tm_min;
    int h = tm->tm_hour;
    int dom = tm->tm_mday;
    int mon = tm->tm_mon + 1;
    int dow = tm->tm_wday;

    if (!bitset_isset(e->minute, m))
        return 0;
    if (!bitset_isset(e->hour, h))
        return 0;
    if (!bitset_isset(e->mon, mon))
        return 0;

    int dom_match = bitset_isset(e->dom, dom);
    int dow_match = bitset_isset(e->dow, dow);

    if (!e->dom_star && !e->dow_star)
    {
        // When both DOM and DOW are restricted, match if EITHER matches.
        return dom_match || dow_match;
    }
    else
    {
        // If one is "*", the other must match.
        if (!e->dom_star && !dom_match)
            return 0;
        if (!e->dow_star && !dow_match)
            return 0;
        return 1;
    }
}

// Find next run > from_time within horizon_minutes.
// Returns 0 on success, -1 if none found in range.
static int cron_next_run(const cron_expr *e,
                         time_t from_time,
                         int horizon_minutes,
                         time_t *out_next)
{
    if (e->is_special && strcmp(e->special, "@reboot") == 0)
    {
        return -1; // no time-based next run
    }

    time_t t = from_time;
    struct tm tm;
    for (int i = 0; i < horizon_minutes; i++)
    {
        t += 60; // next minute
        if (!gmtime_r(&t, &tm))
        {
            return -1;
        }
        if (cron_matches(e, &tm))
        {
            *out_next = t;
            return 0;
        }
    }
    return -1;
}

// ---- Overlap detection ----
//
// For simplicity and robustness, we scan a fixed-size window from now for overlaps.
// You can later improve this with smarter bitset intersection to reduce noise.

static void detect_overlaps(const job_list *jobs, time_t ref_time, int window_minutes)
{
    if (jobs->count < 2)
        return;

    int *runs = (int *)calloc((size_t)window_minutes, sizeof(int));
    if (!runs)
    {
        fprintf(stderr, "cronsan: OOM in detect_overlaps\n");
        return;
    }

    for (size_t i = 0; i < jobs->count; i++)
    {
        const cron_expr *e = &jobs->jobs[i].expr;
        if (e->is_special && strcmp(e->special, "@reboot") == 0)
        {
            continue;
        }
        time_t t = ref_time;
        struct tm tm;
        for (int offset = 0; offset < window_minutes; offset++)
        {
            t = ref_time + (offset + 1) * 60;
            if (!gmtime_r(&t, &tm))
                break;
            if (cron_matches(e, &tm))
            {
                if (runs[offset] && runs[offset] != (int)(i + 1))
                {
                    char ts[64];
                    if (strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M UTC", &tm) == 0)
                    {
                        strcpy(ts, "UNKNOWN-TIME");
                    }

                    printf("WARNING: jobs on lines %d and %d overlap at %s\n",
                           jobs->jobs[i].line_no,
                           jobs->jobs[(size_t)(runs[offset] - 1)].line_no,
                           ts);
                }
                else if (!runs[offset])
                {
                    runs[offset] = (int)(i + 1);
                }
            }
        }
    }

    free(runs);
}

// ---- Dangerous pattern checks ----

static int is_every_minute(const cron_expr *e)
{
    if (e->is_special)
    {
        return strcmp(e->special, "@hourly") == 0; // not really every minute; placeholder
    }
    // Check minute bitset == all 0..59
    int count = 0;
    for (int m = 0; m < 60; m++)
    {
        if (bitset_isset(e->minute, m))
            count++;
    }
    return count == 60;
}

// ---- Main CLI ----

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-f CRONTAB] [-H hours_overlap]\n"
            "  Reads a crontab (default: stdin), lints it, and reports issues.\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    int overlap_hours = 24; // scan 1 day by default

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
        {
            path = argv[++i];
        }
        else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc)
        {
            overlap_hours = atoi(argv[++i]);
            if (overlap_hours <= 0)
                overlap_hours = 24;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            usage(argv[0]);
            return 1;
        }
    }

    FILE *fp = stdin;
    if (path)
    {
        fp = fopen(path, "r");
        if (!fp)
        {
            perror("fopen");
            return 1;
        }
    }

    job_list jobs;
    memset(&jobs, 0, sizeof(jobs));

    char linebuf[CRONSAN_MAX_LINE];
    int line_no = 0;
    int had_error = 0;

    while (fgets(linebuf, sizeof(linebuf), fp))
    {
        line_no++;

        char workbuf[CRONSAN_MAX_LINE];
        strncpy(workbuf, linebuf, sizeof(workbuf) - 1);
        workbuf[sizeof(workbuf) - 1] = '\0';

        char errbuf[256];
        cron_job job;
        int rc = parse_cron_line(line_no, workbuf, &job, errbuf, sizeof(errbuf));
        if (rc == 1)
        {
            continue; // comment/empty
        }
        else if (rc == 2)
        {
            // env line; basic validation: must be KEY=VALUE with no spaces around '='
            const char *p = linebuf;
            while (*p && !isspace((unsigned char)*p) && *p != '=')
                p++;
            if (*p != '=')
            {
                printf("WARNING: line %d looks like env assignment but is malformed: %s",
                       line_no, linebuf);
            }
            continue;
        }
        else if (rc != 0)
        {
            printf("ERROR: line %d: %s\n", line_no, errbuf);
            had_error = 1;
            continue;
        }

        if (jobs.count >= CRONSAN_MAX_JOBS)
        {
            printf("ERROR: too many jobs (max %d)\n", CRONSAN_MAX_JOBS);
            had_error = 1;
            free(job.raw_line);
            free(job.command);
            break;
        }

        jobs.jobs[jobs.count++] = job;
    }

    if (fp != stdin)
        fclose(fp);

    time_t now = time(NULL);
    struct tm now_tm;
    gmtime_r(&now, &now_tm);

    printf("Parsed %zu jobs.\n", jobs.count);

    int horizon_minutes = overlap_hours * 60;

    for (size_t i = 0; i < jobs.count; i++)
    {
        cron_job *j = &jobs.jobs[i];
        printf("Job at line %d: %s\n", j->line_no, j->command);

        if (j->expr.is_special && strcmp(j->expr.special, "@reboot") == 0)
        {
            printf("  Schedule: %s (runs at daemon startup; no next-run time)\n",
                   j->expr.special);
        }
        else
        {
            time_t next;
            if (cron_next_run(&j->expr, now, horizon_minutes, &next) == 0)
            {
                struct tm tm;
                gmtime_r(&next, &tm);
                char buf[64];
                strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
                printf("  Next run within %d hours: %s\n", overlap_hours, buf);
            }
            else
            {
                printf("  Next run not found within %d hours (may be very infrequent)\n",
                       overlap_hours);
            }
        }

        if (is_every_minute(&j->expr))
        {
            printf("  WARNING: runs every minute. Ensure this is intentional.\n");
        }
    }

    detect_overlaps(&jobs, now, horizon_minutes);

    // Cleanup
    for (size_t i = 0; i < jobs.count; i++)
    {
        free(jobs.jobs[i].raw_line);
        free(jobs.jobs[i].command);
    }

    return had_error ? 2 : 0;
}
