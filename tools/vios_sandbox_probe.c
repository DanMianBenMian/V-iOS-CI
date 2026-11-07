/* vios_sandbox_probe.c - V-iOS guest-side App sandbox probe.
 *
 * Depends only on libSystem.B.dylib (matches jprx/ios-cli-tools sysroot:
 * no dyld shared cache, no sandbox-exec, no launchctl on the ramdisk).
 * Emits ONE line of JSON. It never claims kernel enforcement by itself:
 * "sandbox_enforced_candidate" must be confirmed by an R-vs-U A/B control
 * (check S5 in docs/App沙盒实现_2026-11-06.md).
 *
 * Build on a macOS runner with the Xcode iOS SDK:
 *   xcrun --sdk iphoneos clang -arch arm64e -fptrauth-calls \
 *     -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
 *     -o vios_sandbox_probe vios_sandbox_probe.c
 * Then ad-hoc sign it and add its cdhash to ramdisk.tc (AMFI / L2).
 *
 * Usage:
 *   vios_sandbox_probe baseline            # control: do NOT apply any sandbox
 *   vios_sandbox_probe container           # try App Store 'container' profile
 *   vios_sandbox_probe pure-computation    # documented fallback profile
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SANDBOX_NAMED       0x0001
#define SANDBOX_FILTER_PATH 1       /* verify against iOS 27 sandbox.h */

typedef int  (*sandbox_init_fn)(const char *, uint64_t, char **);
typedef void (*sandbox_free_error_fn)(char *);
typedef int  (*sandbox_check_fn)(int, const char *, int, ...);

static int can_read(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int can_write(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 0;
    close(fd);
    unlink(path);               /* best effort: keep the ramdisk clean */
    return 1;
}

static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    if (s) {
        for (; *s; ++s) {
            unsigned char c = (unsigned char)*s;
            if (c == '"' || c == '\\') { fputc('\\', f); fputc(c, f); }
            else if (c == '\n') fputs("\\n", f);
            else if (c == '\r') fputs("\\r", f);
            else if (c == '\t') fputs("\\t", f);
            else if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "baseline";
    const int is_baseline = (strcmp(mode, "baseline") == 0);

    void *p_init  = dlsym(RTLD_DEFAULT, "sandbox_init");
    void *p_check = dlsym(RTLD_DEFAULT, "sandbox_check");
    void *p_free  = dlsym(RTLD_DEFAULT, "sandbox_free_error");

    char *err = NULL;
    int init_rc = -99;         /* -99 = not attempted */
    int applied = 0;

    if (!is_baseline && p_init) {
        init_rc = ((sandbox_init_fn)p_init)(mode, SANDBOX_NAMED, &err);
        if (init_rc == 0) applied = 1;
    }

    int check_rc = -99;
    if (p_check) {
        check_rc = ((sandbox_check_fn)p_check)(
            (int)getpid(), "file-read-data", SANDBOX_FILTER_PATH, "/etc/passwd");
    }

    int r_passwd = can_read("/etc/passwd");
    int w_system = can_write("/System/Library/LaunchDaemons/.vios_probe");
    int w_out    = can_write("/vios/out/.vios_probe");

    const int candidate = (!is_baseline && applied && !init_rc &&
                           !r_passwd && !w_system && w_out);

    fputs("{\"ok\":true,\"tool\":\"vios_sandbox_probe\",\"mode\":", stdout);
    json_string(stdout, mode);
    printf(",\"uid\":%d,\"gid\":%d,\"pid\":%d",
           (int)getuid(), (int)getgid(), (int)getpid());
    printf(",\"sandbox_init_symbol\":%d,\"sandbox_check_symbol\":%d",
           p_init != NULL, p_check != NULL);
    fputs(",\"profile_requested\":", stdout);
    json_string(stdout, is_baseline ? "none" : mode);
    printf(",\"init_rc\":%d,\"profile_applied\":%d", init_rc, applied);
    fputs(",\"init_err\":", stdout);
    json_string(stdout, (err && init_rc != 0) ? err : "");
    printf(",\"check_rc\":%d", check_rc);
    printf(",\"read_etc_passwd\":%d,\"write_system\":%d,\"write_vios_out\":%d",
           r_passwd, w_system, w_out);
    printf(",\"sandbox_enforced_candidate\":%s", candidate ? "true" : "false");
    fputs(",\"note\":\"candidate only; final verdict requires R-vs-U A/B control (S5)\"}\n", stdout);

    if (err && p_free) ((sandbox_free_error_fn)p_free)(err);
    return 0;
}
