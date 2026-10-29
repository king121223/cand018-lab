// multi_probe.m — validates ALL remaining open daemon candidates end-to-end
// on a disposable GitHub Actions macOS runner.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sandbox.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <sys/sysctl.h>

static FILE *outf;
static char g_errmsg[512];
static int g_status;

static void p(const char *fmt, ...) {
    va_list args; va_start(args, fmt);
    vprintf(fmt, args); printf("\n");
    if (outf) { vfprintf(outf, fmt, args); fprintf(outf, "\n"); fflush(outf); }
    va_end(args);
}
static void pid_check(const char *daemon) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s | head -1", daemon);
    FILE *pf = popen(cmd, "r");
    char buf[16] = {0};
    if (fgets(buf, sizeof(buf), pf)) p("  [pid] %s = %s", daemon, buf);
    pclose(pf);
}

@protocol GenericDaemon
- (void)ping;
@end

// MARK: Generic NSXPC connection probe
static void probe_nsxpc_service(const char *name, const char *label) {
    p("\n=== NSXPC probe: %s (%s) ===", name, label);
    pid_check(name);
    memset(g_errmsg, 0, sizeof(g_errmsg)); g_status = 0;

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@(name) options:0];
    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(GenericDaemon)];
    conn.remoteObjectInterface = iface;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);

    conn.interruptionHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "interrupted");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    conn.invalidationHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "invalidated");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    [conn resume];
    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        snprintf(g_errmsg, sizeof(g_errmsg), "error %ld: %s",
            (long)err.code, err.localizedDescription.UTF8String ?: "?");
        g_status = 2; dispatch_semaphore_signal(done);
    }];
    [proxy ping];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
    p("  RESULT: %s", g_status == 0 ? "no reply (silent drop)" : g_errmsg);
    [conn invalidate];
    pid_check(name);
}

// MARK: modelmanagerd
static void probe_modelmanagerd(void) {
    p("\n=== modelmanagerd (com.apple.modelmanager) ===");
    pid_check("modelmanagerd");
    memset(g_errmsg, 0, sizeof(g_errmsg)); g_status = 0;

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.modelmanager" options:0];
    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(GenericDaemon)];
    conn.remoteObjectInterface = iface;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    conn.interruptionHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "interrupted");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    conn.invalidationHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "invalidated");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    [conn resume];
    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        snprintf(g_errmsg, sizeof(g_errmsg), "error %ld: %s",
            (long)err.code, err.localizedDescription.UTF8String ?: "?");
        g_status = 2; dispatch_semaphore_signal(done);
    }];
    [proxy ping];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
    p("  RESULT: %s", g_status == 0 ? "no reply (silent)" : g_errmsg);
    [conn invalidate];
    pid_check("modelmanagerd");
}

// MARK: gamepolicyd
static void probe_gamepolicyd(void) {
    p("\n=== gamepolicyd (com.apple.gamepolicyd.app) ===");
    pid_check("gamepolicyd");
    memset(g_errmsg, 0, sizeof(g_errmsg)); g_status = 0;
    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.gamepolicyd.app" options:0];
    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(GenericDaemon)];
    conn.remoteObjectInterface = iface;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    conn.interruptionHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "interrupted");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    conn.invalidationHandler = ^(void){
        snprintf(g_errmsg, sizeof(g_errmsg), "invalidated");
        g_status = 2; dispatch_semaphore_signal(done);
    };
    [conn resume];
    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        snprintf(g_errmsg, sizeof(g_errmsg), "error %ld: %s",
            (long)err.code, err.localizedDescription.UTF8String ?: "?");
        g_status = 2; dispatch_semaphore_signal(done);
    }];
    [proxy ping];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
    p("  RESULT: %s", g_status == 0 ? "no reply (silent)" : g_errmsg);
    [conn invalidate];
    pid_check("gamepolicyd");
}

// MARK: mediaremoted
static void probe_mediaremoted(void) {
    p("\n=== mediaremoted (com.apple.mediaremoted.xpc) ===");
    pid_check("mediaremoted");
    void *mr = dlopen("/System/Library/PrivateFrameworks/MediaRemote.framework/Versions/A/MediaRemote", RTLD_NOW|RTLD_LOCAL);
    if (!mr) { p("  dlopen failed: %s", dlerror()); return; }
    p("  MediaRemote loaded");

    // Read: designed read
    void (*getNowPlayingInfo)(dispatch_queue_t, void (^)(NSDictionary *)) = dlsym(mr, "MRMediaRemoteGetNowPlayingInfo");
    if (getNowPlayingInfo) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_queue_t q = dispatch_queue_create("mr-r", NULL);
        __block NSDictionary *info = nil;
        getNowPlayingInfo(q, ^(NSDictionary *i) { info = i; dispatch_semaphore_signal(sem); });
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
        if (info) p("  READ: now-playing info (%lu keys) — designed", (unsigned long)info.count);
        else p("  READ: nothing playing");
    }

    // Identity test: foreign app name in Now Playing
    void (*setNowPlayingInfo)(NSDictionary *, dispatch_queue_t, void (^)(NSError *)) = dlsym(mr, "MRMediaRemoteSetNowPlayingInfo");
    if (setNowPlayingInfo) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSDictionary *fake = @{
            @"kMRMediaRemoteNowPlayingInfoAppName": @"PWNED-APP",
            @"kMRMediaRemoteNowPlayingInfoTitle": @"CAND-009-PROBE"
        };
        dispatch_queue_t q = dispatch_queue_create("mr-s", NULL);
        __block NSError *e2 = nil;
        setNowPlayingInfo(fake, q, ^(NSError *e) { e2 = e; dispatch_semaphore_signal(sem); });
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
        if (e2) p("  IDENTITY: set DENIED: %s", e2.localizedDescription.UTF8String ?: "?");
        else p("  !! IDENTITY: foreign app name ACCEPTED — now-playing spoofing");
    }

    // Command: play (designed control)
    void (*sendCmd)(int, NSDictionary *, dispatch_queue_t, void (^)(NSError *)) = dlsym(mr, "MRMediaRemoteSendCommand");
    if (sendCmd) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_queue_t q = dispatch_queue_create("mr-c", NULL);
        __block NSError *e3 = nil;
        sendCmd(1, @{}, q, ^(NSError *e) { e3 = e; dispatch_semaphore_signal(sem); });
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC));
        if (e3) p("  COMMAND: play DENIED: %s", e3.localizedDescription.UTF8String ?: "?");
        else p("  COMMAND: play accepted (designed)");
    }
    dlclose(mr);
    pid_check("mediaremoted");
}

// MARK: main
int main(int argc, char **argv) {
    @autoreleasepool {
        const char *outfile = argc > 1 ? argv[1] : "/dev/stdout";
        outf = fopen(outfile, "w");
        if (outf) setvbuf(outf, NULL, _IONBF, 0);

        p("=== multi-candidate daemon validation ===");
        char buf[256] = {0}; size_t sz = sizeof(buf);
        sysctlbyname("kern.version", buf, &sz, NULL, 0);
        p("  kernel: %s", buf);

        probe_modelmanagerd();
        probe_gamepolicyd();
        probe_mediaremoted();
        probe_nsxpc_service("com.apple.timesync.expositor", "clocksyncd");
        probe_nsxpc_service("com.apple.spindump", "spindump");
        probe_nsxpc_service("com.apple.tailspind", "tailspind");
        probe_nsxpc_service("com.apple.secinitd.fileoperations", "secinitd");

        p("\n=== all probes complete ===");
        if (outf && outf != stdout) fclose(outf);
    }
    return 0;
}
