#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <libuci.h>
#include <pthread.h>
#include <time.h>
#include <json-c/json.h>

#define MODULE_PATH "/sys/module/pkt_frag/parameters"
#define CONFIG_FILE "/etc/config/pkt-frag"
#define STATE_FILE "/var/run/pkt-frag-state.json"

static int running = 1;
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int enabled;
    int frag_size;
    int enable_tcp;
    int enable_udp;
    int enable_tls_frag;
    int enable_quic_frag;
    int enable_padding;
    int padding_min;
    int padding_max;
    int enable_fingerprint;
    int tls_record_size;
    char interface[32];
    char fingerprint_profile[32];
    int rotate_interval;
    time_t last_rotate;
} config_t;

static config_t current_config = {
    .enabled = 1,
    .frag_size = 512,
    .enable_tcp = 1,
    .enable_udp = 1,
    .enable_tls_frag = 1,
    .enable_quic_frag = 1,
    .enable_padding = 1,
    .padding_min = 0,
    .padding_max = 64,
    .enable_fingerprint = 1,
    .tls_record_size = 1400,
    .interface = "wan",
    .fingerprint_profile = "chrome",
    .rotate_interval = 3600,
    .last_rotate = 0
};

const char *fingerprint_profiles[][16] = {
    {"chrome", "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xcca9,0xcca8,0xc013,0xc014", NULL},
    {"firefox", "0x1301,0x1302,0x1303,0x1304,0xc02b,0xc02f,0xcca9,0xcca8,0xc013,0xc014", NULL},
    {"safari", "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8", NULL},
    {"edge", "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xcca9,0xcca8,0xc013,0xc014", NULL},
    {"curl", "0x1301,0x1302,0x1303,0xc02b,0xc02f,0xcca9,0xcca8", NULL},
    {"random", NULL, NULL}
};

void sig_handler(int sig) {
    running = 0;
}

int write_param(const char *name, const char *value) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", MODULE_PATH, name);
    
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    
    int ret = write(fd, value, strlen(value));
    close(fd);
    return ret > 0 ? 0 : -1;
}

int write_param_int(const char *name, int value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", value);
    return write_param(name, buf);
}

void apply_kernel_params(const config_t *cfg) {
    write_param_int("enabled", cfg->enabled);
    write_param_int("frag_size", cfg->frag_size);
    write_param_int("enable_tcp", cfg->enable_tcp);
    write_param_int("enable_udp", cfg->enable_udp);
    write_param_int("enable_tls_frag", cfg->enable_tls_frag);
    write_param_int("enable_quic_frag", cfg->enable_quic_frag);
    write_param_int("enable_padding", cfg->enable_padding);
    write_param_int("padding_min", cfg->padding_min);
    write_param_int("padding_max", cfg->padding_max);
    write_param_int("enable_fingerprint", cfg->enable_fingerprint);
    write_param_int("tls_record_size", cfg->tls_record_size);
    
    syslog(LOG_INFO, "pkt-frag: applied kernel params (frag=%d, tls=%d, quic=%d, pad=%d-%d, fp=%d)",
           cfg->frag_size, cfg->enable_tls_frag, cfg->enable_quic_frag,
           cfg->padding_min, cfg->padding_max, cfg->enable_fingerprint);
}

void save_state(const config_t *cfg) {
    json_object *root = json_object_new_object();
    json_object_object_add(root, "enabled", json_object_new_int(cfg->enabled));
    json_object_object_add(root, "frag_size", json_object_new_int(cfg->frag_size));
    json_object_object_add(root, "enable_tcp", json_object_new_int(cfg->enable_tcp));
    json_object_object_add(root, "enable_udp", json_object_new_int(cfg->enable_udp));
    json_object_object_add(root, "enable_tls_frag", json_object_new_int(cfg->enable_tls_frag));
    json_object_object_add(root, "enable_quic_frag", json_object_new_int(cfg->enable_quic_frag));
    json_object_object_add(root, "enable_padding", json_object_new_int(cfg->enable_padding));
    json_object_object_add(root, "padding_min", json_object_new_int(cfg->padding_min));
    json_object_object_add(root, "padding_max", json_object_new_int(cfg->padding_max));
    json_object_object_add(root, "enable_fingerprint", json_object_new_int(cfg->enable_fingerprint));
    json_object_object_add(root, "tls_record_size", json_object_new_int(cfg->tls_record_size));
    json_object_object_add(root, "interface", json_object_new_string(cfg->interface));
    json_object_object_add(root, "fingerprint_profile", json_object_new_string(cfg->fingerprint_profile));
    json_object_object_add(root, "rotate_interval", json_object_new_int(cfg->rotate_interval));
    json_object_object_add(root, "last_rotate", json_object_new_int64(cfg->last_rotate));
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    FILE *f = fopen(STATE_FILE, "w");
    if (f) {
        fputs(json_str, f);
        fclose(f);
    }
    json_object_put(root);
}

void rotate_fingerprint(config_t *cfg) {
    if (!cfg->enable_fingerprint || cfg->rotate_interval <= 0) return;
    
    time_t now = time(NULL);
    if (now - cfg->last_rotate < cfg->rotate_interval) return;
    
    int count = 0;
    while (fingerprint_profiles[count][0]) count++;
    
    int idx = rand() % count;
    strncpy(cfg->fingerprint_profile, fingerprint_profiles[idx][0], sizeof(cfg->fingerprint_profile) - 1);
    cfg->last_rotate = now;
    
    syslog(LOG_INFO, "pkt-frag: rotated fingerprint to %s", cfg->fingerprint_profile);
    save_state(cfg);
}

int parse_uci_config(config_t *cfg) {
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return -1;
    
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "pkt-frag", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return -1;
    }
    
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, "global") != 0) continue;
        
        const char *val;
        val = uci_lookup_option_string(ctx, s, "enabled");
        if (val) cfg->enabled = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "frag_size");
        if (val) cfg->frag_size = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_tcp");
        if (val) cfg->enable_tcp = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_udp");
        if (val) cfg->enable_udp = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_tls_frag");
        if (val) cfg->enable_tls_frag = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_quic_frag");
        if (val) cfg->enable_quic_frag = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_padding");
        if (val) cfg->enable_padding = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "padding_min");
        if (val) cfg->padding_min = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "padding_max");
        if (val) cfg->padding_max = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "enable_fingerprint");
        if (val) cfg->enable_fingerprint = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "tls_record_size");
        if (val) cfg->tls_record_size = atoi(val);
        
        val = uci_lookup_option_string(ctx, s, "interface");
        if (val) strncpy(cfg->interface, val, sizeof(cfg->interface) - 1);
        
        val = uci_lookup_option_string(ctx, s, "fingerprint_profile");
        if (val) strncpy(cfg->fingerprint_profile, val, sizeof(cfg->fingerprint_profile) - 1);
        
        val = uci_lookup_option_string(ctx, s, "rotate_interval");
        if (val) cfg->rotate_interval = atoi(val);
    }
    
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return 0;
}

void *config_watcher(void *arg) {
    int fd = inotify_init();
    if (fd < 0) return NULL;
    
    int wd = inotify_add_watch(fd, CONFIG_FILE, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
    if (wd < 0) {
        close(fd);
        return NULL;
    }
    
    char buf[4096];
    while (running) {
        int len = read(fd, buf, sizeof(buf));
        if (len > 0) {
            pthread_mutex_lock(&config_mutex);
            config_t new_cfg = current_config;
            if (parse_uci_config(&new_cfg) == 0) {
                apply_kernel_params(&new_cfg);
                current_config = new_cfg;
                save_state(&current_config);
                syslog(LOG_INFO, "pkt-frag: config reloaded");
            }
            pthread_mutex_unlock(&config_mutex);
        }
    }
    
    inotify_rm_watch(fd, wd);
    close(fd);
    return NULL;
}

void *rotation_thread(void *arg) {
    while (running) {
        sleep(60);
        pthread_mutex_lock(&config_mutex);
        rotate_fingerprint(&current_config);
        pthread_mutex_unlock(&config_mutex);
    }
    return NULL;
}

int load_state(config_t *cfg) {
    FILE *f = fopen(STATE_FILE, "r");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = 0;
    fclose(f);
    
    json_object *root = json_tokener_parse(data);
    free(data);
    if (!root) return -1;
    
    json_object *obj;
    if (json_object_object_get_ex(root, "fingerprint_profile", &obj))
        strncpy(cfg->fingerprint_profile, json_object_get_string(obj), sizeof(cfg->fingerprint_profile) - 1);
    if (json_object_object_get_ex(root, "last_rotate", &obj))
        cfg->last_rotate = json_object_get_int64(obj);
    if (json_object_object_get_ex(root, "rotate_interval", &obj))
        cfg->rotate_interval = json_object_get_int(obj);
    
    json_object_put(root);
    return 0;
}

int main(int argc, char *argv[]) {
    openlog("pkt-frag-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    srand(time(NULL));
    
    if (parse_uci_config(&current_config) != 0) {
        syslog(LOG_WARNING, "pkt-frag: using defaults, UCI config not found");
    }
    
    load_state(&current_config);
    apply_kernel_params(&current_config);
    save_state(&current_config);
    
    pthread_t watcher_tid, rotation_tid;
    pthread_create(&watcher_tid, NULL, config_watcher, NULL);
    pthread_create(&rotation_tid, NULL, rotation_thread, NULL);
    
    syslog(LOG_INFO, "pkt-frag-daemon started");
    
    while (running) {
        sleep(10);
    }
    
    pthread_cancel(watcher_tid);
    pthread_cancel(rotation_tid);
    pthread_join(watcher_tid, NULL);
    pthread_join(rotation_tid, NULL);
    
    write_param_int("enabled", 0);
    syslog(LOG_INFO, "pkt-frag-daemon stopped");
    closelog();
    return 0;
}