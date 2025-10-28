#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>

#define BUFFER_SIZE 16384
#define CHOISE_DEFAULT_VPN 1
#define VIEW_CONFIG_PAGED  2 
#define PARSE_AND_CREATE_VILE 4
#define VALIDATE_VPN   3
#define EXIT_OPTION 5

struct MemoryStruct {
    char *memory;
    size_t size;
};

/* Helper: perform TCP connect to host:port with timeout (ms). Returns 0 on success, -1 on failure.
   On success, elapsed_ms is set (if non-NULL). On failure, err_buf (if provided) is filled. */
static int tcp_connect_with_timeout(const char *host, const char *port, int timeout_ms, double *elapsed_ms, char *err_buf, size_t err_buf_size) {
    struct addrinfo hints, *res = NULL, *rp;
    int s = -1;
    int ret = -1;
    struct timeval start, end;

    if (!host || !port) {
        if (err_buf) snprintf(err_buf, err_buf_size, "invalid host/port");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        if (err_buf) snprintf(err_buf, err_buf_size, "DNS resolution failed for %s:%s", host, port);
        return -1;
    }

    gettimeofday(&start, NULL);

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0) continue;

        /* Set non-blocking */
        int flags = fcntl(s, F_GETFL, 0);
        if (flags < 0) flags = 0;
        fcntl(s, F_SETFL, flags | O_NONBLOCK);

        int c = connect(s, rp->ai_addr, rp->ai_addrlen);
        if (c == 0) {
            /* Connected immediately */
            ret = 0;
            close(s);
            break;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sel = select(s + 1, NULL, &wfds, NULL, &tv);
            if (sel > 0 && FD_ISSET(s, &wfds)) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    ret = 0;
                    close(s);
                    break;
                } else {
                    if (err_buf) snprintf(err_buf, err_buf_size, "connect failed: %s", strerror(so_error));
                    close(s);
                    s = -1;
                    continue;
                }
            } else {
                if (err_buf) snprintf(err_buf, err_buf_size, "connect timeout");
                close(s);
                s = -1;
                continue;
            }
        } else {
            /* immediate error */
            if (err_buf) snprintf(err_buf, err_buf_size, "connect error: %s", strerror(errno));
            close(s);
            s = -1;
            continue;
        }
    }

    gettimeofday(&end, NULL);
    if (elapsed_ms) {
        *elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    }

    freeaddrinfo(res);
    return ret;
}

/* Check if an IPv4 address is private/reserved */
static int is_private_ipv4(const char *ipstr) {
    if (!ipstr) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, ipstr, &a) != 1) return 0;
    uint32_t ip = ntohl(a.s_addr);
    if ((ip & 0xFF000000) == 0x0A000000) return 1;       // 10.0.0.0/8
    if ((ip & 0xFFF00000) == 0xAC100000) return 1;      // 172.16.0.0/12
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 1;      // 192.168.0.0/16
    if ((ip & 0xFF000000) == 0x7F000000) return 1;      // 127.0.0.0/8 loopback
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return 1;      // 169.254.0.0/16 link-local
    if ((ip & 0xFFC00000) == 0x64400000) return 1;      // 100.64.0.0/10 carrier-grade NAT
    return 0;
}

/* Simple Redis RESP SADD using plain TCP (no hiredis dependency) */
static int redis_sadd(const char *host, const char *port, const char *key, const char *member, int timeout_ms) {
    if (!host || !port || !key || !member) return -1;
    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd), "*3\r\n$4\r\nSADD\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n",
                     strlen(key), key, strlen(member), member);
    if (n < 0 || n >= (int)sizeof(cmd)) return -1;

    struct addrinfo hints, *res = NULL, *rp;
    int s = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0) continue;
        /* set send/recv timeout */
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) return -1;

    ssize_t w = write(s, cmd, strlen(cmd));
    if (w <= 0) { close(s); return -1; }
    char rbuf[512];
    ssize_t r = read(s, rbuf, sizeof(rbuf)-1);
    if (r > 0) rbuf[r] = '\0';
    close(s);
    if (r > 0 && (rbuf[0] == ':' || rbuf[0] == '+')) return 0;
    return -1;
}

int download_url_to_file(const char *url, const char *output_file) {
    CURL *curl_handle;
    FILE *fp;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if(curl_handle) {
        fp = fopen(output_file, "wb");
        if(!fp) {
            fprintf(stderr, "Error opening file %s for writing\n", output_file);
            curl_easy_cleanup(curl_handle);
            return -1;
        }

        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);

        res = curl_easy_perform(curl_handle);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fclose(fp);
            curl_easy_cleanup(curl_handle);
            return -1;
        }

        fclose(fp);
        curl_easy_cleanup(curl_handle);
    }
    curl_global_cleanup();
    return 0;
}

int is_valid_url(const char *url){
    if (!url) return 0;
    return (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0);
}

/* Use a local CURL handle to safely unescape URL-encoded strings. Returns malloc'd string or NULL. */
static char *safe_unescape(const char *str) {
    if (!str) return NULL;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    int outlen = 0;
    char *res = curl_easy_unescape(curl, str, 0, &outlen);
    curl_easy_cleanup(curl);
    return res; /* caller must free with curl_free() */
}

/* Simple base64 decoder. Returns malloc'd buffer (null-terminated) or NULL on error. Caller must free(). */
static int _b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2; /* padding */
    return -1; /* invalid */
}

static unsigned char *base64_decode(const char *data, size_t input_length, size_t *out_len) {
    if (!data) return NULL;
    if (input_length % 4 == 1) return NULL;

    size_t output_length = input_length / 4 * 3;
    if (input_length >= 1 && data[input_length - 1] == '=') output_length--;
    if (input_length >= 2 && data[input_length - 2] == '=') output_length--;

    unsigned char *decoded_data = malloc(output_length + 1);
    if (!decoded_data) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        int vals[4];
        for (int k = 0; k < 4; k++) {
            vals[k] = _b64val(data[i++]);
        }
        if (vals[0] < 0 || vals[1] < 0) { free(decoded_data); return NULL; }

        unsigned int byte1 = (vals[0] << 2) | ((vals[1] & 0x30) >> 4);
        decoded_data[j++] = (unsigned char)(byte1 & 0xFF);

        if (vals[2] == -2) break; /* padding, only one byte */
        if (vals[2] < 0) { free(decoded_data); return NULL; }

        unsigned int byte2 = ((vals[1] & 0x0F) << 4) | ((vals[2] & 0x3C) >> 2);
        if (j < output_length) decoded_data[j++] = (unsigned char)(byte2 & 0xFF);

        if (vals[3] == -2) break; /* padding, two bytes */
        if (vals[3] < 0) { free(decoded_data); return NULL; }

        unsigned int byte3 = ((vals[2] & 0x03) << 6) | (vals[3] & 0x3F);
        if (j < output_length) decoded_data[j++] = (unsigned char)(byte3 & 0xFF);
    }

    decoded_data[output_length] = '\0';
    if (out_len) *out_len = output_length;
    return decoded_data;
}

void download_vpn_list(const char *url, const char *output_file) {
    if (!url || !output_file) {
        fprintf(stderr, "Invalid arguments to download_vpn_list\n");
        exit(EXIT_FAILURE);
    }
    if (!is_valid_url(url)) {
        fprintf(stderr, "Refusing to download: invalid URL '%s'\n", url);
        exit(EXIT_FAILURE);
    }
    if (download_url_to_file(url, output_file) != 0) {
        fprintf(stderr, "Error downloading VPN list from %s\n", url);
        exit(EXIT_FAILURE);
    }
}

void display_configs_paged(cJSON *configs, int per_page) {
    int total = cJSON_GetArraySize(configs);
    for (int i = 0; i < total; i += per_page) {
        for (int j = i; j < i + per_page && j < total; j++) {
            cJSON *config = cJSON_GetArrayItem(configs, j);
            char *config_str = cJSON_Print(config);
            printf("%s\n", config_str);
            free(config_str);
        }
        if (i + per_page < total) {
            printf("Press Enter to continue...\n");
            getchar();
        }
    }
}

void parse_vpn_to_json(const char *input_file, const char *output_json) {
    FILE *in = fopen(input_file, "r");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *configs = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "configs", configs);

    char line[BUFFER_SIZE];
    int count = 0;

    while (fgets(line, sizeof(line), in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        cJSON *item = cJSON_CreateObject();
        char remark[256] = {0};

        // Extract name (after #)
        const char *hash = strrchr(line, '#');
        if (hash) {
            strncpy(remark, hash + 1, sizeof(remark) - 1);
            remark[sizeof(remark) - 1] = '\0';
            /* Safely unescape URL-encoded names if possible */
            char *unescaped = safe_unescape(remark);
            if (unescaped) {
                /* safe_unescape returns malloc'd pointer allocated by libcurl; use strncpy then free via curl_free */
                strncpy(remark, unescaped, sizeof(remark) - 1);
                remark[sizeof(remark) - 1] = '\0';
                curl_free(unescaped);
            }
        }

        if (strncmp(line, "ss://", 5) == 0) {
            cJSON_AddStringToObject(item, "type", "ss");
            if (remark[0]) cJSON_AddStringToObject(item, "name", remark);

            // Декодируем base64-like часть
            char *decoded = safe_unescape(line + 5);
            if (decoded) {
                char *at = strchr(decoded, '@');
                if (at) {
                    *at = '\0';
                    char *host_port = at + 1;
                    char *colon = strrchr(host_port, ':');
                    if (colon) {
                        *colon = '\0';
                        cJSON_AddStringToObject(item, "server", host_port);
                        cJSON_AddNumberToObject(item, "port", atoi(colon + 1));
                    }
                    char *sep = strchr(decoded, ':');
                    if (sep) {
                        *sep = '\0';
                        cJSON_AddStringToObject(item, "method", decoded);
                        cJSON_AddStringToObject(item, "password", sep + 1);
                    }
                }
                curl_free(decoded);
            } else {
                cJSON_AddStringToObject(item, "raw", line);
            }

        } else if (strncmp(line, "trojan://", 9) == 0) {
            cJSON_AddStringToObject(item, "type", "trojan");
            if (remark[0]) cJSON_AddStringToObject(item, "name", remark);

            char *at = strchr(line + 9, '@');
            if (at) {
                *at = '\0';
                char *host_port = at + 1;
                char *colon = strrchr(host_port, ':');
                if (colon) {
                    *colon = '\0';
                    cJSON_AddStringToObject(item, "server", host_port);
                    cJSON_AddNumberToObject(item, "port", atoi(colon + 1));
                }
                cJSON_AddStringToObject(item, "password", line + 9);
            } else {
                cJSON_AddStringToObject(item, "raw", line);
            }

        } else if (strncmp(line, "vmess://", 8) == 0) {
            cJSON_AddStringToObject(item, "type", "vmess");
            if (remark[0]) cJSON_AddStringToObject(item, "name", remark);

            // Base64-decode the vmess payload (URL-safe base64 variants supported)
            size_t in_len = strlen(line + 8);
            char *b64_str = malloc(in_len + 1);
            if (b64_str) memcpy(b64_str, line + 8, in_len + 1);
            if (b64_str) {
                for (char *p = b64_str; *p; p++) {
                    if (*p == '-') *p = '+';
                    if (*p == '_') *p = '/';
                }
                size_t out_len = 0;
                unsigned char *decoded_str = base64_decode(b64_str, strlen(b64_str), &out_len);
                if (decoded_str) {
                    cJSON *vmess_json = cJSON_Parse((char *)decoded_str);
                    if (vmess_json && cJSON_IsObject(vmess_json)) {
                        const char *fields[] = {"add", "host", "id", "aid", "net", "path", "port", "ps", "tls", "sni", NULL};
                        for (int i = 0; fields[i]; i++) {
                            cJSON *f = cJSON_GetObjectItemCaseSensitive(vmess_json, fields[i]);
                            if (f && (cJSON_IsString(f) || cJSON_IsNumber(f))) {
                                cJSON_AddItemReferenceToObject(item, fields[i], f);
                            }
                        }
                        if (!remark[0]) {
                            cJSON *ps = cJSON_GetObjectItemCaseSensitive(vmess_json, "ps");
                            if (ps && cJSON_IsString(ps)) {
                                cJSON_AddStringToObject(item, "name", ps->valuestring);
                            }
                        }
                        cJSON_Delete(vmess_json);
                    } else {
                        cJSON_AddStringToObject(item, "raw", line);
                    }
                    free(decoded_str);
                } else {
                    cJSON_AddStringToObject(item, "raw", line);
                }
                free(b64_str);
            } else {
                cJSON_AddStringToObject(item, "raw", line);
            }

        } else {
            cJSON_AddStringToObject(item, "type", "unknown");
            cJSON_AddStringToObject(item, "raw", line);
        }

        cJSON_AddItemToArray(configs, item);
        count++;
    }

    fclose(in);

    // Генерируем КРАСИВЫЙ JSON с отступами
    char *json_str = cJSON_Print(root);
    if (!json_str) {
        fprintf(stderr, "Failed to generate JSON output\n");
        cJSON_Delete(root);
        exit(EXIT_FAILURE);
    }

    FILE *out = fopen(output_json, "w");
    if (!out) {
        perror("Error opening output JSON file");
        free(json_str);
        cJSON_Delete(root);
        exit(EXIT_FAILURE);
    }
    fputs(json_str, out);
    fclose(out);
    free(json_str);
    cJSON_Delete(root);

    printf("✅ Parsed %d VPN configurations to %s\n", count, output_json);
}

// Возвращает количество валидных конфигураций
int check_validate_vpn(const char *json_file, const char *report_file) {
    FILE *fp = fopen(json_file, "r");
    if (!fp) {
        fprintf(stderr, "❌ Cannot open %s for validation\n", json_file);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_data = malloc(fsize + 1);
    if (!json_data) {
        fclose(fp);
        return -1;
    }

    fread(json_data, 1, fsize, fp);
    json_data[fsize] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_data);
    free(json_data);
    if (!root) {
        fprintf(stderr, "❌ Failed to parse %s: %s\n", json_file, cJSON_GetErrorPtr());
        return -1;
    }

    cJSON *configs = cJSON_GetObjectItemCaseSensitive(root, "configs");
    if (!configs || !cJSON_IsArray(configs)) {
        fprintf(stderr, "❌ Invalid structure in %s\n", json_file);
        cJSON_Delete(root);
        return -1;
    }

    int total = cJSON_GetArraySize(configs);
    int valid_count = 0;
    cJSON *validated_list = cJSON_CreateArray();

    

    for (int i = 0; i < total; i++) {
        cJSON *item = cJSON_GetArrayItem(configs, i);
        if (!item || !cJSON_IsObject(item)) continue;

        cJSON *type_obj = cJSON_GetObjectItemCaseSensitive(item, "type");
        if (!type_obj || !cJSON_IsString(type_obj)) continue;

        const char *type = type_obj->valuestring;
        int is_valid = 0;

        if (strcmp(type, "ss") == 0) {
            // Требуемые поля: server, port, method, password
            is_valid = (cJSON_GetObjectItemCaseSensitive(item, "server") &&
                        cJSON_GetObjectItemCaseSensitive(item, "port") &&
                        cJSON_GetObjectItemCaseSensitive(item, "method") &&
                        cJSON_GetObjectItemCaseSensitive(item, "password"));
        }
        else if (strcmp(type, "trojan") == 0) {
            // Требуемые: server, port, password
            is_valid = (cJSON_GetObjectItemCaseSensitive(item, "server") &&
                        cJSON_GetObjectItemCaseSensitive(item, "port") &&
                        cJSON_GetObjectItemCaseSensitive(item, "password"));
        }
        else if (strcmp(type, "vmess") == 0) {
            // Требуемые: add (server), port, id
            is_valid = (cJSON_GetObjectItemCaseSensitive(item, "add") &&
                        cJSON_GetObjectItemCaseSensitive(item, "port") &&
                        cJSON_GetObjectItemCaseSensitive(item, "id"));
        }
        else {
            // unknown — считаем невалидным
            is_valid = 0;
        }

        if (is_valid) valid_count++;

        /* Enrich validation with network checks */
        cJSON *copy = cJSON_Duplicate(item, 1);
        cJSON_AddBoolToObject(copy, "valid", is_valid);

        if (is_valid) {
            char server_buf[256] = {0};
            char port_buf[32] = {0};
            /* Extract server and port depending on type */
            if (strcmp(type, "ss") == 0) {
                cJSON *s = cJSON_GetObjectItemCaseSensitive(item, "server");
                cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "port");
                if (s && cJSON_IsString(s)) strncpy(server_buf, s->valuestring, sizeof(server_buf)-1);
                if (p) {
                    if (cJSON_IsNumber(p)) snprintf(port_buf, sizeof(port_buf), "%d", p->valueint);
                    else if (cJSON_IsString(p)) strncpy(port_buf, p->valuestring, sizeof(port_buf)-1);
                }
            } else if (strcmp(type, "trojan") == 0) {
                cJSON *s = cJSON_GetObjectItemCaseSensitive(item, "server");
                cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "port");
                if (s && cJSON_IsString(s)) strncpy(server_buf, s->valuestring, sizeof(server_buf)-1);
                if (p) {
                    if (cJSON_IsNumber(p)) snprintf(port_buf, sizeof(port_buf), "%d", p->valueint);
                    else if (cJSON_IsString(p)) strncpy(port_buf, p->valuestring, sizeof(port_buf)-1);
                }
            } else if (strcmp(type, "vmess") == 0) {
                cJSON *s = cJSON_GetObjectItemCaseSensitive(item, "add");
                if (!s) s = cJSON_GetObjectItemCaseSensitive(item, "host");
                cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "port");
                if (s && cJSON_IsString(s)) strncpy(server_buf, s->valuestring, sizeof(server_buf)-1);
                if (p) {
                    if (cJSON_IsNumber(p)) snprintf(port_buf, sizeof(port_buf), "%d", p->valueint);
                    else if (cJSON_IsString(p)) strncpy(port_buf, p->valuestring, sizeof(port_buf)-1);
                }
            }

            double latency = -1.0;
            char net_err[128] = {0};
            int reach = -1;
            if (server_buf[0] && port_buf[0]) {
                reach = tcp_connect_with_timeout(server_buf, port_buf, 3000, &latency, net_err, sizeof(net_err));
            } else {
                snprintf(net_err, sizeof(net_err), "missing host or port");
            }

            cJSON_AddBoolToObject(copy, "reachable", (reach == 0) ? 1 : 0);
            if (reach == 0) cJSON_AddNumberToObject(copy, "latency_ms", latency);
            else cJSON_AddNumberToObject(copy, "latency_ms", -1);
            if (net_err[0]) cJSON_AddStringToObject(copy, "network_error", net_err);
        }

        cJSON_AddItemToArray(validated_list, copy);
    }

    // Сохраняем расширенный отчёт (опционально)
    if (report_file) {
        cJSON *report_root = cJSON_CreateObject();
        cJSON_AddItemToObject(report_root, "validated_configs", validated_list);
        cJSON_AddNumberToObject(report_root, "total", total);
        cJSON_AddNumberToObject(report_root, "valid", valid_count);
        cJSON_AddNumberToObject(report_root, "invalid", total - valid_count);

        /* Write pretty JSON report */
        char *output_str = cJSON_Print(report_root);
        if (output_str) {
            FILE *out = fopen(report_file, "w");
            if (out) {
                fputs(output_str, out);
                fclose(out);
                printf("Wrote JSON report to %s\n", report_file);
            } else {
                fprintf(stderr, "Failed to open %s for writing: %s\n", report_file, strerror(errno));
            }
            free(output_str);
        }

        /* Also write a simple YAML report alongside JSON */
        size_t yaml_path_len = strlen(report_file) + 8;
        char *yaml_path = malloc(yaml_path_len);
        if (yaml_path) {
            snprintf(yaml_path, yaml_path_len, "%s.yaml", report_file);
            FILE *yout = fopen(yaml_path, "w");
            if (yout) {
                fprintf(yout, "total: %d\nvalid: %d\ninvalid: %d\nvalidated_configs:\n", total, valid_count, total - valid_count);
                int n = cJSON_GetArraySize(validated_list);
                for (int k = 0; k < n; k++) {
                    cJSON *e = cJSON_GetArrayItem(validated_list, k);
                    if (!e) continue;
                    cJSON *name = cJSON_GetObjectItemCaseSensitive(e, "name");
                    cJSON *type = cJSON_GetObjectItemCaseSensitive(e, "type");
                    cJSON *server = cJSON_GetObjectItemCaseSensitive(e, "server");
                    cJSON *port = cJSON_GetObjectItemCaseSensitive(e, "port");
                    cJSON *valid = cJSON_GetObjectItemCaseSensitive(e, "valid");
                    cJSON *reachable = cJSON_GetObjectItemCaseSensitive(e, "reachable");
                    cJSON *lat = cJSON_GetObjectItemCaseSensitive(e, "latency_ms");
                    cJSON *nerr = cJSON_GetObjectItemCaseSensitive(e, "network_error");

                    fprintf(yout, "  - name: '%s'\n", name && cJSON_IsString(name) ? name->valuestring : "");
                    fprintf(yout, "    type: '%s'\n", type && cJSON_IsString(type) ? type->valuestring : "");
                    fprintf(yout, "    server: '%s'\n", server && cJSON_IsString(server) ? server->valuestring : "");
                    if (port) {
                        if (cJSON_IsNumber(port)) fprintf(yout, "    port: %d\n", port->valueint);
                        else if (cJSON_IsString(port)) fprintf(yout, "    port: '%s'\n", port->valuestring);
                    } else fprintf(yout, "    port: ''\n");
                    fprintf(yout, "    valid: %s\n", (valid && cJSON_IsBool(valid) && cJSON_IsTrue(valid)) ? "true" : "false");
                    fprintf(yout, "    reachable: %s\n", (reachable && cJSON_IsBool(reachable) && cJSON_IsTrue(reachable)) ? "true" : "false");
                    if (lat && cJSON_IsNumber(lat)) fprintf(yout, "    latency_ms: %.2f\n", lat->valuedouble);
                    if (nerr && cJSON_IsString(nerr)) fprintf(yout, "    network_error: '%s'\n", nerr->valuestring);
                    fprintf(yout, "\n");
                }
                fclose(yout);
                printf("Wrote YAML report to %s\n", yaml_path);
            } else {
                fprintf(stderr, "Failed to open %s for YAML writing: %s\n", yaml_path, strerror(errno));
            }
            free(yaml_path);
        }

        cJSON_Delete(report_root);
    } else {
        cJSON_Delete(validated_list); // освобождаем, если не сохраняем
    }

    cJSON_Delete(root);
    return valid_count;
}


int main() {
    const char *default_url = 
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt";

    const char *temp_file = "vpn_raw.txt";
    /* make output_json a modifiable buffer so we can overwrite it with user input */
    char output_json[256] = "vpn_configs.json";

    char url[512];

    printf("Enter options 1 or 2:\n");
    printf("1. Use default VPN list URL\n");
    printf("2. Enter custom VPN list URL\n");
    printf("3. Generate VPN report from JSON\n");
    printf("4. Parse VPN list from URL and create JSON file\n");
    printf("5. Exit\n"); 
    int choice;
    printf("> ");
    scanf("%d", &choice);
    getchar(); // consume newline

    bool exit_flag = false;

    while(!exit_flag) {

        switch(choice) {
            case CHOISE_DEFAULT_VPN:
                printf("Enter VPN subscription URL (or press Enter to use default or Exit(3)): ");
                if (!fgets(url, sizeof(url), stdin)) {
                    fprintf(stderr, "Error reading input\n");
                    return EXIT_FAILURE;
                }

                url[strcspn(url, "\r\n")] = 0; // Remove newline characters
                if(strlen(url) == 0) {
                    strncpy(url, default_url, sizeof(url));
                }

                printf("Downloading VPN list from: %s\n", url);
                download_vpn_list(url, temp_file);

                printf("Parsing VPN configurations to JSON...\n");
                parse_vpn_to_json(temp_file, output_json);

                printf("VPN configurations saved to %s\n", output_json);
                
                exit_flag = true;
                break;
            case VIEW_CONFIG_PAGED:
                {
                    FILE *fp = fopen(output_json, "r");
                    if (!fp) {
                        perror("Error opening JSON file");
                        return EXIT_FAILURE;
                    }

                    fseek(fp, 0, SEEK_END);
                    long fsize = ftell(fp);
                    fseek(fp, 0, SEEK_SET);

                    char *json_data = malloc(fsize + 1);
                    fread(json_data, 1, fsize, fp);
                    json_data[fsize] = 0;
                    fclose(fp);

                    cJSON *json = cJSON_Parse(json_data);
                    free(json_data);
                    if (!json) {
                        fprintf(stderr, "Error parsing JSON data\n");
                        return EXIT_FAILURE;
                    }

                    cJSON *configs = cJSON_GetObjectItemCaseSensitive(json, "configs");
                    if (!cJSON_IsArray(configs)) {
                        fprintf(stderr, "Invalid JSON format: 'configs' is not an array\n");
                        cJSON_Delete(json);
                        return EXIT_FAILURE;
                    }

                    display_configs_paged(configs, 5); // Display 5 configs per page

                    cJSON_Delete(json);
                }
                break;
            case PARSE_AND_CREATE_VILE:
                printf("Enter VPN subscription URL (or press Enter to use default or Exit(3)): ");
                if (!fgets(url, sizeof(url), stdin)) {
                    fprintf(stderr, "Error reading input\n");
                    return EXIT_FAILURE;
                }

                printf("Enter name and extension of output file (default: vpn_configs.json): ");
                char output_file_input[256];
                if (!fgets(output_file_input, sizeof(output_file_input), stdin)) {
                    fprintf(stderr, "Error reading input\n");
                    return EXIT_FAILURE;
                }
                output_file_input[strcspn(output_file_input, "\r\n")] = 0; // Remove newline characters
                if(strlen(output_file_input) > 0) {
                    strncpy(output_json, output_file_input, sizeof(output_json)-1);
                    output_json[sizeof(output_json)-1] = '\0';
                }


                url[strcspn(url, "\r\n")] = 0; // Remove newline characters
                if(strlen(url) == 0) {
                    strncpy(url, default_url, sizeof(url));
                }

                printf("Downloading VPN list from: %s\n", url);
                download_vpn_list(url, temp_file);

                printf("Parsing VPN configurations to JSON...\n");
                parse_vpn_to_json(temp_file, output_json);

                printf("VPN configurations saved to %s\n", output_json);
                
                exit_flag = true;
                break;

            case VALIDATE_VPN:
                printf("validating VPN configurations in %s...\n", output_json);
                int valid_count = check_validate_vpn(output_json, "vpn_validation_report.json");
                if (valid_count >= 0) {
                    printf("Validation complete. Valid configurations: %d\n", valid_count);
                } else {
                    printf("Validation failed.\n");
                }
                break;
            case EXIT_OPTION:
                printf("Exiting program.\n");
                /* End program immediately */
                return 0;
            default:
                printf("Invalid choice. Please enter 1 or 2.\n");
        }     

    }
    return 0;
}