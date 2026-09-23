use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};


fn anal(dir_path: &str){
    // 1. opendir / perror equivalent
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("opendir: {}", err);
            return;
        }
    };

    // 2. readdir loop equivalent
    for entry in entries {
        // Skip entry if it encountered an I/O error during iteration
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // 3. d_type != DT_DIR equivalent
        // (Note: Rust automatically filters out "." and "..")
        if let Ok(file_type) = entry.file_type() {
            if !file_type.is_dir() {
                continue;
            }
        } else {
            continue;
        }

        // Process your directory entry here
        println!("Found directory: {:?}", entry.path());
        let subzy_path = format!("{}/subzy.txt", entry.path());
        let subjack_path = format!("{}/subjack.txt", entry.path());
        let nuclei_path = format!("{}/nuclei.txt", entry.path());
        let xss_path = format!("{}/xss.txt", entry.path());
        let wpscan_path = format!("{}/wpscan.txt", entry.path());
        let vuln_path = format!("{}/vuln.txt", entry.path());

        // custom xss
        


        let mut file = File::open(subzy_path)?;
        let subzy_file = BufReader::new(file);

        for line in subzy_file.lines() {
            println!("{}", line?);

            if line.contains("VULNERABLE") || line.contains("TAKEOVER"){

                println!("[TAKEOVER] {}", line);

            }

        }

        file = File::open(subjack_path)?;
        let subjack_file = BufReader::new(file);

        for line in subjack_file.lines() {
            println!("{}", line?);

            if line.contains("VULNERABLE") || line.contains("TAKEOVER"){

                println!("[TAKEOVER] {}", line);

            }

        }

        file = File::open(nuclei_path)?;
        let nuclei_file = BufReader::new(file);

        for line in nuclei_file.lines() {
            println!("{}", line?);

            if line.contains("[critical]") || 
                line.contains("[high]") || 
                line.contains("[medium]") ||
                line.contains("[low]") {

                println!("[NUCLEI] {}", line);

            }

        }

        file = File::open(xss_path)?;
        let xss_file = BufReader::new(file);

        for line in xss_file.lines() {
            println!("{}", line?);

            if line.len() > 5 {

                println!("[XSS] {}", line);

            }

        }

        file = File::open(wpscan_path)?;
        let wpscan_file = BufReader::new(file);

        for line in wpscan_file.lines() {
            println!("{}", line?);

            if (line.contains("[!]") ||
                line.contains("Vulnerable") ||
                line.contains("Confirmed"))
            {
                println!("[WPSCAN] {}", line);
            }

        }
        // CUSTOM XSS
        file = File::open()


    }
}

fn anal{
    
}
fn main() -> io::Result<()> {
    let file = File::open("example.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        println!("{}", line?);
    }
    fs::write("output.txt", "Hello, Rust file I/O!")?;

    let mut file = File::create("output.txt")?;
    file.write_all(b"Hello as bytes!\n")?;

    process_directorie("../");
    Ok(())
    
}

/*void analyze(){
    printf("[+] Analyzing scan results...\n");

    DIR *dir = opendir(g.dir);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL){
        if (entry->d_type != DT_DIR)
            continue;
        if (!strcmp(entry->d_name, "."))
            continue;
        if (!strcmp(entry->d_name, ".."))
            continue;

        char subzy[2048];
        char subjack[2048];
        char nuclei[2048];
        char xss[2048];
        char wpscan[2048];
        char vuln[2048];

        snprintf(subzy, sizeof(subzy), "%s/%s/subzy.txt", g.dir, entry->d_name);
        snprintf(subjack, sizeof(subjack), "%s/%s/subjack.txt", g.dir, entry->d_name);

        snprintf(nuclei, sizeof(nuclei), "%s/%s/nuclei.txt", g.dir, entry->d_name);
        snprintf(xss, sizeof(xss), "%s/%s/xss.txt", g.dir, entry->d_name);
        snprintf(wpscan, sizeof(wpscan), "%s/%s/wpscan.txt", g.dir, entry->d_name);
        snprintf(vuln, sizeof(vuln), "%s/%s/vuln.txt", g.dir, entry->d_name);

        FILE *out = fopen(vuln, "w");
        if (!out)
            continue;

        int findings = 0;
        char line[4096];

        FILE *fp = fopen(nuclei, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "[critical]") ||
                    strstr(line, "[high]") ||
                    strstr(line, "[medium]") ||
                    strstr(line, "[low]"))
                {
                    fprintf(out, "[NUCLEI] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(xss, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strlen(line) > 5)
                {
                    fprintf(out, "[XSS] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(wpscan, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "[!]") ||
                    strstr(line, "Vulnerable") ||
                    strstr(line, "Confirmed"))
                {
                    fprintf(out, "[WPSCAN] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(subzy, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, entry->d_name) &&
                    strstr(line, "[VULNERABLE]"))
                {
                    fprintf(out, "[TAKEOVER] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(subjack, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, entry->d_name) &&
                    strstr(line, "[VULNERABLE]"))
                {
                    fprintf(out, "[TAKEOVER] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fclose(out);

        printf("[+] %-35s %3d findings\n", entry->d_name, findings);
    }

    closedir(dir);
    printf("[+] Analysis complete.\n");
}
*/