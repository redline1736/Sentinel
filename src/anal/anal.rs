use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

fn anal(dir_path: &str) -> io::Result<()> {
    let entries = fs::read_dir(dir_path)?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Only process directories
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let path = entry.path();

        println!("Found directory: {:?}", path);

        let subzy_path = path.join("subzy.txt");
        let subjack_path = path.join("subjack.txt");
        let nuclei_path = path.join("nuclei.txt");
        let xss_path = path.join("xss.txt");
        let wpscan_path = path.join("wpscan.txt");

        let gen_payloads = path.join("valid_payloads.txt");
        let custom_payloads = path.join("valid_payloads_custom.txt");

        // Output file
        let vuln_path = path.join("vuln.txt");
        let mut vuln = File::create(vuln_path)?;

        // -------------------------
        // SUBZY
        // -------------------------

        if let Ok(file) = File::open(&subzy_path) {
            let reader = BufReader::new(file);

            writeln!(vuln, "SUBZY Results")?;

            for line in reader.lines() {
                let line = line?;

                if line.contains("VULNERABLE") || line.contains("TAKEOVER") {
                    println!("[TAKEOVER] {}", line);
                    writeln!(vuln, "[TAKEOVER] {}", line)?;
                }
            }
        }

        // -------------------------
        // SUBJACK
        // -------------------------

        if let Ok(file) = File::open(&subjack_path) {
            let reader = BufReader::new(file);

            writeln!(vuln, "SUBJACK Results")?;

            for line in reader.lines() {
                let line = line?;

                if line.contains("VULNERABLE") || line.contains("TAKEOVER") {
                    println!("[TAKEOVER] {}", line);
                    writeln!(vuln, "[TAKEOVER] {}", line)?;
                }
            }
        }

        // -------------------------
        // NUCLEI
        // -------------------------

        if let Ok(file) = File::open(&nuclei_path) {
            let reader = BufReader::new(file);

            writeln!(vuln, "NUCLEI Results")?;

            for line in reader.lines() {
                let line = line?;

                if line.contains("[critical]")
                    || line.contains("[high]")
                    || line.contains("[medium]")
                    || line.contains("[low]")
                {
                    println!("[NUCLEI] {}", line);
                    writeln!(vuln, "[NUCLEI] {}", line)?;
                }
            }
        }

        // -------------------------
        // XSS
        // -------------------------

        if let Ok(file) = File::open(&xss_path) {
            let reader = BufReader::new(file);

            writeln!(vuln, "XSS TOOLCHAIN Results")?;

            for line in reader.lines() {
                let line = line?;

                if line.len() > 5 {
                    println!("[XSS] {}", line);
                    writeln!(vuln, "[XSS] {}", line)?;
                }
            }
        }

        // -------------------------
        // WPSCAN
        // -------------------------

        if let Ok(file) = File::open(&wpscan_path) {
            let reader = BufReader::new(file);

            writeln!(vuln, "WPSCAN Results")?;

            for line in reader.lines() {
                let line = line?;

                if line.contains("[!]")
                    || line.contains("Vulnerable")
                    || line.contains("Confirmed")
                {
                    println!("[WPSCAN] {}", line);
                    writeln!(vuln, "[WPSCAN] {}", line)?;
                }
            }
        }

        // -------------------------
        // GENERATED XSS
        // -------------------------

        if let Ok(file) = File::open(&gen_payloads) {
            let reader = BufReader::new(file);

            writeln!(vuln, "XSS TOOL RESULTS")?;

            for line in reader.lines() {
                let line = line?;
                writeln!(vuln, "[XSS_GENERATED] {}", line)?;
            }
        }

        // -------------------------
        // CUSTOM XSS
        // -------------------------

        if let Ok(file) = File::open(&custom_payloads) {
            let reader = BufReader::new(file);

            writeln!(vuln, "CUSTOM XSS TOOL RESULTS")?;

            for line in reader.lines() {
                let line = line?;
                writeln!(vuln, "[XSS_GENERATED] {}", line)?;
            }
        }

        println!("[+] Analysis complete.");
        writeln!(vuln, "[+] Analysis complete.")?;
    }

    Ok(())
}
