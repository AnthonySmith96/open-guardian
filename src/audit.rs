use crate::banner;
use std::fs;
use std::path::Path;

pub fn run_audit(path: &str) -> anyhow::Result<()> {
    banner::print_step(&format!("Auditing directory: {path}"));

    let audit_path = Path::new(path);
    if !audit_path.exists() {
        banner::print_error("Path does not exist.");
        return Ok(());
    }

    let files_to_check = [".env", "openclaw.json", "config.json"];

    for entry in fs::read_dir(audit_path)? {
        let entry = entry?;
        let file_name = entry.file_name().into_string().unwrap_or_default();

        if files_to_check.contains(&file_name.as_str()) {
            banner::print_warning(&format!("Found sensitive config file: {file_name}"));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = entry.metadata()?;
                let mode = metadata.permissions().mode();
                if mode & 0o007 != 0 {
                    banner::print_error(&format!(
                        "CRITICAL: {file_name} is world-readable! (Mode: {mode:o})"
                    ));
                }
            }

            // Check for dangerous settings in JSON files
            if file_name.ends_with(".json") {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if content.contains("0.0.0.0") {
                        banner::print_warning(&format!(
                            "{file_name} binds to 0.0.0.0 (Potentially exposed)"
                        ));
                    }
                }
            }
        }
    }

    banner::print_success("Audit complete.");
    Ok(())
}
