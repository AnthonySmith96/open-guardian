use colored::*;

pub fn print_banner() {
    let banner = r#"
   ____                      _____                      _ _             
  / __ \                    / ____|                    | (_)            
 | |  | |_ __   ___ _ __   | |  __ _   _  __ _ _ __  __| |_  __ _ _ __  
 | |  | | '_ \ / _ \ '_ \  | | |_ | | | |/ _` | '__|/ _` | |/ _` | '_ \ 
 | |__| | |_) |  __/ | | | | |__| | |_| | (_| | |  | (_| | | (_| | | | |
  \____/| .__/ \___|_| |_|  \_____|\__,_|\__,_|_|   \__,_|_|\__,_|_| |_|
        | |                                                             
        |_|                                                             
    "#;

    println!("{}", banner.bright_cyan().bold());
    println!(
        "   {}",
        "Stopping Smart Agents from doing stupid things."
            .bright_white()
            .italic()
    );
    println!(
        "   {}",
        format!(
            "Version {} — Licensed under Apache-2.0",
            env!("CARGO_PKG_VERSION")
        )
        .bright_black()
    );
    println!();
    println!(
        "   {}",
        "Built with ❤️ by CyberIndustree & The Open Source Community".blue()
    );
}

pub fn print_startup_info(addr: &str, upstream: &str, action: &str, dlp: &str, model: &str) {
    let corner_tl = "┌".bright_black();
    let corner_tr = "┐".bright_black();
    let corner_bl = "└".bright_black();
    let corner_br = "┘".bright_black();
    let side = "│".bright_black();

    let width = 60;
    let line = "─".repeat(width).bright_black();

    println!("{}{}{}", corner_tl, line, corner_tr);
    println!(
        "{}  {: <18}  {}",
        side,
        "🛡️  STATUS:".bright_green().bold(),
        format!("SHIELD ACTIVE (v{})", env!("CARGO_PKG_VERSION"))
            .on_green()
            .black()
            .bold()
    );
    println!(
        "{}  {: <18}  {}",
        side,
        "📍 ENDPOINT:".bright_white(),
        addr.bright_cyan()
    );
    println!(
        "{}  {: <18}  {}",
        side,
        "🚀 UPSTREAM:".bright_white(),
        upstream.bright_cyan()
    );
    println!(
        "{}  {: <18}  {}",
        side,
        "⚖️  CORE POLICY:".bright_white(),
        action.to_uppercase().bright_yellow()
    );
    println!(
        "{}  {: <18}  {}",
        side,
        "🔍 DLP ACTION:".bright_white(),
        dlp.to_uppercase().bright_yellow()
    );
    println!(
        "{}  {: <18}  {}",
        side,
        "🤖 AI JUDGE:".bright_white(),
        model.bright_magenta()
    );
    println!("{}{}{}", corner_bl, line, corner_br);
    println!();
}

pub fn print_step(msg: &str) {
    println!(" {} {}", "➜".bright_blue().bold(), msg);
    tracing::info!("STEP: {}", msg);
}

pub fn print_success(msg: &str) {
    println!(" {} {}", "✔".bright_green().bold(), msg);
    tracing::info!("SUCCESS: {}", msg);
}

pub fn print_warning(msg: &str) {
    println!(" {} {}", "⚠".bright_yellow().bold(), msg);
    tracing::warn!("WARNING: {}", msg);
}

pub fn print_error(msg: &str) {
    println!(" {} {}", "✘".bright_red().bold(), msg);
    tracing::error!("ERROR: {}", msg);
}

pub fn print_info(msg: &str) {
    println!(" {} {}", "→".bright_cyan(), msg);
    tracing::info!("{}", msg);
}

pub fn print_blocking(msg: &str) {
    println!(" {} {}", "🛡".bright_red().bold(), msg);
    tracing::warn!("BLOCKED: {}", msg);
}
