/* bolt CLI and interactive BitTorrent terminal user interface */

use bolt::engine::SwarmEngine;
use bolt::torrent::FileTree;
use bolt::{
    render_dashboard, AppState, MagnetLink, Metainfo, PeerDisplayItem, PieceVisualState,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/* RAII terminal guard ensuring alternate screen and raw mode cleanup on drop */
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/* print CLI help and usage information */
fn print_help() {
    println!(
        r#"bolt ⚡ - high-performance asynchronous BitTorrent client engine

USAGE:
    bolt [OPTIONS] [TORRENT_OR_MAGNET]

ARGUMENTS:
    <TORRENT_OR_MAGNET>   Path to a .torrent metainfo file or a magnet:? URI

OPTIONS:
    -d, --demo            Launch simulated BitTorrent TUI dashboard
    -t, --tui             Launch interactive BitTorrent TUI dashboard for target
    -o, --output <DIR>    Directory to store downloaded files (default: ./downloads)
    -h, --help            Print help information
    -v, --version         Print version information

EXAMPLES:
    cargo run
    cargo run -- --demo
    cargo run -- "magnet:?xt=urn:btih:c12fe1c06bba254a9d1b00f12abb1f30c1d322ce&dn=ubuntu.iso"
    cargo run -- --tui "magnet:?xt=urn:btih:c12fe1c06bba254a9d1b00f12abb1f30c1d322ce&dn=ubuntu.iso"
    cargo run -- archlinux.torrent
"#
    );
}

/* print crate version */
fn print_version() {
    println!("bolt {}", env!("CARGO_PKG_VERSION"));
}

/* construct synthetic demo AppState with simulated swarm peers and pieces */
fn create_demo_state() -> AppState {
    let total_pieces = 128;
    let piece_length = 262144; /* 256 KiB */
    let total_bytes = total_pieces as u64 * piece_length;

    let mut app = AppState::new(
        "archlinux-2026.10.01-x86_64.iso".to_string(),
        "c12fe1c06bba254a9d1b00f12abb1f30c1d322ce".to_string(),
        total_pieces,
        piece_length,
        total_bytes,
    );

    /* initialize simulated piece heatmap states */
    for i in 0..48 {
        app.piece_states[i] = PieceVisualState::Downloaded;
    }
    for i in 48..64 {
        app.piece_states[i] = PieceVisualState::InFlight;
    }
    for i in 64..80 {
        app.piece_states[i] = PieceVisualState::Rare;
    }
    app.downloaded_bytes = 48 * piece_length;

    /* populate simulated connected peers */
    let mut qb_id = [0u8; 20];
    qb_id[..8].copy_from_slice(b"-qB4390-");
    app.peers.push(PeerDisplayItem::new(
        "192.168.1.100:6881".to_string(),
        &qb_id,
        2840.5,
        120.0,
        false,
        true,
        92.5,
    ));

    let mut tr_id = [0u8; 20];
    tr_id[..8].copy_from_slice(b"-TR3000-");
    app.peers.push(PeerDisplayItem::new(
        "10.0.0.45:51413".to_string(),
        &tr_id,
        1420.0,
        64.5,
        false,
        true,
        68.0,
    ));

    let mut lt_id = [0u8; 20];
    lt_id[..8].copy_from_slice(b"-LT1214-");
    app.peers.push(PeerDisplayItem::new(
        "172.16.0.88:6889".to_string(),
        &lt_id,
        980.2,
        32.0,
        true,
        true,
        45.2,
    ));

    let mut ut_id = [0u8; 20];
    ut_id[..8].copy_from_slice(b"-UT3530-");
    app.peers.push(PeerDisplayItem::new(
        "198.51.100.22:16881".to_string(),
        &ut_id,
        512.0,
        18.0,
        false,
        false,
        15.8,
    ));

    /* prime sparkline throughput buffers with initial telemetry values */
    for i in 0..60 {
        let factor = (i as f64 / 60.0).sin().abs();
        app.record_throughput_sample(3200.0 * factor + 500.0, 150.0 * factor + 20.0);
    }

    app
}

/* run interactive Ratatui TUI dashboard event loop */
fn run_tui(
    app_state: Arc<Mutex<AppState>>,
    is_demo_simulation: bool,
    engine: Option<Arc<SwarmEngine>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let tick_rate = Duration::from_millis(200);
    let mut last_tick = Instant::now();
    let mut sim_step = 0usize;

    loop {
        {
            let app = app_state.lock().unwrap();
            terminal.draw(|frame| render_dashboard(frame, &app))?;
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            if is_demo_simulation {
                sim_step = sim_step.wrapping_add(1);
                let mut app = app_state.lock().unwrap();

                /* simulate incremental piece download progression */
                let piece_idx = (48 + (sim_step / 3)) % app.total_pieces;
                if piece_idx < app.piece_states.len() {
                    app.piece_states[piece_idx] = PieceVisualState::Downloaded;
                    if piece_idx + 1 < app.piece_states.len() {
                        app.piece_states[piece_idx + 1] = PieceVisualState::InFlight;
                    }
                }

                let completed = app
                    .piece_states
                    .iter()
                    .filter(|&&s| s == PieceVisualState::Downloaded)
                    .count();
                app.downloaded_bytes = (completed as u64 * app.piece_length).min(app.total_bytes);

                /* toggle endgame mode indicator dynamically when reaching near-completion */
                if completed >= (app.total_pieces * 9) / 10 {
                    app.is_endgame = true;
                }

                /* record oscillatory throughput fluctuations */
                let wave = ((sim_step as f64) * 0.15).sin();
                let down = (3800.0 + wave * 900.0).max(100.0);
                let up = (220.0 + wave * 60.0).max(10.0);
                app.record_throughput_sample(down, up);
            }

            last_tick = Instant::now();
        }
    }

    if let Some(eng) = engine {
        eng.shutdown();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    /* handle help flags */
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help();
        return Ok(());
    }

    /* handle version flags */
    if args.iter().any(|arg| arg == "-v" || arg == "--version") {
        print_version();
        return Ok(());
    }

    /* demo flag explicitly requests interactive TUI simulation */
    if args.iter().any(|a| a == "-d" || a == "--demo") {
        let app = create_demo_state();
        let app_state = Arc::new(Mutex::new(app));
        run_tui(app_state, true, None)?;
        return Ok(());
    }

    /* inspect positional target argument if supplied */
    let is_tui_requested = args.iter().any(|a| a == "-t" || a == "--tui");

    /* inspect optional output directory argument (default: ./downloads) */
    let download_dir = if let Some(pos) = args.iter().position(|a| a == "-o" || a == "--output") {
        args.get(pos + 1)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./downloads"))
    } else {
        PathBuf::from("./downloads")
    };

    let target_arg = args.iter().skip(1).find(|a| !a.starts_with('-') && Some(a.as_str()) != args.iter().position(|x| x == "-o" || x == "--output").and_then(|p| args.get(p + 1)).map(|s| s.as_str()));

    if let Some(target) = target_arg {
        if target.starts_with("magnet:") {
            /* parse BEP-0009 magnet URI */
            let magnet = MagnetLink::parse(target)?;
            let hex_hash = magnet.info_hash_hex();
            let name = magnet
                .display_name
                .clone()
                .unwrap_or_else(|| format!("magnet-{}", &hex_hash[..8]));

            let mut initial_app = AppState::new(name, hex_hash, 64, 262144, 64 * 262144);
            initial_app.is_magnet_resolving = true;
            let app_state = Arc::new(Mutex::new(initial_app));

            /* start background asynchronous swarm engine */
            let engine = Arc::new(SwarmEngine::new_from_magnet(
                &magnet,
                Arc::clone(&app_state),
                download_dir.clone(),
            ));
            Arc::clone(&engine).start();

            if is_tui_requested {
                run_tui(app_state, false, Some(engine))?;
            } else {
                println!("magnet URI parsed successfully:");
                println!(
                    "  name:        {}",
                    magnet.display_name.as_deref().unwrap_or("unnamed")
                );
                println!("  info_hash:   {}", magnet.info_hash_hex());
                println!("  output dir:  {}", download_dir.display());
                println!("  trackers:    {}", magnet.trackers.len());
                for (idx, trk) in magnet.trackers.iter().enumerate() {
                    println!("    [{}] {}", idx + 1, trk);
                }
                println!("\nConnecting to swarm (pass --tui for full interactive dashboard)...");

                let mut last_print = Instant::now();
                while engine.is_running() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if last_print.elapsed() >= Duration::from_secs(1) {
                        let app = app_state.lock().unwrap();
                        let mode = if app.is_magnet_resolving {
                            "RESOLVING MAGNET METADATA"
                        } else if app.is_endgame {
                            "ENDGAME"
                        } else {
                            "DOWNLOADING"
                        };
                        let down_mib = app.downloaded_bytes as f64 / (1024.0 * 1024.0);
                        let tot_mib = app.total_bytes as f64 / (1024.0 * 1024.0);
                        let pct = app.download_progress();
                        println!(
                            "[{mode}] {:.1}% ({:.1}/{:.1} MiB) | Down: {:.1} KiB/s | Peers: {}",
                            pct, down_mib, tot_mib, app.current_down_kib, app.peers.len()
                        );
                        last_print = Instant::now();
                    }
                }
            }
            return Ok(());
        }

        let path = Path::new(target);
        if path.exists() {
            /* parse BEP-0003 .torrent metainfo file */
            let bytes = fs::read(path)?;
            let metainfo = Metainfo::parse(&bytes)?;
            let hex_hash = metainfo.info_hash_hex();
            let name = match &metainfo.file_tree {
                FileTree::SingleFile { name, .. } => (*name).to_string(),
                FileTree::MultiFile { directory_name, .. } => (*directory_name).to_string(),
            };
            let piece_count = metainfo.piece_count();
            let piece_length = metainfo.piece_length;
            let total_bytes = metainfo.total_length();

            let initial_app = AppState::new(name.clone(), hex_hash, piece_count, piece_length, total_bytes);
            let app_state = Arc::new(Mutex::new(initial_app));

            /* start background asynchronous swarm engine */
            let engine = Arc::new(SwarmEngine::new_from_metainfo(
                &metainfo,
                Arc::clone(&app_state),
                download_dir.clone(),
            ));
            Arc::clone(&engine).start();

            if is_tui_requested {
                run_tui(app_state, false, Some(engine))?;
            } else {
                println!(".torrent metainfo parsed successfully:");
                println!("  name:         {}", name);
                println!("  info_hash:    {}", metainfo.info_hash_hex());
                println!("  output dir:   {}", download_dir.display());
                println!("  announce:     {}", metainfo.announce);
                println!("  piece count:  {}", piece_count);
                println!("  piece length: {} bytes", piece_length);
                println!("  total length: {} bytes", total_bytes);
                println!("\nConnecting to swarm (pass --tui for full interactive dashboard)...");

                let mut last_print = Instant::now();
                while engine.is_running() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if last_print.elapsed() >= Duration::from_secs(1) {
                        let app = app_state.lock().unwrap();
                        let down_mib = app.downloaded_bytes as f64 / (1024.0 * 1024.0);
                        let tot_mib = app.total_bytes as f64 / (1024.0 * 1024.0);
                        let pct = app.download_progress();
                        println!(
                            "[DOWNLOADING] {:.1}% ({:.1}/{:.1} MiB) | Down: {:.1} KiB/s | Peers: {}",
                            pct, down_mib, tot_mib, app.current_down_kib, app.peers.len()
                        );
                        last_print = Instant::now();
                    }
                }
            }
            return Ok(());
        }

        eprintln!("error: target file not found: {}", target);
        std::process::exit(1);
    }

    /* default to printing help message if no arguments provided */
    print_help();
    Ok(())
}
