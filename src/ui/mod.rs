/* terminal user interface built with ratatui featuring Bitfield Heatmap and peer telemetry */

pub mod app;

use app::{AppState, PieceVisualState};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table,
};
use ratatui::Frame;

/* render entire BitTorrent TUI dashboard across terminal layout panes */
pub fn render_dashboard(frame: &mut Frame<'_>, app: &AppState) {
    let size = frame.area();

    /* root vertical layout partition */
    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), /* top header info panel */
            Constraint::Length(3), /* progress gauge */
            Constraint::Min(10),   /* middle area: heatmap and peer table */
            Constraint::Length(7), /* bottom sparklines */
        ])
        .split(size);

    render_header(frame, root_chunks[0], app);
    render_progress_bar(frame, root_chunks[1], app);

    /* partition middle pane into Bitfield Heatmap (top/left) and Peer Table (bottom/right) */
    let middle_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), /* live bitfield heatmap grid */
            Constraint::Percentage(50), /* connected peer table */
        ])
        .split(root_chunks[2]);

    render_bitfield_heatmap(frame, middle_chunks[0], app);
    render_peer_table(frame, middle_chunks[1], app);

    /* partition bottom pane for dual download/upload sparklines */
    let sparkline_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root_chunks[3]);

    render_download_sparkline(frame, sparkline_chunks[0], app);
    render_upload_sparkline(frame, sparkline_chunks[1], app);
}

/* render header showing torrent metadata, info_hash, and engine operating mode */
fn render_header(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let mode_badge = if app.is_magnet_resolving {
        Span::styled(
            " [RESOLVING MAGNET METADATA (BEP-0009)] ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    } else if app.is_endgame {
        Span::styled(
            " [ENDGAME MODE ACTIVE] ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [DOWNLOADING (RAREST-FIRST)] ",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )
    };

    let title_line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.torrent_name),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Hash: "),
        Span::styled(&app.info_hash_hex, Style::default().fg(Color::DarkGray)),
        Span::raw(" | Mode: "),
        mode_badge,
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" bolt BitTorrent Client Engine ");

    let paragraph = Paragraph::new(title_line).block(block);
    frame.render_widget(paragraph, area);
}

/* render download percentage gauge with throughput and transfer metrics */
fn render_progress_bar(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let pct = app.download_progress();
    let downloaded_mib = app.downloaded_bytes as f64 / (1024.0 * 1024.0);
    let total_mib = app.total_bytes as f64 / (1024.0 * 1024.0);

    let label = format!(
        "{:.1}% ({:.1} / {:.1} MiB) | Down: {:.1} KiB/s | Up: {:.1} KiB/s",
        pct, downloaded_mib, total_mib, app.current_down_kib, app.current_up_kib
    );

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Transfer Progress "))
        .gauge_style(
            Style::default()
                .fg(Color::LightGreen)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .percent(pct.clamp(0.0, 100.0) as u16)
        .label(label);

    frame.render_widget(gauge, area);
}

/* render live 2D Bitfield Heatmap grid with color-coded piece status */
fn render_bitfield_heatmap(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Swarm Bitfield Heatmap ");

    /* inner area inside borders */
    let inner_width = area.width.saturating_sub(2) as usize;
    let inner_height = area.height.saturating_sub(4) as usize; /* leave room for legend */

    let mut lines = Vec::new();

    if inner_width > 0 && !app.piece_states.is_empty() {
        /* adaptive column count based on panel width */
        let cols = inner_width;
        let mut row_spans = Vec::with_capacity(cols);

        for (idx, &state) in app.piece_states.iter().enumerate() {
            let (glyph, style) = match state {
                PieceVisualState::Downloaded => (
                    "■",
                    Style::default().fg(Color::Green),
                ),
                PieceVisualState::InFlight => (
                    "▲",
                    Style::default().fg(Color::Yellow),
                ),
                PieceVisualState::Rare => (
                    "░",
                    Style::default().fg(Color::Cyan),
                ),
                PieceVisualState::Missing => (
                    "·",
                    Style::default().fg(Color::DarkGray),
                ),
            };

            row_spans.push(Span::styled(glyph, style));

            if row_spans.len() == cols || idx == app.piece_states.len() - 1 {
                lines.push(Line::from(std::mem::take(&mut row_spans)));
                if lines.len() >= inner_height {
                    break;
                }
            }
        }
    }

    /* append visual color legend at bottom */
    lines.push(Line::from(""));
    let legend = Line::from(vec![
        Span::styled("■", Style::default().fg(Color::Green)),
        Span::raw(" Complete  "),
        Span::styled("▲", Style::default().fg(Color::Yellow)),
        Span::raw(" In-Flight  "),
        Span::styled("░", Style::default().fg(Color::Cyan)),
        Span::raw(" Rare  "),
        Span::styled("·", Style::default().fg(Color::DarkGray)),
        Span::raw(" Missing"),
    ]);
    lines.push(legend);

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/* render connected peer table displaying parsed client software and telemetry */
fn render_peer_table(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let header_cells = [
        "Peer Address",
        "Client Software",
        "Down (KiB/s)",
        "Up (KiB/s)",
        "Choked",
        "Done %",
    ]
    .iter()
    .map(|&h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });

    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::Black))
        .height(1);

    let rows: Vec<Row> = app
        .peers
        .iter()
        .map(|peer| {
            let choke_status = if peer.is_choked { "Yes" } else { "No" };
            let choke_style = if peer.is_choked {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };

            let cells = vec![
                Cell::from(peer.endpoint.clone()),
                Cell::from(peer.client_name.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{:.1}", peer.download_speed_kib)),
                Cell::from(format!("{:.1}", peer.upload_speed_kib)),
                Cell::from(choke_status).style(choke_style),
                Cell::from(format!("{:.1}%", peer.progress_pct)),
            ];
            Row::new(cells)
        })
        .collect();

    let widths = [
        Constraint::Length(18),
        Constraint::Length(22),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Connected Swarm Peers "));

    frame.render_widget(table, area);
}

/* render live download throughput sparkline widget */
fn render_download_sparkline(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let title = format!(" Download Throughput: {:.1} KiB/s ", app.current_down_kib);
    let block = Block::default().borders(Borders::ALL).title(title);

    let sparkline = Sparkline::default()
        .block(block)
        .style(Style::default().fg(Color::LightGreen))
        .data(&app.download_sparkline);

    frame.render_widget(sparkline, area);
}

/* render live upload throughput sparkline widget */
fn render_upload_sparkline(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let title = format!(" Upload Throughput: {:.1} KiB/s ", app.current_up_kib);
    let block = Block::default().borders(Borders::ALL).title(title);

    let sparkline = Sparkline::default()
        .block(block)
        .style(Style::default().fg(Color::Magenta))
        .data(&app.upload_sparkline);

    frame.render_widget(sparkline, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::PeerDisplayItem;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_tui_render_dashboard_deterministic() {
        /* setup in-memory test terminal backend (160 columns x 40 rows) */
        let backend = TestBackend::new(160, 40);
        let mut terminal = Terminal::new(backend).expect("terminal creation failed");

        let mut app = AppState::new(
            "ubuntu-22.04.iso".to_string(),
            "c12fe1c06bba254a9d1b00f12abb1f30c1d322ce".to_string(),
            64,
            262144,
            64 * 262144,
        );

        /* set piece states for heatmap visualization */
        for i in 0..16 {
            app.piece_states[i] = PieceVisualState::Downloaded;
        }
        for i in 16..24 {
            app.piece_states[i] = PieceVisualState::InFlight;
        }
        for i in 24..32 {
            app.piece_states[i] = PieceVisualState::Rare;
        }

        /* add synthetic peer telemetry */
        let mut qb_id = [0u8; 20];
        qb_id[..8].copy_from_slice(b"-qB4390-");
        app.peers.push(PeerDisplayItem::new(
            "192.168.1.100:6881".to_string(),
            &qb_id,
            1250.5,
            42.0,
            false,
            true,
            75.0,
        ));

        let mut tr_id = [0u8; 20];
        tr_id[..8].copy_from_slice(b"-TR3000-");
        app.peers.push(PeerDisplayItem::new(
            "10.0.0.50:51413".to_string(),
            &tr_id,
            820.0,
            12.5,
            true,
            true,
            100.0,
        ));

        /* feed throughput history */
        for i in 1..=60 {
            app.record_throughput_sample(i as f64 * 20.0, i as f64 * 2.0);
        }

        /* render dashboard into virtual terminal buffer */
        terminal
            .draw(|f| render_dashboard(f, &app))
            .expect("terminal rendering failed");

        /* inspect rendered virtual buffer */
        let buffer = terminal.backend().buffer();
        let content = format!("{buffer:?}");

        /* verify title and peer client software are present in output */
        assert!(content.contains("ubuntu-22.04.iso"));
        assert!(content.contains("qBittorrent"));
        assert!(content.contains("Transmission"));
        assert!(content.contains("Bitfield Heatmap"));
    }
}
