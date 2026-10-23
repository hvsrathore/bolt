/* decode BitTorrent peer ID client fingerprint for known software clients */

/* parse 20-byte peer ID into human-readable client name and version string */
pub fn parse_peer_client(peer_id: &[u8; 20]) -> String {
    /* check for standard Azureus-style fingerprint: '-XXYYYY-' */
    if peer_id[0] == b'-' && peer_id[7] == b'-' {
        let client_code = &peer_id[1..3];
        let version_digits = &peer_id[3..7];

        let client_name = match client_code {
            b"qB" => "qBittorrent",
            b"TR" => "Transmission",
            b"LT" => "libtorrent",
            b"UT" => "uTorrent",
            b"DE" => "Deluge",
            b"BT" => "BitTorrent",
            b"AZ" => "Vuze",
            b"BL" => "bolt",
            b"WD" => "WebTorrent",
            b"KT" => "KTorrent",
            b"BC" => "BitComet",
            b"AG" => "Ares",
            _ => "Unknown Azureus Client",
        };

        let v_str = String::from_utf8_lossy(version_digits);
        let formatted_ver = format_azureus_version(&v_str);

        if formatted_ver.is_empty() {
            client_name.to_string()
        } else {
            format!("{client_name} {formatted_ver}")
        }
    } else if &peer_id[0..3] == b"M7-" || &peer_id[0..4] == b"-M7-" {
        "Mainline BitTorrent".to_string()
    } else {
        /* check if initial 8 bytes contain ASCII printable characters */
        let printable = peer_id[..8]
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ');

        if printable {
            format!("Generic ({})", String::from_utf8_lossy(&peer_id[..8]).trim())
        } else {
            "Unknown Peer".to_string()
        }
    }
}

/* format 4-character version code into semver style representation */
fn format_azureus_version(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() == 4 && chars.iter().all(|c| c.is_ascii_alphanumeric()) {
        if chars[3] == '0' {
            format!("{}.{}.{}", chars[0], chars[1], chars[2])
        } else {
            format!("{}.{}.{}.{}", chars[0], chars[1], chars[2], chars[3])
        }
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_known_clients() {
        let mut qb = [0u8; 20];
        qb[..8].copy_from_slice(b"-qB4390-");
        assert_eq!(parse_peer_client(&qb), "qBittorrent 4.3.9");

        let mut tr = [0u8; 20];
        tr[..8].copy_from_slice(b"-TR3000-");
        assert_eq!(parse_peer_client(&tr), "Transmission 3.0.0");

        let mut lt = [0u8; 20];
        lt[..8].copy_from_slice(b"-LT1214-");
        assert_eq!(parse_peer_client(&lt), "libtorrent 1.2.1.4");

        let mut ut = [0u8; 20];
        ut[..8].copy_from_slice(b"-UT3530-");
        assert_eq!(parse_peer_client(&ut), "uTorrent 3.5.3");
    }
}
