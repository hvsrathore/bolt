/* client for HTTP trackers implementing BEP-0003 and BEP-0023 compact peer specifications */

use crate::bencode::parse;
use crate::tracker::{
    parse_compact_peers_ipv4, AnnounceRequest, AnnounceResponse, Peer, TrackerError,
};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/* default HTTP port when not explicitly specified in tracker URL */
pub const HTTP_PORT_DEFAULT: u16 = 80;

/* manage HTTP tracker client utilizing raw TCP sockets for full control over HTTP framing */
pub struct HttpTrackerClient {
    timeout: Duration,
}

impl Default for HttpTrackerClient {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl HttpTrackerClient {
    /* construct HTTP client with configurable socket I/O timeout */
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /* percent-encode arbitrary binary slice (RFC 3986 unreserved character preservation).
       unlike standard string URL encoders which assume valid UTF-8, torrent info_hash
       and peer_id contain raw arbitrary binary bytes (0x00..=0xFF) that must be preserved
       losslessly as %XX hex escape sequences unless they fall into unreserved ASCII */
    pub fn url_encode_binary(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 3);
        for &byte in bytes {
            match byte {
                /* preserve RFC 3986 unreserved characters */
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                /* non-unreserved bytes encoded as uppercase two-digit hex escapes */
                other => {
                    use std::fmt::Write;
                    write!(&mut encoded, "%{:02X}", other).unwrap();
                }
            }
        }
        encoded
    }

    /* construct full HTTP GET URL and query string for announce request */
    pub fn build_announce_url(base_url: &str, req: &AnnounceRequest) -> String {
        let mut url = base_url.to_string();
        let separator = if url.contains('?') { '&' } else { '?' };
        url.push(separator);

        url.push_str("info_hash=");
        url.push_str(&Self::url_encode_binary(&req.info_hash));

        url.push_str("&peer_id=");
        url.push_str(&Self::url_encode_binary(&req.peer_id));

        use std::fmt::Write;
        write!(
            &mut url,
            "&port={}&uploaded={}&downloaded={}&left={}&compact=1",
            req.port, req.uploaded, req.downloaded, req.left
        )
        .unwrap();

        if let Some(event_str) = req.event.to_http_param_str() {
            url.push_str("&event=");
            url.push_str(event_str);
        }

        if let Some(num_want) = req.num_want {
            write!(&mut url, "&numwant={num_want}").unwrap();
        }

        url
    }

    /* decompose tracker URL into host, port, and path-with-query */
    pub fn parse_url(url: &str) -> Result<(String, u16, String), TrackerError> {
        let trimmed = url.trim();
        let stripped = trimmed
            .strip_prefix("http://")
            .ok_or_else(|| TrackerError::InvalidUrl(url.to_string()))?;

        /* split host/port from path */
        let (host_port, path_and_query) = match stripped.find('/') {
            Some(idx) => (&stripped[..idx], &stripped[idx..]),
            None => (stripped, "/"),
        };

        /* extract optional port from host component */
        let (host, port) = match host_port.find(':') {
            Some(colon_idx) => {
                let h = &host_port[..colon_idx];
                let p_str = &host_port[colon_idx + 1..];
                let p = p_str.parse::<u16>().map_err(|_| {
                    TrackerError::InvalidUrl(format!("invalid port number in {url}"))
                })?;
                (h, p)
            }
            None => (host_port, HTTP_PORT_DEFAULT),
        };

        if host.is_empty() {
            return Err(TrackerError::InvalidUrl(url.to_string()));
        }

        Ok((host.to_string(), port, path_and_query.to_string()))
    }

    /* parse raw HTTP response bytes: status line, header delimiters, and bencoded body */
    pub fn parse_http_response(raw_response: &[u8]) -> Result<AnnounceResponse, TrackerError> {
        /* locate header-body separator (double CRLF per RFC 7230) */
        let delimiter = b"\r\n\r\n";
        let body_start = raw_response
            .windows(delimiter.len())
            .position(|window| window == delimiter)
            .map(|pos| pos + delimiter.len())
            .or_else(|| {
                /* fallback to single LF delimiter for non-conformant servers */
                let lf_delim = b"\n\n";
                raw_response
                    .windows(lf_delim.len())
                    .position(|w| w == lf_delim)
                    .map(|p| p + lf_delim.len())
            })
            .ok_or(TrackerError::InvalidResponse("missing HTTP header delimiter"))?;

        let header_bytes = &raw_response[..body_start];
        let header_str = String::from_utf8_lossy(header_bytes);

        /* parse status line */
        let mut lines = header_str.lines();
        let status_line = lines
            .next()
            .ok_or(TrackerError::InvalidResponse("empty HTTP response"))?;

        let mut status_parts = status_line.split_whitespace();
        let _http_version = status_parts.next();
        let status_code = status_parts
            .next()
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or(TrackerError::InvalidResponse("invalid HTTP status code"))?;

        if status_code != 200 {
            let reason = status_parts.collect::<Vec<_>>().join(" ");
            return Err(TrackerError::HttpStatus {
                status_code,
                reason,
            });
        }

        /* parse bencoded payload body */
        let body_bytes = &raw_response[body_start..];
        Self::parse_bencoded_announce_body(body_bytes)
    }

    /* parse bencoded dictionary returned by HTTP tracker */
    pub fn parse_bencoded_announce_body(body: &[u8]) -> Result<AnnounceResponse, TrackerError> {
        let root = parse(body)?;

        /* check if tracker reported explicit failure message */
        if let Some(failure_val) = root.dict_get_by_str("failure reason")
            && let Some(msg) = failure_val.as_str()
        {
            return Err(TrackerError::TrackerFailure(msg.to_string()));
        }

        /* extract mandatory announce interval in seconds */
        let interval_val = root
            .dict_get_by_str("interval")
            .ok_or(TrackerError::InvalidResponse("missing interval in tracker response"))?;
        let interval = interval_val
            .as_i64()
            .ok_or(TrackerError::InvalidResponse("interval must be integer"))?
            as u32;

        /* extract optional seeder/leecher swarm counts */
        let seeders = root
            .dict_get_by_str("complete")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u32;

        let leechers = root
            .dict_get_by_str("incomplete")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u32;

        /* extract peers list: compact byte string (BEP-0023) or list of dicts (BEP-0003) */
        let peers_val = root
            .dict_get_by_str("peers")
            .ok_or(TrackerError::InvalidResponse("missing peers in tracker response"))?;

        let peers = if let Some(compact_bytes) = peers_val.as_bytes() {
            /* compact binary format: 6 bytes per IPv4 peer */
            parse_compact_peers_ipv4(compact_bytes)?
        } else if let Some(dict_list) = peers_val.as_list() {
            /* legacy non-compact dictionary list format */
            let mut list = Vec::new();
            for entry in dict_list {
                if let (Some(ip_str), Some(port)) = (
                    entry.dict_get_by_str("ip").and_then(|v| v.as_str()),
                    entry.dict_get_by_str("port").and_then(|v| v.as_i64()),
                ) && let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    list.push(Peer {
                        ip,
                        port: port as u16,
                    });
                }
            }
            list
        } else {
            return Err(TrackerError::InvalidResponse("invalid peers representation"));
        };

        Ok(AnnounceResponse {
            interval,
            seeders,
            leechers,
            peers,
        })
    }

    /* execute synchronous HTTP GET announce request over TCP socket */
    pub fn announce(
        &self,
        tracker_url: &str,
        req: &AnnounceRequest,
    ) -> Result<AnnounceResponse, TrackerError> {
        let full_url = Self::build_announce_url(tracker_url, req);
        let (host, port, path_and_query) = Self::parse_url(&full_url)?;

        /* resolve remote address and establish TCP connection */
        let addr_str = format!("{host}:{port}");
        let socket_addr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| TrackerError::InvalidUrl(format!("failed to resolve {host}")))?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        /* construct HTTP/1.1 GET request frame */
        let request_str = format!(
            "GET {path_and_query} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: bolt/0.1.0\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n"
        );

        stream.write_all(request_str.as_bytes())?;
        stream.flush()?;

        /* read raw HTTP response until server closes connection */
        let mut raw_response = Vec::new();
        stream.read_to_end(&mut raw_response)?;

        Self::parse_http_response(&raw_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker::{AnnounceEvent, Peer};
    use std::net::Ipv4Addr;

    #[test]
    fn test_url_encode_binary() {
        /* unreserved characters must remain untouched */
        assert_eq!(
            HttpTrackerClient::url_encode_binary(b"abc-123_.~"),
            "abc-123_.~"
        );

        /* reserved and binary characters must be percent-encoded in uppercase hex */
        assert_eq!(
            HttpTrackerClient::url_encode_binary(&[0x00, 0x12, 0xff, 0x20]),
            "%00%12%FF%20"
        );
    }

    #[test]
    fn test_parse_url() {
        let (host, port, path) =
            HttpTrackerClient::parse_url("http://tracker.example.com:6969/announce?a=b")
                .expect("parse url failed");
        assert_eq!(host, "tracker.example.com");
        assert_eq!(port, 6969);
        assert_eq!(path, "/announce?a=b");

        let (host, port, path) =
            HttpTrackerClient::parse_url("http://tracker.example.com/announce")
                .expect("parse url failed");
        assert_eq!(host, "tracker.example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/announce");
    }

    #[test]
    fn test_build_announce_url() {
        let req = AnnounceRequest {
            info_hash: [0x01; 20], /* non-alphanumeric bytes (0x01 -> %01) */
            peer_id: [0x30; 20],   /* '0' repeated 20 times (ASCII unreserved) */
            port: 6881,
            uploaded: 100,
            downloaded: 200,
            left: 300,
            event: AnnounceEvent::Started,
            num_want: Some(30),
        };

        let url = HttpTrackerClient::build_announce_url("http://tracker.test/announce", &req);
        assert!(url.starts_with("http://tracker.test/announce?info_hash=%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01%01"));
        assert!(url.contains("&peer_id=00000000000000000000"));
        assert!(url.contains("&port=6881"));
        assert!(url.contains("&uploaded=100"));
        assert!(url.contains("&downloaded=200"));
        assert!(url.contains("&left=300"));
        assert!(url.contains("&compact=1"));
        assert!(url.contains("&event=started"));
        assert!(url.contains("&numwant=30"));
    }

    #[test]
    fn test_parse_http_response_compact_peers() {
        let http_response = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 46\r\n\
\r\n\
d8:completei10e10:incompletei4e8:intervali900e5:peers6:\xc0\xa8\x01\x01\x1a\xe1e";

        let parsed = HttpTrackerClient::parse_http_response(http_response)
            .expect("HTTP response parsing failed");

        assert_eq!(parsed.interval, 900);
        assert_eq!(parsed.seeders, 10);
        assert_eq!(parsed.leechers, 4);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0], Peer {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            port: 6881,
        });
    }

    #[test]
    fn test_parse_http_response_failure_reason() {
        let http_response = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
\r\n\
d14:failure reason24:info_hash not registerede";

        let result = HttpTrackerClient::parse_http_response(http_response);
        match result {
            Err(TrackerError::TrackerFailure(reason)) => {
                assert_eq!(reason, "info_hash not registered");
            }
            other => panic!("expected TrackerFailure, got: {:?}", other),
        }
    }
}
