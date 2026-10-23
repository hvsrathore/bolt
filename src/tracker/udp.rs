/* binary UDP tracker client implementing the BEP-0015 specification */

use crate::tracker::{
    parse_compact_peers_ipv4, AnnounceRequest, AnnounceResponse, TrackerError,
};
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

/* magic 64-bit constant identifying BEP-0015 protocol (0x41727101980) */
pub const MAGIC_CONNECTION_ID: i64 = 0x41727101980;

/* define BEP-0015 action identifier codes */
pub const ACTION_CONNECT: i32 = 0;
pub const ACTION_ANNOUNCE: i32 = 1;
pub const ACTION_SCRAPE: i32 = 2;
pub const ACTION_ERROR: i32 = 3;

/* define UDP packet sizing constants */
pub const CONNECT_REQUEST_SIZE: usize = 16;
pub const CONNECT_RESPONSE_SIZE: usize = 16;
pub const ANNOUNCE_REQUEST_SIZE: usize = 98;
pub const ANNOUNCE_RESPONSE_HEADER_SIZE: usize = 20;

/* binary UDP tracker client for BEP-0015 transactions */
pub struct UdpTrackerClient {
    timeout: Duration,
}

impl Default for UdpTrackerClient {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl UdpTrackerClient {
    /* construct UDP client with configurable socket I/O timeout */
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /* generate pseudo-random 32-bit transaction ID from system time entropy */
    pub fn generate_transaction_id() -> u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0x9e3779b9);

        let mut x = (nanos as u32) ^ ((nanos >> 32) as u32);
        if x == 0 {
            x = 0x85ebca6b;
        }
        /* 32-bit xorshift pseudorandom step */
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    }

    /* construct 16-byte BEP-0015 connect request datagram in big-endian network byte order.
       memory layout:
       - 0..8:  protocol_id (i64, 0x41727101980)
       - 8..12: action (i32, 0 for connect)
       - 12..16: transaction_id (u32) */
    pub fn build_connect_request(transaction_id: u32) -> [u8; CONNECT_REQUEST_SIZE] {
        let mut packet = [0u8; CONNECT_REQUEST_SIZE];
        packet[0..8].copy_from_slice(&MAGIC_CONNECTION_ID.to_be_bytes());
        packet[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        packet[12..16].copy_from_slice(&transaction_id.to_be_bytes());
        packet
    }

    /* parse and validate 16-byte connect response, extracting 64-bit connection_id.
       memory layout:
       - 0..4:  action (i32, must match 0)
       - 4..8:  transaction_id (u32, must match request transaction_id)
       - 8..16: connection_id (i64, active token for subsequent announces) */
    pub fn parse_connect_response(
        response: &[u8],
        expected_transaction_id: u32,
    ) -> Result<i64, TrackerError> {
        /* check if tracker returned an error message packet (action == 3) */
        if Self::is_error_response(response) {
            return Err(Self::parse_error_payload(response));
        }

        if response.len() < CONNECT_RESPONSE_SIZE {
            return Err(TrackerError::InvalidResponse(
                "connect response smaller than 16 bytes",
            ));
        }

        let action = i32::from_be_bytes(
            response[0..4]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );
        let transaction_id = u32::from_be_bytes(
            response[4..8]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );

        if action != ACTION_CONNECT {
            return Err(TrackerError::InvalidAction {
                expected: ACTION_CONNECT,
                received: action,
            });
        }

        if transaction_id != expected_transaction_id {
            return Err(TrackerError::TransactionIdMismatch {
                expected: expected_transaction_id,
                received: transaction_id,
            });
        }

        let connection_id = i64::from_be_bytes(
            response[8..16]
                .try_into()
                .expect("slice length verified to be 8 bytes"),
        );

        Ok(connection_id)
    }

    /* construct 98-byte BEP-0015 announce request datagram in big-endian network byte order.
       memory layout:
       - 0..8:   connection_id (i64)
       - 8..12:  action (i32, 1 for announce)
       - 12..16: transaction_id (u32)
       - 16..36: info_hash (20 bytes)
       - 36..56: peer_id (20 bytes)
       - 56..64: downloaded (u64)
       - 64..72: left (u64)
       - 72..80: uploaded (u64)
       - 80..84: event (i32: 0=none, 1=completed, 2=started, 3=stopped)
       - 84..88: ip_address (u32, 0 default)
       - 88..92: key (u32, client session token)
       - 92..96: num_want (i32, -1 default)
       - 96..98: port (u16) */
    pub fn build_announce_request(
        connection_id: i64,
        transaction_id: u32,
        key: u32,
        req: &AnnounceRequest,
    ) -> [u8; ANNOUNCE_REQUEST_SIZE] {
        let mut packet = [0u8; ANNOUNCE_REQUEST_SIZE];

        packet[0..8].copy_from_slice(&connection_id.to_be_bytes());
        packet[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        packet[12..16].copy_from_slice(&transaction_id.to_be_bytes());
        packet[16..36].copy_from_slice(&req.info_hash);
        packet[36..56].copy_from_slice(&req.peer_id);
        packet[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
        packet[64..72].copy_from_slice(&req.left.to_be_bytes());
        packet[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
        packet[80..84].copy_from_slice(&req.event.to_udp_event_id().to_be_bytes());
        packet[84..88].copy_from_slice(&0u32.to_be_bytes()); /* default IP address */
        packet[88..92].copy_from_slice(&key.to_be_bytes());
        let num_want = req.num_want.unwrap_or(-1);
        packet[92..96].copy_from_slice(&num_want.to_be_bytes());
        packet[96..98].copy_from_slice(&req.port.to_be_bytes());

        packet
    }

    /* parse and validate announce response, extracting metrics and compact 6-byte IPv4 peers.
       memory layout:
       - 0..4:   action (i32, must match 1)
       - 4..8:   transaction_id (u32, must match request transaction_id)
       - 8..12:  interval (u32, announce interval in seconds)
       - 12..16: leechers (u32, incomplete count)
       - 16..20: seeders (u32, complete count)
       - 20..N:  compact 6-byte IPv4 peers */
    pub fn parse_announce_response(
        response: &[u8],
        expected_transaction_id: u32,
    ) -> Result<AnnounceResponse, TrackerError> {
        /* check if tracker returned an error message packet (action == 3) */
        if Self::is_error_response(response) {
            return Err(Self::parse_error_payload(response));
        }

        if response.len() < ANNOUNCE_RESPONSE_HEADER_SIZE {
            return Err(TrackerError::InvalidResponse(
                "announce response header smaller than 20 bytes",
            ));
        }

        let action = i32::from_be_bytes(
            response[0..4]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );
        let transaction_id = u32::from_be_bytes(
            response[4..8]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );

        if action != ACTION_ANNOUNCE {
            return Err(TrackerError::InvalidAction {
                expected: ACTION_ANNOUNCE,
                received: action,
            });
        }

        if transaction_id != expected_transaction_id {
            return Err(TrackerError::TransactionIdMismatch {
                expected: expected_transaction_id,
                received: transaction_id,
            });
        }

        let interval = u32::from_be_bytes(
            response[8..12]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );
        let leechers = u32::from_be_bytes(
            response[12..16]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );
        let seeders = u32::from_be_bytes(
            response[16..20]
                .try_into()
                .expect("slice length verified to be 4 bytes"),
        );

        /* parse binary slice containing compact 6-byte IPv4 addresses and ports */
        let peers_slice = &response[ANNOUNCE_RESPONSE_HEADER_SIZE..];
        let peers = parse_compact_peers_ipv4(peers_slice)?;

        Ok(AnnounceResponse {
            interval,
            seeders,
            leechers,
            peers,
        })
    }

    /* check if incoming packet corresponds to BEP-0015 error action (action == 3) */
    fn is_error_response(response: &[u8]) -> bool {
        if response.len() >= 8 {
            let action = i32::from_be_bytes([
                response[0],
                response[1],
                response[2],
                response[3],
            ]);
            action == ACTION_ERROR
        } else {
            false
        }
    }

    /* extract human-readable error string from BEP-0015 error packet payload */
    fn parse_error_payload(response: &[u8]) -> TrackerError {
        let msg_bytes = &response[8..];
        let message = String::from_utf8_lossy(msg_bytes).to_string();
        TrackerError::TrackerFailure(message)
    }

    /* parse UDP tracker endpoint string, stripping optional 'udp://' prefix and path */
    pub fn parse_endpoint(url: &str) -> Result<String, TrackerError> {
        let trimmed = url.trim();
        let without_proto = if let Some(stripped) = trimmed.strip_prefix("udp://") {
            stripped
        } else {
            trimmed
        };

        /* strip trailing path if present (e.g. /announce) */
        let host_port = match without_proto.find('/') {
            Some(idx) => &without_proto[..idx],
            None => without_proto,
        };

        if host_port.is_empty() {
            return Err(TrackerError::InvalidUrl(url.to_string()));
        }

        Ok(host_port.to_string())
    }

    /* execute complete two-phase BEP-0015 exchange: connect -> announce */
    pub fn announce(
        &self,
        tracker_url: &str,
        req: &AnnounceRequest,
    ) -> Result<AnnounceResponse, TrackerError> {
        let endpoint = Self::parse_endpoint(tracker_url)?;

        /* resolve remote address and bind client UDP socket */
        let remote_addr = endpoint
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| TrackerError::InvalidUrl(format!("failed to resolve {endpoint}")))?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.connect(remote_addr)?;

        /* step 1: send BEP-0015 connect request */
        let connect_tx_id = Self::generate_transaction_id();
        let connect_req = Self::build_connect_request(connect_tx_id);
        socket.send(&connect_req)?;

        let mut connect_buf = [0u8; 64];
        let read_len = socket.recv(&mut connect_buf)?;
        let connection_id =
            Self::parse_connect_response(&connect_buf[..read_len], connect_tx_id)?;

        /* step 2: send BEP-0015 announce request */
        let announce_tx_id = Self::generate_transaction_id();
        let client_key = Self::generate_transaction_id();
        let announce_req =
            Self::build_announce_request(connection_id, announce_tx_id, client_key, req);
        socket.send(&announce_req)?;

        /* buffer large enough for 20-byte header + hundreds of 6-byte peers */
        let mut announce_buf = vec![0u8; 4096];
        let read_len = socket.recv(&mut announce_buf)?;
        Self::parse_announce_response(&announce_buf[..read_len], announce_tx_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker::{AnnounceEvent, Peer};
    use std::net::Ipv4Addr;

    #[test]
    fn test_bep0015_connect_request_wire_format() {
        let tx_id = 0x12345678_u32;
        let packet = UdpTrackerClient::build_connect_request(tx_id);

        /* verify size */
        assert_eq!(packet.len(), 16);

        /* verify protocol_id magic constant 0x41727101980 in big-endian */
        assert_eq!(
            &packet[0..8],
            &[0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80]
        );

        /* verify action == 0 (connect) */
        assert_eq!(&packet[8..12], &[0x00, 0x00, 0x00, 0x00]);

        /* verify transaction_id */
        assert_eq!(&packet[12..16], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_bep0015_connect_response_parsing() {
        let tx_id = 0x99aabbcc_u32;
        let conn_id = 0x0102030405060708_i64;

        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&0_i32.to_be_bytes()); /* action == 0 */
        resp[4..8].copy_from_slice(&tx_id.to_be_bytes()); /* transaction_id */
        resp[8..16].copy_from_slice(&conn_id.to_be_bytes()); /* connection_id */

        let parsed_conn_id =
            UdpTrackerClient::parse_connect_response(&resp, tx_id).expect("parsing failed");
        assert_eq!(parsed_conn_id, conn_id);

        /* transaction ID mismatch must return error */
        assert!(UdpTrackerClient::parse_connect_response(&resp, 0xdeadbeef).is_err());
    }

    #[test]
    fn test_bep0015_announce_request_wire_format() {
        let conn_id = 0x1122334455667788_i64;
        let tx_id = 0x44332211_u32;
        let key = 0xaabbccdd_u32;

        let req = AnnounceRequest {
            info_hash: [0x55; 20],
            peer_id: [0x66; 20],
            port: 6881,
            uploaded: 1024,
            downloaded: 2048,
            left: 4096,
            event: AnnounceEvent::Started,
            num_want: Some(50),
        };

        let packet = UdpTrackerClient::build_announce_request(conn_id, tx_id, key, &req);
        assert_eq!(packet.len(), 98);

        /* verify connection_id */
        assert_eq!(&packet[0..8], &conn_id.to_be_bytes());

        /* verify action == 1 (announce) */
        assert_eq!(&packet[8..12], &1_i32.to_be_bytes());

        /* verify transaction_id */
        assert_eq!(&packet[12..16], &tx_id.to_be_bytes());

        /* verify info_hash and peer_id */
        assert_eq!(&packet[16..36], &[0x55; 20]);
        assert_eq!(&packet[36..56], &[0x66; 20]);

        /* verify downloaded, left, uploaded */
        assert_eq!(&packet[56..64], &2048_u64.to_be_bytes());
        assert_eq!(&packet[64..72], &4096_u64.to_be_bytes());
        assert_eq!(&packet[72..80], &1024_u64.to_be_bytes());

        /* verify event: started == 2 */
        assert_eq!(&packet[80..84], &2_i32.to_be_bytes());

        /* verify key and num_want */
        assert_eq!(&packet[88..92], &key.to_be_bytes());
        assert_eq!(&packet[92..96], &50_i32.to_be_bytes());

        /* verify port 6881 */
        assert_eq!(&packet[96..98], &6881_u16.to_be_bytes());
    }

    #[test]
    fn test_bep0015_announce_response_parsing_with_compact_peers() {
        let tx_id = 0x55667788_u32;
        let mut resp = Vec::new();

        /* action == 1 (announce) */
        resp.extend_from_slice(&1_i32.to_be_bytes());
        /* transaction_id */
        resp.extend_from_slice(&tx_id.to_be_bytes());
        /* interval == 1800 */
        resp.extend_from_slice(&1800_u32.to_be_bytes());
        /* leechers == 5 */
        resp.extend_from_slice(&5_u32.to_be_bytes());
        /* seeders == 12 */
        resp.extend_from_slice(&12_u32.to_be_bytes());

        /* compact peer: 172.16.0.1:51413 */
        resp.extend_from_slice(&[172, 16, 0, 1]);
        resp.extend_from_slice(&51413_u16.to_be_bytes());

        let parsed = UdpTrackerClient::parse_announce_response(&resp, tx_id)
            .expect("announce response parsing failed");

        assert_eq!(parsed.interval, 1800);
        assert_eq!(parsed.leechers, 5);
        assert_eq!(parsed.seeders, 12);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0], Peer {
            ip: Ipv4Addr::new(172, 16, 0, 1),
            port: 51413,
        });
    }

    #[test]
    fn test_bep0015_error_response_handling() {
        let tx_id = 0x11112222_u32;
        let mut resp = Vec::new();

        /* action == 3 (error) */
        resp.extend_from_slice(&3_i32.to_be_bytes());
        resp.extend_from_slice(&tx_id.to_be_bytes());
        resp.extend_from_slice(b"connection limit exceeded");

        let result = UdpTrackerClient::parse_connect_response(&resp, tx_id);
        match result {
            Err(TrackerError::TrackerFailure(msg)) => {
                assert_eq!(msg, "connection limit exceeded");
            }
            other => panic!("expected TrackerFailure error, got: {:?}", other),
        }
    }
}
