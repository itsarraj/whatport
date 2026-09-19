//! Parsing for `/proc/net/tcp` and `/proc/net/tcp6`. Pure and
//! filesystem-free — every function here takes the file's contents as a
//! `&str` and is exercised directly against fixture strings in the unit
//! tests below, no real `/proc` needed to test the decoding logic.
//!
//! Column layout (both files, `tcp` and `tcp6`, only the address field's
//! hex width differs — 8 chars for IPv4, 32 for IPv6):
//!
//! ```text
//!   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//!    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0
//! ```
//!
//! `local_address` is `<hex addr>:<hex port>`; column index 3 (`st`) is
//! the socket state, `0A` = `TCP_LISTEN`; the last relevant column,
//! index 9, is the socket's inode — the key that ties this table back to
//! a process via `<pid>/fd/*` (see `procinfo.rs`).

/// A `LISTEN`-state row whose local port matched what the caller asked
/// for.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenSocket {
    /// Displayable `ip:port` (or `[ipv6]:port`) the socket is bound to.
    pub local_addr: String,
    pub port: u16,
    pub inode: u64,
}

const TCP_LISTEN: u8 = 0x0A;

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Decodes an IPv4 `local_address` field: 8 hex chars, 4 bytes written
/// little-endian (reverse of network byte order) — `"0100007F:1F90"` is
/// `127.0.0.1:8080`, not `1.0.0.127:8080`. This byte order was already
/// empirically confirmed live on this same host by a sibling tool
/// (`netaudit`'s `addr.rs`); reused here as the same known-good decoding,
/// re-implemented rather than shared per this workspace's
/// standalone-crate convention (see `tools/README.md`).
fn decode_ipv4(addr_hex: &str, port_hex: &str) -> Option<(String, u16)> {
    let bytes = hex_to_bytes(addr_hex)?;
    if bytes.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
    Some((format!("{ip}:{port}"), port))
}

/// Decodes an IPv6 `local_address` field: 32 hex chars as 4 words of 4
/// bytes each, bytes reversed *within* each word (word order preserved)
/// — `::1` is `00000000000000000000000001000000`. Same empirically
/// confirmed encoding as `decode_ipv4`'s doc comment references.
fn decode_ipv6(addr_hex: &str, port_hex: &str) -> Option<(String, u16)> {
    let raw = hex_to_bytes(addr_hex)?;
    if raw.len() != 16 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let base = word * 4;
        bytes[base] = raw[base + 3];
        bytes[base + 1] = raw[base + 2];
        bytes[base + 2] = raw[base + 1];
        bytes[base + 3] = raw[base];
    }
    let groups: Vec<String> = bytes
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    Some((format!("[{}]:{port}", groups.join(":")), port))
}

/// Returns every `LISTEN` row in `contents` whose local port equals
/// `port`. Usually zero or one row, but more than one is legitimate:
/// `SO_REUSEPORT` lets multiple independent sockets — and therefore
/// distinct inodes, possibly owned by distinct processes — all bind the
/// exact same port. Malformed/short lines are skipped rather than
/// treated as fatal, matching how this table can contain rows this
/// parser doesn't need to understand (other socket families, kernel
/// version skew in trailing columns).
pub fn parse_listen_sockets_for_port(contents: &str, port: u16, ipv6: bool) -> Vec<ListenSocket> {
    let mut result = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Ok(state) = u8::from_str_radix(fields[3], 16) else {
            continue;
        };
        if state != TCP_LISTEN {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let decoded = if ipv6 {
            decode_ipv6(addr_hex, port_hex)
        } else {
            decode_ipv4(addr_hex, port_hex)
        };
        let Some((local_addr, found_port)) = decoded else {
            continue;
        };
        if found_port != port {
            continue;
        }
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        result.push(ListenSocket {
            local_addr,
            port: found_port,
            inode,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0A00A8C0:C6C4 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn finds_the_listen_row_matching_the_requested_port() {
        // 0x1F90 == 8080
        let sockets = parse_listen_sockets_for_port(FIXTURE_TCP, 8080, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].inode, 111);
        assert_eq!(sockets[0].local_addr, "0.0.0.0:8080");
    }

    #[test]
    fn loopback_bound_port_decodes_the_real_ip() {
        // 0x0050 == 80, "0100007F" -> 127.0.0.1 (verified byte order)
        let sockets = parse_listen_sockets_for_port(FIXTURE_TCP, 80, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_addr, "127.0.0.1:80");
        assert_eq!(sockets[0].inode, 222);
    }

    #[test]
    fn non_listen_state_rows_are_never_matched_even_on_port_match() {
        // row 2 is ESTABLISHED (01) on local port 0x1538 (5432) — must
        // not show up even if asked for port 5432.
        let sockets = parse_listen_sockets_for_port(FIXTURE_TCP, 0x1538, false);
        assert!(sockets.is_empty());
    }

    #[test]
    fn port_with_no_matching_row_returns_empty() {
        assert!(parse_listen_sockets_for_port(FIXTURE_TCP, 9999, false).is_empty());
    }

    #[test]
    fn empty_table_returns_empty() {
        assert!(parse_listen_sockets_for_port("header only\n", 80, false).is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let contents = "header\nnot enough fields\n";
        assert!(parse_listen_sockets_for_port(contents, 80, false).is_empty());
    }

    #[test]
    fn so_reuseport_two_inodes_same_port_are_both_returned() {
        // Two distinct LISTEN rows, same local port 8080, different
        // inodes -- the SO_REUSEPORT case: independent sockets/processes
        // sharing one port.
        let contents = "header\n\
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n\
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n";
        let sockets = parse_listen_sockets_for_port(contents, 8080, false);
        assert_eq!(sockets.len(), 2);
        let inodes: Vec<u64> = sockets.iter().map(|s| s.inode).collect();
        assert!(inodes.contains(&111));
        assert!(inodes.contains(&222));
    }

    #[test]
    fn ipv6_any_address_decodes_and_matches_by_port() {
        let contents = "header\n   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 444 1 0 100 0 0 10 0\n";
        let sockets = parse_listen_sockets_for_port(contents, 8080, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0].local_addr,
            "[0000:0000:0000:0000:0000:0000:0000:0000]:8080"
        );
        assert_eq!(sockets[0].inode, 444);
    }

    #[test]
    fn ipv6_loopback_decodes_the_real_address() {
        // ::1 -> 00000000000000000000000001000000, empirically confirmed
        // encoding (see decode_ipv6's doc comment).
        let contents = "header\n   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0\n";
        let sockets = parse_listen_sockets_for_port(contents, 80, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0].local_addr,
            "[0000:0000:0000:0000:0000:0000:0000:0001]:80"
        );
    }

    #[test]
    fn bad_inode_column_is_skipped_not_fatal() {
        let contents = "header\n   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 not-a-number 1 0 100 0 0 10 0\n";
        assert!(parse_listen_sockets_for_port(contents, 8080, false).is_empty());
    }
}
