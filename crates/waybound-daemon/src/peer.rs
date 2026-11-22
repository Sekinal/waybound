//! Verification of the local process behind a connection to the loopback proxy forwarder.
//!
//! The forwarder injects the upstream proxy credentials into every request it relays, so a
//! connection from an arbitrary local process would let that process use the user's
//! authenticated proxy. Chrome cannot present per-session credentials to a proxy without
//! an auth prompt, so the forwarder instead checks who owns the connecting socket.
//!
//! # Policy per OS
//!
//! - **Linux:** the connecting socket is looked up in `/proc/net/tcp` (then `/proc/net/tcp6`,
//!   for dual-stack clients using IPv4-mapped addresses) by its exact four-tuple, and the
//!   connection is refused unless the socket's owning UID equals the daemon's effective UID
//!   (read from `/proc/self/status`). Rows with inode 0 (orphaned sockets whose owner already
//!   closed them, `TIME_WAIT` mini-sockets) report UID 0 regardless of who created them, so
//!   they count as "not found". Because the kernel reads the table in chunks and can skip a
//!   row whose hash bucket changes mid-read, a miss is retried once after a few
//!   milliseconds. Lookups that still fail (socket gone, `/proc` unreadable) are refused
//!   (fail closed). At startup the forwarder checks that its own listening socket
//!   is visible in `/proc/net/tcp` under its own UID; if it is not (an unusual `/proc`,
//!   gVisor-like sandboxes), enforcement would refuse Chrome too, so the forwarder logs a
//!   warning and runs unrestricted instead.
//!
//!   The UID comparison means little when the daemon runs as root (UID 0: every root
//!   process is admitted, and root can read the credentials anyway) or as the overflow UID
//!   65534 (inside a user namespace every unmapped user's sockets also report 65534). The
//!   check stays on in both cases, but a startup warning says the forwarder is effectively
//!   unrestricted for those users.
//!
//!   Processes running as the *same* user are still allowed. Narrowing further to "the
//!   launched browser or one of its descendants" would require mapping the socket inode to
//!   a PID by scanning `/proc/<pid>/fd`, which fails for Chrome's sandboxed, non-dumpable
//!   child processes (the network service among them), so it cannot be done reliably. It
//!   would also add little: a same-user process can already read the credentials from the
//!   daemon's own `/proc/<pid>/environ` or attach a debugger to it.
//! - **macOS and Windows:** unrestricted. Neither OS exposes socket ownership without either
//!   FFI (`libproc` `proc_pidfdinfo`, `GetExtendedTcpTable`), which this crate forbids, or a
//!   per-connection `lsof`/`netstat` subprocess, which is far too slow for a browser opening
//!   dozens of connections per page. Any local process, under any user, can use the forwarder
//!   there while a session is running.

use std::net::SocketAddr;
use std::sync::Arc;

/// Outcome of checking the process behind a proxy client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDecision {
    /// The connection may use the forwarder.
    Allow,
    /// The connection must be refused; the reason is safe to log (no credentials).
    Deny(String),
}

/// Decides whether the local process behind a proxy client connection may use the forwarder.
pub trait PeerVerifier: Send + Sync {
    /// Checks the client whose socket is bound to `peer` and connected to `local`
    /// (the forwarder's address for this connection).
    fn verify(&self, peer: SocketAddr, local: SocketAddr) -> PeerDecision;
}

/// Accepts every connection. Used where the OS offers no sound check (see the module docs).
pub struct AllowAll;

impl PeerVerifier for AllowAll {
    fn verify(&self, _peer: SocketAddr, _local: SocketAddr) -> PeerDecision {
        PeerDecision::Allow
    }
}

/// Chooses the peer verifier for a forwarder listening on `listen`.
#[cfg(target_os = "linux")]
pub fn platform_verifier(listen: SocketAddr) -> Arc<dyn PeerVerifier> {
    let verifier = match procfs::ProcUidVerifier::for_current_user(std::path::PathBuf::from(
        "/proc",
    )) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "cannot read own uid from /proc; local proxy forwarder is open to every local user"
            );
            return Arc::new(AllowAll);
        }
    };
    match verifier.owns_listener(listen) {
        Ok(true) => {
            if let Some(caveat) = procfs::uid_caveat(verifier.uid()) {
                tracing::warn!(
                    uid = verifier.uid(),
                    "local proxy forwarder is effectively unrestricted: {caveat}"
                );
            } else {
                tracing::debug!(
                    uid = verifier.uid(),
                    "local proxy forwarder restricted to the daemon's user"
                );
            }
            Arc::new(verifier)
        }
        Ok(false) => {
            tracing::warn!(
                "own proxy listener not visible in /proc/net/tcp; local proxy forwarder is open \
                 to every local user"
            );
            Arc::new(AllowAll)
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "cannot read /proc/net/tcp; local proxy forwarder is open to every local user"
            );
            Arc::new(AllowAll)
        }
    }
}

/// Chooses the peer verifier for a forwarder listening on `listen`.
#[cfg(not(target_os = "linux"))]
pub fn platform_verifier(_listen: SocketAddr) -> Arc<dyn PeerVerifier> {
    tracing::debug!(
        "local proxy forwarder cannot verify connecting processes on this OS; any local \
         process can use it"
    );
    Arc::new(AllowAll)
}

/// Linux `/proc/net/tcp` socket-ownership lookup. Pure parsing lives here too so it is
/// unit-tested on every platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod procfs {
    use std::fs::File;
    use std::io::{self, BufRead, BufReader, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use super::{PeerDecision, PeerVerifier};

    /// `TCP_TIME_WAIT`: such entries are kernel mini-sockets reported with UID 0.
    pub const STATE_TIME_WAIT: u8 = 0x06;
    /// `TCP_LISTEN`.
    pub const STATE_LISTEN: u8 = 0x0A;
    /// The kernel's overflow UID, reported for UIDs unmapped in the reader's user namespace.
    pub const OVERFLOW_UID: u32 = 65534;
    /// Pause before re-reading the tables after a miss (see the module docs).
    pub const LOOKUP_RETRY_PAUSE: Duration = Duration::from_millis(5);

    /// Explains why the UID check is not a meaningful boundary for `uid`, if it is not.
    #[must_use]
    pub const fn uid_caveat(uid: u32) -> Option<&'static str> {
        match uid {
            0 => Some(
                "the daemon runs as root, so any root-owned process can use the forwarder; \
                 run waybound as an unprivileged user",
            ),
            OVERFLOW_UID => Some(
                "the daemon runs as the overflow uid 65534, which every user unmapped in this \
                 user namespace shares; run waybound under a mapped uid",
            ),
            _ => None,
        }
    }

    /// One parsed row of `/proc/net/tcp` or `/proc/net/tcp6`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpEntry {
        /// Local address, with IPv4-mapped IPv6 addresses converted to IPv4.
        pub local: SocketAddr,
        /// Remote address, with IPv4-mapped IPv6 addresses converted to IPv4.
        pub remote: SocketAddr,
        /// Kernel TCP state (`st` column).
        pub state: u8,
        /// UID owning the socket.
        pub uid: u32,
        /// Socket inode; 0 for orphaned and `TIME_WAIT` sockets, which have no owner.
        pub inode: u64,
    }

    /// Converts an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4.
    #[must_use]
    pub const fn canonical(addr: SocketAddr) -> SocketAddr {
        SocketAddr::new(addr.ip().to_canonical(), addr.port())
    }

    fn parse_hex_u32(hex: &str) -> Option<u32> {
        if hex.len() != 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    }

    /// Decodes an address column such as `0100007F:1F90` (IPv4) or a 32-digit IPv6 form.
    ///
    /// The kernel prints each 32-bit word of the network-order address as a host-order
    /// integer, so each word is converted back with native byte order. The port is printed
    /// in host order already.
    #[must_use]
    pub fn parse_hex_socket_addr(field: &str) -> Option<SocketAddr> {
        let (addr_hex, port_hex) = field.split_once(':')?;
        if port_hex.len() != 4 || !port_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let ip = match addr_hex.len() {
            8 => IpAddr::V4(Ipv4Addr::from(parse_hex_u32(addr_hex)?.to_ne_bytes())),
            32 => {
                let mut octets = Vec::with_capacity(16);
                for i in 0..4 {
                    let word = addr_hex.get(i * 8..i * 8 + 8)?;
                    octets.extend_from_slice(&parse_hex_u32(word)?.to_ne_bytes());
                }
                let octets: [u8; 16] = octets.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        Some(canonical(SocketAddr::new(ip, port)))
    }

    /// Parses one data row. Returns `None` for the header row and for malformed rows.
    #[must_use]
    pub fn parse_tcp_line(line: &str) -> Option<TcpEntry> {
        let mut fields = line.split_whitespace();
        let slot = fields.next()?;
        if !slot.ends_with(':') {
            return None;
        }
        let local = parse_hex_socket_addr(fields.next()?)?;
        let remote = parse_hex_socket_addr(fields.next()?)?;
        let state_hex = fields.next()?;
        if state_hex.len() != 2 {
            return None;
        }
        let state = u8::from_str_radix(state_hex, 16).ok()?;
        // tx_queue:rx_queue, tr:tm->when, retrnsmt
        let uid_field = fields.nth(3)?;
        if !uid_field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let uid = uid_field.parse().ok()?;
        // timeout, then inode
        let inode_field = fields.nth(1)?;
        if !inode_field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let inode = inode_field.parse().ok()?;
        Some(TcpEntry {
            local,
            remote,
            state,
            uid,
            inode,
        })
    }

    /// Returns the UID of the first owned socket (inode not 0, not `TIME_WAIT`) matching `want`.
    ///
    /// Orphaned sockets (the owning process already closed them) keep their four-tuple but
    /// report UID 0 and inode 0; they are skipped so they can never pass as root-owned.
    ///
    /// # Errors
    ///
    /// Returns any I/O error from reading `reader`.
    pub fn find_uid<R: BufRead>(
        reader: R,
        want: impl Fn(&TcpEntry) -> bool,
    ) -> io::Result<Option<u32>> {
        for line in reader.lines() {
            let line = line?;
            if let Some(entry) = parse_tcp_line(&line)
                && entry.inode != 0
                && entry.state != STATE_TIME_WAIT
                && want(&entry)
            {
                return Ok(Some(entry.uid));
            }
        }
        Ok(None)
    }

    /// Extracts the effective UID from `/proc/<pid>/status` content.
    #[must_use]
    pub fn parse_status_euid(status: &str) -> Option<u32> {
        let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    }

    /// Source of the kernel's TCP socket tables (a seam for tests).
    pub trait TableSource: Send + Sync {
        /// Opens table `name` (`tcp` or `tcp6`); `Ok(None)` if the table does not exist.
        ///
        /// # Errors
        ///
        /// Returns any other I/O error from opening the table.
        fn open(&self, name: &str) -> io::Result<Option<Box<dyn BufRead>>>;
    }

    /// Reads tables from `<root>/net/<name>`.
    pub struct ProcDir(pub PathBuf);

    impl TableSource for ProcDir {
        fn open(&self, name: &str) -> io::Result<Option<Box<dyn BufRead>>> {
            match File::open(self.0.join("net").join(name)) {
                Ok(file) => Ok(Some(Box::new(BufReader::new(file)))),
                Err(err) if err.kind() == ErrorKind::NotFound && name != "tcp" => Ok(None),
                Err(err) => Err(err),
            }
        }
    }

    /// Allows only sockets owned by one UID.
    pub struct ProcUidVerifier {
        source: Box<dyn TableSource>,
        uid: u32,
    }

    impl ProcUidVerifier {
        /// Creates a verifier allowing `uid`, reading tables under `proc_root`.
        #[must_use]
        pub fn new(proc_root: PathBuf, uid: u32) -> Self {
            Self::with_source(Box::new(ProcDir(proc_root)), uid)
        }

        /// Creates a verifier allowing `uid`, reading tables from `source`.
        #[must_use]
        pub fn with_source(source: Box<dyn TableSource>, uid: u32) -> Self {
            Self { source, uid }
        }

        /// Creates a verifier allowing the current process's effective UID.
        ///
        /// # Errors
        ///
        /// Returns an error if `<proc_root>/self/status` is unreadable or has no `Uid:` line.
        pub fn for_current_user(proc_root: PathBuf) -> io::Result<Self> {
            let status = std::fs::read_to_string(proc_root.join("self").join("status"))?;
            let uid = parse_status_euid(&status).ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "no Uid line in /proc/self/status")
            })?;
            Ok(Self::new(proc_root, uid))
        }

        /// The UID this verifier allows.
        #[must_use]
        pub const fn uid(&self) -> u32 {
            self.uid
        }

        /// Searches `tcp`, then `tcp6` (absent when IPv6 is disabled), once.
        fn lookup_once(&self, want: &impl Fn(&TcpEntry) -> bool) -> io::Result<Option<u32>> {
            for name in ["tcp", "tcp6"] {
                if let Some(table) = self.source.open(name)?
                    && let Some(uid) = find_uid(table, want)?
                {
                    return Ok(Some(uid));
                }
            }
            Ok(None)
        }

        /// Like [`Self::lookup_once`], but re-reads once after a miss: the kernel serves the
        /// table in chunks and can skip a row when its hash bucket changes between them.
        fn lookup(&self, want: impl Fn(&TcpEntry) -> bool) -> io::Result<Option<u32>> {
            if let Some(uid) = self.lookup_once(&want)? {
                return Ok(Some(uid));
            }
            thread::sleep(LOOKUP_RETRY_PAUSE);
            self.lookup_once(&want)
        }

        /// Self-test: whether the listening socket on `listen` is visible and owned by us.
        ///
        /// # Errors
        ///
        /// Returns any I/O error from reading the tables.
        pub fn owns_listener(&self, listen: SocketAddr) -> io::Result<bool> {
            let listen = canonical(listen);
            let uid = self.lookup(|e| e.state == STATE_LISTEN && e.local == listen)?;
            Ok(uid == Some(self.uid))
        }
    }

    impl PeerVerifier for ProcUidVerifier {
        fn verify(&self, peer: SocketAddr, local: SocketAddr) -> PeerDecision {
            // The client's own socket is bound to `peer` and connected to `local`; the
            // forwarder's accepted socket is the mirror image and is skipped by this match.
            let (peer, local) = (canonical(peer), canonical(local));
            match self.lookup(|e| e.local == peer && e.remote == local) {
                Ok(Some(uid)) if uid == self.uid => PeerDecision::Allow,
                Ok(Some(uid)) => PeerDecision::Deny(format!(
                    "client socket is owned by uid {uid}, daemon runs as uid {}",
                    self.uid
                )),
                Ok(None) => PeerDecision::Deny("client socket not found in /proc/net".to_owned()),
                Err(err) => PeerDecision::Deny(format!("cannot read /proc/net tables: {err}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use std::io::{self, BufRead};
    use std::sync::atomic::AtomicUsize;

    use super::procfs::{
        OVERFLOW_UID, ProcUidVerifier, STATE_LISTEN, TableSource, TcpEntry, find_uid,
        parse_hex_socket_addr, parse_status_euid, parse_tcp_line, uid_caveat,
    };
    use super::*;

    /// `TCP_ESTABLISHED` in the kernel's `st` column.
    const STATE_ESTABLISHED: u8 = 0x01;
    const LISTEN: &str = "127.0.0.1:41394"; // A1B2
    const CLIENT: &str = "127.0.0.1:50000"; // C350

    // Sample rows in the kernel's format as printed on a little-endian host.
    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    const TCP_LISTEN_ROW: &str = "   0: 0100007F:A1B2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41234 1 0000000000000000 100 0 0 10 0";
    const TCP_CLIENT_ROW: &str = "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0 41240 1 0000000000000000 20 4 30 10 -1";
    const TCP_ACCEPTED_ROW: &str = "   2: 0100007F:A1B2 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 41241 1 0000000000000000 20 4 30 10 -1";
    const TCP_TIME_WAIT_ROW: &str = "   3: 0100007F:C350 0100007F:A1B2 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000";
    const TCP6_HEADER: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    const TCP6_MAPPED_CLIENT_ROW: &str = "   0: 0000000000000000FFFF00000100007F:C351 0000000000000000FFFF00000100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1002        0 41250 1 0000000000000000 20 4 30 10 -1";
    const TCP6_LOOPBACK_ROW: &str = "   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41260 1 0000000000000000 100 0 0 10 0";

    // Rows from a real kernel (captured in a Linux container): a live client socket owned by
    // uid 1234 connected to a forwarder on port 0xB663, and an orphaned socket in FIN_WAIT2
    // whose owner wrote a request and closed it (uid and inode both reported as 0).
    const REAL_CLIENT: &str = "127.0.0.1:54516"; // D4F4
    const REAL_LISTEN: &str = "127.0.0.1:46691"; // B663
    const REAL_ORPHAN: &str = "127.0.0.1:54892"; // D66C
    const REAL_ORPHAN_LISTEN: &str = "127.0.0.1:43697"; // AAB1
    const REAL_CLIENT_ROW: &str = "   7: 0100007F:D4F4 0100007F:B663 01 00000000:00000000 00:00000000 00000000  1234        0 327144 1 0000000000000000 20 4 30 10 -1";
    const REAL_ORPHAN_ROW: &str = "   8: 0100007F:D66C 0100007F:AAB1 05 00000000:00000000 01:00000E9D 00000000     0        0 0 2 0000000000000000 20 4 30 10 -1";

    /// In-memory tables; `tcp` is served empty for the first `misses` reads.
    struct FakeTables {
        tcp: String,
        misses: usize,
        tcp_reads: Arc<AtomicUsize>,
    }

    impl TableSource for FakeTables {
        fn open(&self, name: &str) -> io::Result<Option<Box<dyn BufRead>>> {
            if name != "tcp" {
                return Ok(None);
            }
            let reads = self.tcp_reads.fetch_add(1, Ordering::SeqCst);
            let body = if reads < self.misses {
                TCP_HEADER.to_owned()
            } else {
                self.tcp.clone()
            };
            Ok(Some(Box::new(io::Cursor::new(body.into_bytes()))))
        }
    }

    fn fake_verifier(
        rows: &[&str],
        misses: usize,
        uid: u32,
    ) -> (ProcUidVerifier, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut table = vec![TCP_HEADER];
        table.extend_from_slice(rows);
        let source = FakeTables {
            tcp: table.join("\n"),
            misses,
            tcp_reads: Arc::clone(&reads),
        };
        (ProcUidVerifier::with_source(Box::new(source), uid), reads)
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_real_kernel_rows() {
        assert_eq!(
            parse_tcp_line(REAL_CLIENT_ROW),
            Some(TcpEntry {
                local: addr(REAL_CLIENT),
                remote: addr(REAL_LISTEN),
                state: STATE_ESTABLISHED,
                uid: 1234,
                inode: 327_144,
            })
        );
        assert_eq!(
            parse_tcp_line(REAL_ORPHAN_ROW),
            Some(TcpEntry {
                local: addr(REAL_ORPHAN),
                remote: addr(REAL_ORPHAN_LISTEN),
                state: 0x05,
                uid: 0,
                inode: 0,
            })
        );
    }

    /// An orphaned socket reports uid 0; a daemon running as root must not mistake it for
    /// one of its own and forward the dead client's buffered request.
    #[test]
    #[cfg(target_endian = "little")]
    fn orphaned_socket_is_refused_even_for_root_daemon() {
        for uid in [0, 1234] {
            let (verifier, reads) = fake_verifier(&[REAL_ORPHAN_ROW, REAL_CLIENT_ROW], 0, uid);
            let decision = verifier.verify(addr(REAL_ORPHAN), addr(REAL_ORPHAN_LISTEN));
            assert!(
                matches!(&decision, PeerDecision::Deny(r) if r.contains("not found")),
                "uid {uid}: {decision:?}"
            );
            // A miss is re-read once before refusing.
            assert_eq!(reads.load(Ordering::SeqCst), 2);
        }
        let (verifier, _) = fake_verifier(&[REAL_ORPHAN_ROW, REAL_CLIENT_ROW], 0, 1234);
        assert_eq!(
            verifier.verify(addr(REAL_CLIENT), addr(REAL_LISTEN)),
            PeerDecision::Allow
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn row_skipped_by_one_read_is_found_on_retry() {
        let (verifier, reads) = fake_verifier(&[REAL_CLIENT_ROW], 1, 1234);
        assert_eq!(
            verifier.verify(addr(REAL_CLIENT), addr(REAL_LISTEN)),
            PeerDecision::Allow
        );
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // Only one retry: a row missing from two reads is refused.
        let (verifier, reads) = fake_verifier(&[REAL_CLIENT_ROW], 2, 1234);
        assert!(matches!(
            verifier.verify(addr(REAL_CLIENT), addr(REAL_LISTEN)),
            PeerDecision::Deny(_)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // A hit on the first read does not re-read.
        let (verifier, reads) = fake_verifier(&[REAL_CLIENT_ROW], 0, 1234);
        assert_eq!(
            verifier.verify(addr(REAL_CLIENT), addr(REAL_LISTEN)),
            PeerDecision::Allow
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn root_and_overflow_uid_carry_a_caveat() {
        assert!(uid_caveat(0).is_some_and(|c| c.contains("root")));
        assert!(uid_caveat(OVERFLOW_UID).is_some_and(|c| c.contains("65534")));
        assert_eq!(uid_caveat(1000), None);
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn decodes_ipv4_and_ipv6_address_columns() {
        assert_eq!(parse_hex_socket_addr("0100007F:A1B2"), Some(addr(LISTEN)));
        assert_eq!(
            parse_hex_socket_addr("0101A8C0:0050"),
            Some(addr("192.168.1.1:80"))
        );
        assert_eq!(
            parse_hex_socket_addr("00000000000000000000000001000000:1F90"),
            Some(addr("[::1]:8080"))
        );
        // IPv4-mapped IPv6 is reported as plain IPv4 so it matches the forwarder's view.
        assert_eq!(
            parse_hex_socket_addr("0000000000000000FFFF00000100007F:C351"),
            Some(addr("127.0.0.1:50001"))
        );
        assert_eq!(
            parse_hex_socket_addr("B80D0120000000000000000001000000:01BB"),
            Some(addr("[2001:db8::1]:443"))
        );
    }

    #[test]
    fn rejects_malformed_address_columns() {
        for bad in [
            "",
            "0100007F",
            "0100007F:",
            "0100007F:A1B",
            "0100007F:A1B2C",
            "0100007G:A1B2",
            "+100007F:A1B2",
            "0100007F:+1B2",
            "100007F:A1B2",
            "0000000000000000FFFF00000100007:A1B2",
            "0000000000000000FFFF00000100007Z:A1B2",
        ] {
            assert_eq!(parse_hex_socket_addr(bad), None, "{bad:?}");
        }
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_rows_and_skips_header_and_garbage() {
        assert_eq!(parse_tcp_line(TCP_HEADER), None);
        assert_eq!(parse_tcp_line(TCP6_HEADER), None);
        assert_eq!(
            parse_tcp_line(TCP_CLIENT_ROW),
            Some(TcpEntry {
                local: addr(CLIENT),
                remote: addr(LISTEN),
                state: STATE_ESTABLISHED,
                uid: 1001,
                inode: 41_240,
            })
        );
        assert_eq!(
            parse_tcp_line(TCP_LISTEN_ROW).map(|e| (e.state, e.uid)),
            Some((STATE_LISTEN, 1000))
        );
        assert_eq!(
            parse_tcp_line(TCP6_MAPPED_CLIENT_ROW).map(|e| (e.local, e.remote, e.uid)),
            Some((addr("127.0.0.1:50001"), addr(LISTEN), 1002))
        );
        for bad in [
            "",
            "garbage",
            "   1: 0100007F:C350",
            "   1 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  -1",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  99999999999",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0 abc 1",
            "   1: 0100007F:C350 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0 -5 1",
            "   1: 0100007F:C350 0100007F:A1B2 1 00000000:00000000 00:00000000 00000000  1001",
            "   1: 0100007F:C350 nonsense 01 00000000:00000000 00:00000000 00000000  1001",
        ] {
            assert_eq!(parse_tcp_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn find_uid_matches_exact_tuple_and_ignores_time_wait() {
        let table = [
            TCP_HEADER,
            TCP_TIME_WAIT_ROW,
            "this line is malformed",
            TCP_LISTEN_ROW,
            TCP_ACCEPTED_ROW,
            TCP_CLIENT_ROW,
        ]
        .join("\n");
        let (client, listen) = (addr(CLIENT), addr(LISTEN));
        let found = find_uid(table.as_bytes(), |e| {
            e.local == client && e.remote == listen
        });
        assert_eq!(found.ok(), Some(Some(1001)));
        let missing = find_uid(table.as_bytes(), |e| e.local == addr("127.0.0.1:1"));
        assert_eq!(missing.ok(), Some(None));
    }

    #[test]
    fn parses_effective_uid_from_status() {
        let status = "Name:\twaybound-daemon\nUmask:\t0022\nState:\tS (sleeping)\n\
                      Tgid:\t4242\nPid:\t4242\nPPid:\t1\nUid:\t1000\t1001\t1002\t1003\n\
                      Gid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_euid(status), Some(1001));
        assert_eq!(parse_status_euid("Name:\tx\n"), None);
        assert_eq!(parse_status_euid("Uid:\t1000\n"), None);
        assert_eq!(parse_status_euid("Uid:\tabc\tdef\n"), None);
    }

    /// A throwaway fake `/proc` tree; removed on drop.
    struct FakeProc(PathBuf);

    impl FakeProc {
        fn new(status: &str, tcp: &[&str], tcp6: Option<&[&str]>) -> Option<Self> {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "waybound-fake-proc-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let fake = Self(root);
            fs::create_dir_all(fake.0.join("self")).ok()?;
            fs::create_dir_all(fake.0.join("net")).ok()?;
            fs::write(fake.0.join("self").join("status"), status).ok()?;
            fs::write(fake.0.join("net").join("tcp"), tcp.join("\n")).ok()?;
            if let Some(rows) = tcp6 {
                fs::write(fake.0.join("net").join("tcp6"), rows.join("\n")).ok()?;
            }
            Some(fake)
        }

        fn root(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const STATUS_UID_1000: &str = "Name:\tdaemon\nUid:\t1000\t1000\t1000\t1000\n";

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_verifier_allows_own_user_and_denies_others() {
        let Some(fake) = FakeProc::new(
            STATUS_UID_1000,
            &[TCP_HEADER, TCP_LISTEN_ROW, TCP_CLIENT_ROW, TCP_ACCEPTED_ROW],
            Some(&[TCP6_HEADER, TCP6_LOOPBACK_ROW, TCP6_MAPPED_CLIENT_ROW]),
        ) else {
            return;
        };
        let Ok(verifier) = ProcUidVerifier::for_current_user(fake.root().to_path_buf()) else {
            return;
        };
        assert_eq!(verifier.uid(), 1000);
        assert_eq!(verifier.owns_listener(addr(LISTEN)).ok(), Some(true));
        assert_eq!(
            verifier.owns_listener(addr("127.0.0.1:9")).ok(),
            Some(false)
        );

        // Client socket owned by uid 1001: denied, even though the forwarder's own accepted
        // socket for the same connection (uid 1000) is in the table too.
        let denied = verifier.verify(addr(CLIENT), addr(LISTEN));
        assert!(
            matches!(&denied, PeerDecision::Deny(reason) if reason.contains("uid 1001")),
            "{denied:?}"
        );

        // Dual-stack client found only in tcp6 under a mapped address, owned by uid 1002.
        let mapped = verifier.verify(addr("[::ffff:127.0.0.1]:50001"), addr(LISTEN));
        assert!(matches!(mapped, PeerDecision::Deny(reason) if reason.contains("uid 1002")));

        // Unknown socket (already closed, or not local): fail closed.
        let unknown = verifier.verify(addr("127.0.0.1:1"), addr(LISTEN));
        assert!(matches!(unknown, PeerDecision::Deny(_)));

        let own = ProcUidVerifier::new(fake.root().to_path_buf(), 1001);
        assert_eq!(own.verify(addr(CLIENT), addr(LISTEN)), PeerDecision::Allow);
        let own6 = ProcUidVerifier::new(fake.root().to_path_buf(), 1002);
        assert_eq!(
            own6.verify(addr("127.0.0.1:50001"), addr(LISTEN)),
            PeerDecision::Allow
        );
    }

    #[test]
    fn proc_verifier_fails_closed_without_tables() {
        let Some(fake) = FakeProc::new(STATUS_UID_1000, &[TCP_HEADER], None) else {
            return;
        };
        // Missing tcp6 (IPv6 disabled) is not an error, just no match.
        let verifier = ProcUidVerifier::new(fake.root().to_path_buf(), 1000);
        assert!(matches!(
            verifier.verify(addr(CLIENT), addr(LISTEN)),
            PeerDecision::Deny(_)
        ));
        let missing = ProcUidVerifier::new(fake.root().join("does-not-exist"), 1000);
        assert!(matches!(
            missing.verify(addr(CLIENT), addr(LISTEN)),
            PeerDecision::Deny(reason) if reason.contains("cannot read")
        ));
        assert!(missing.owns_listener(addr(LISTEN)).is_err());
        assert!(ProcUidVerifier::for_current_user(fake.root().join("nope")).is_err());
    }

    #[test]
    fn allow_all_allows() {
        assert_eq!(
            AllowAll.verify(addr(CLIENT), addr(LISTEN)),
            PeerDecision::Allow
        );
    }

    /// On real Linux, a connection from this (same-user) test process is allowed, and the
    /// startup self-test finds the listener.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_proc_allows_connection_from_own_process() {
        use std::net::{TcpListener, TcpStream};

        let Ok(verifier) = ProcUidVerifier::for_current_user(PathBuf::from("/proc")) else {
            return;
        };
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(listen) = listener.local_addr() else {
            return;
        };
        assert_eq!(verifier.owns_listener(listen).ok(), Some(true));
        let Ok(client) = TcpStream::connect(listen) else {
            return;
        };
        let Ok((accepted, peer)) = listener.accept() else {
            return;
        };
        let Ok(local) = accepted.local_addr() else {
            return;
        };
        assert_eq!(peer, client.local_addr().unwrap_or(peer));
        assert_eq!(verifier.verify(peer, local), PeerDecision::Allow);
        let stranger = ProcUidVerifier::new(PathBuf::from("/proc"), verifier.uid() ^ 1);
        assert!(matches!(
            stranger.verify(peer, local),
            PeerDecision::Deny(_)
        ));
    }
}
