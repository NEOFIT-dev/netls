use netls::{Connection, summary, top_connections};

/// Print a per-protocol/state summary of `conns` to stdout (`--summary`).
pub fn print(conns: &[Connection]) {
    let s = summary(conns);
    println!(
        "TCP:  {} (estab {}, listen {}, timewait {}, closewait {}, other {})",
        s.tcp_total, s.tcp_established, s.tcp_listen, s.tcp_timewait, s.tcp_closewait, s.tcp_other
    );
    println!("UDP:  {}", s.udp_total);
    if s.unix_total > 0 {
        println!("Unix: {}", s.unix_total);
    }
    println!("Total: {}", conns.len());
}

/// Print the top `n` processes by connection count to stdout (`--top N`).
pub fn print_top(conns: &[Connection], n: usize) {
    let top = top_connections(conns, n);
    if top.is_empty() {
        println!("No connections found.");
        return;
    }
    println!("{:<6}  PROCESS", "COUNT");
    for (name, count) in &top {
        println!("{count:<6}  {name}");
    }
}
