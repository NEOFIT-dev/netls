use anyhow::Result;
use std::collections::HashMap;

use crate::Connection;

/// Group `conns` by `field` (`remote-ip`, `process`, `port`, or `proto`) and
/// print counts per group to stdout.
pub fn print_conns(conns: &[Connection], field: &str) -> Result<()> {
    let valid = ["remote-ip", "process", "port", "proto"];
    if !valid.contains(&field) {
        anyhow::bail!(
            "invalid --group-by value {:?}. Valid values: {}",
            field,
            valid.join(", ")
        );
    }

    let mut groups: HashMap<String, usize> = HashMap::new();
    for c in conns {
        let key = match field {
            "remote-ip" => c
                .remote
                .rsplit_once(':')
                .map_or(c.remote.as_str(), |(ip, _)| ip)
                .to_string(),
            "process" => c.process.clone().unwrap_or_else(|| "-".to_string()),
            "port" => c.local.rsplit_once(':').map_or("*", |(_, p)| p).to_string(),
            "proto" => c.proto.to_string(),
            _ => continue,
        };
        *groups.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<(String, usize)> = groups.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let col_name = match field {
        "remote-ip" => "REMOTE IP",
        "process" => "PROCESS",
        "port" => "PORT",
        "proto" => "PROTO",
        _ => field,
    };
    println!("{:<6}  {}", "COUNT", col_name);
    for (key, count) in &rows {
        println!("{count:<6}  {key}");
    }
    Ok(())
}
