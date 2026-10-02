//! `serve`: a long-running signer. JSON over HTTP at /v1/check and /v1/sign, and MCP (JSON responses,
//! no SSE) at /mcp. Every route but /health needs a bearer token from `[[serve.tokens]]`.

use std::io::Read;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Request, Response};
use zeroize::Zeroizing;

use crate::config::{Config, ServeConfig, TokenConfig};
use crate::engine::{self, Mode, Outcome};
use crate::payload::hex;
use crate::rpc::Rpc;

const MAX_BODY: u64 = 1024 * 1024;
/// Inside compose's 90 s stop grace period; a sign waits at most until its blockhash expires.
const DRAIN_DEADLINE: Duration = Duration::from_secs(80);
const DRAIN_POLL: Duration = Duration::from_millis(100);
const MCP_LATEST: &str = "2025-11-25";
const MCP_VERSIONS: [&str; 3] = [MCP_LATEST, "2025-06-18", "2025-03-26"];

pub fn run(cfg: Config) -> Result<()> {
    let Some(serve) = cfg.serve.as_ref() else {
        bail!("no [serve] section in the config");
    };
    if serve.tokens.is_empty() {
        bail!("no [[serve.tokens]]; create one with `sa-forge-signer token new`");
    }
    let listen = serve.listen.clone();
    let server = tiny_http::Server::http(&listen)
        .map_err(|e| anyhow::anyhow!("listening on {listen}: {e}"))?;
    eprintln!(
        "sa-forge-signer {} serving on {listen}",
        env!("CARGO_PKG_VERSION")
    );
    let server = Arc::new(server);
    // SIGTERM (docker stop) or SIGINT ends the accept loop; running requests then drain.
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let stopper = Arc::clone(&server);
    std::thread::spawn(move || {
        if let Some(sig) = signals.forever().next() {
            eprintln!("signal {sig}: no new requests; draining");
            stopper.unblock();
        }
    });
    let running = serve_on(&server, &Arc::new(cfg));
    let left = drain(running, DRAIN_DEADLINE);
    if left > 0 {
        eprintln!(
            "stopping with {left} request(s) still running; their callers must treat a sign as unknown"
        );
    }
    eprintln!("stopped");
    Ok(())
}

/// One thread per request; signing blocks while it confirms. Returns the threads still running
/// when the accept loop ends.
fn serve_on(server: &tiny_http::Server, cfg: &Arc<Config>) -> Vec<JoinHandle<()>> {
    let mut running: Vec<JoinHandle<()>> = Vec::new();
    for request in server.incoming_requests() {
        running.retain(|h| !h.is_finished());
        let cfg = Arc::clone(cfg);
        running.push(std::thread::spawn(move || handle(&cfg, request)));
    }
    running
}

/// Waits for running requests until `deadline`; returns how many were still running.
fn drain(mut running: Vec<JoinHandle<()>>, deadline: Duration) -> usize {
    let start = Instant::now();
    loop {
        running.retain(|h| !h.is_finished());
        if running.is_empty() || start.elapsed() >= deadline {
            return running.len();
        }
        std::thread::sleep(DRAIN_POLL);
    }
}

struct Reply {
    status: u16,
    body: Option<Value>,
}

const fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: Some(body),
    }
}

fn handle(cfg: &Config, mut request: Request) {
    let path = request
        .url()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    let method = request.method().clone();
    let (r, log) = route(cfg, &mut request, &method, &path);
    eprintln!("{method} {path} -> {} {log}", r.status);
    let text = r.body.map(|b| b.to_string()).unwrap_or_default();
    let mut response = Response::from_string(text).with_status_code(r.status);
    if let Ok(h) = "Content-Type: application/json".parse::<Header>() {
        response.add_header(h);
    }
    let _ = request.respond(response);
}

/// Returns the reply and a short log note (never secrets).
fn route(cfg: &Config, request: &mut Request, method: &Method, path: &str) -> (Reply, String) {
    let Some(serve) = cfg.serve.as_ref() else {
        return (reply(500, json!({"error": "not serving"})), String::new());
    };
    if let Err(e) = check_origin(serve, request) {
        return (reply(403, json!({"error": e})), String::new());
    }
    if (method, path) == (&Method::Get, "/health") {
        return (reply(200, json!({"status": "ok"})), String::new());
    }
    let Some(token) = authenticate(serve, request) else {
        return (
            reply(401, json!({"error": "missing or unknown bearer token"})),
            String::new(),
        );
    };
    let note = format!("token={}", token.name);
    if method != &Method::Post {
        return (reply(405, json!({"error": "use POST"})), note);
    }
    let body = match read_body(request) {
        Ok(b) => b,
        Err(r) => return (r, note),
    };
    let r = match path {
        "/v1/check" => http_engine(cfg, token, &body, false),
        "/v1/sign" => http_engine(cfg, token, &body, true),
        "/mcp" => mcp(cfg, token, &body),
        _ => reply(404, json!({"error": "not found"})),
    };
    (r, note)
}

/// Host and Origin must name an allowed host, so a web page cannot reach the signer (DNS rebinding).
fn check_origin(serve: &ServeConfig, request: &Request) -> Result<(), String> {
    let allowed = |h: &str| {
        serve
            .allowed_hosts
            .iter()
            .any(|a| a.eq_ignore_ascii_case(h))
    };
    let host = header(request, "Host").ok_or("missing Host header")?;
    if !allowed(host_name(&host)) {
        return Err(format!("host {host:?} is not allowed"));
    }
    if let Some(origin) = header(request, "Origin") {
        let authority = origin.split("://").nth(1).unwrap_or_default();
        if !allowed(host_name(authority)) {
            return Err(format!("origin {origin:?} is not allowed"));
        }
    }
    Ok(())
}

/// The host part of `host[:port]` or `[v6]:port`.
fn host_name(authority: &str) -> &str {
    let authority = authority.split('/').next().unwrap_or_default();
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    authority.split(':').next().unwrap_or_default()
}

fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}

fn authenticate<'a>(serve: &'a ServeConfig, request: &Request) -> Option<&'a TokenConfig> {
    let value = Zeroizing::new(header(request, "Authorization")?);
    let token = value.strip_prefix("Bearer ")?;
    token_for(serve, token)
}

pub fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn token_for<'a>(serve: &'a ServeConfig, token: &str) -> Option<&'a TokenConfig> {
    let hash = token_hash(token);
    serve.tokens.iter().find(|t| t.sha256 == hash)
}

fn read_body(request: &mut Request) -> Result<Zeroizing<String>, Reply> {
    let mut body = Zeroizing::new(String::new());
    request
        .as_reader()
        .take(MAX_BODY.saturating_add(1))
        .read_to_string(&mut body)
        .map_err(|e| reply(400, json!({"error": format!("reading the body: {e}")})))?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_BODY {
        return Err(reply(413, json!({"error": "body too large"})));
    }
    Ok(body)
}

/// Arguments shared by the HTTP endpoints and the MCP tools.
fn engine_call(
    cfg: &Config,
    token: &TokenConfig,
    args: &Value,
    sign: bool,
) -> Result<engine::Report> {
    let Some(payload) = args.get("payload").filter(|p| p.is_object()) else {
        bail!("`payload` must be the payload object from a forge-mcp build_* call");
    };
    let text = Zeroizing::new(serde_json::to_string(payload)?);
    let key = args.get("key").and_then(Value::as_str);
    let mode = if sign {
        Mode::Sign {
            intent: args
                .get("intent")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    } else {
        Mode::Check
    };
    engine::execute(cfg, key, &text, &mode, Some(&token.keys)).map(|(report, _, _)| report)
}

fn http_engine(cfg: &Config, token: &TokenConfig, body: &str, sign: bool) -> Reply {
    let args: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return reply(400, json!({"error": format!("body is not JSON: {e}")})),
    };
    match engine_call(cfg, token, &args, sign) {
        Ok(report) => reply(200, serde_json::to_value(report).unwrap_or_default()),
        Err(e) => reply(500, json!({"error": format!("{e:#}")})),
    }
}

fn mcp(cfg: &Config, token: &TokenConfig, body: &str) -> Reply {
    let Ok(msg) = serde_json::from_str::<Value>(body) else {
        return reply(400, rpc_error(&Value::Null, -32700, "parse error"));
    };
    if !msg.is_object() {
        return reply(
            400,
            rpc_error(&Value::Null, -32600, "batches are not supported"),
        );
    }
    // Notifications and responses from the client get no body.
    let Some(id) = msg.get("id").cloned() else {
        return Reply {
            status: 202,
            body: None,
        };
    };
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match msg.get("method").and_then(Value::as_str) {
        Some("initialize") => Ok(initialize(&params)),
        Some("ping") => Ok(json!({})),
        Some("tools/list") => Ok(json!({"tools": tools()})),
        Some("tools/call") => call_tool(cfg, token, &params),
        _ => Err((-32601, "method not found".to_owned())),
    };
    match result {
        Ok(r) => reply(200, json!({"jsonrpc": "2.0", "id": id, "result": r})),
        Err((code, message)) => reply(200, rpc_error(&id, code, &message)),
    }
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked
        .filter(|v| MCP_VERSIONS.contains(v))
        .unwrap_or(MCP_LATEST);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "sa-forge-signer", "version": env!("CARGO_PKG_VERSION")},
        "instructions": "Signs SAGE C4 payloads built by forge-mcp. Pass the payload object from a build_* call unchanged. \
            `check` runs every check and a simulation without signing; `sign` checks, simulates, signs, sends and confirms. \
            The result is a JSON report: act on `outcome` (never resend on `unknown`; rebuild on `expired`).",
    })
}

fn tools() -> Value {
    let payload_args = json!({
        "type": "object",
        "properties": {
            "payload": {"type": "object", "description": "The payload object returned by a forge-mcp build_* call, unchanged."},
            "key": {"type": "string", "description": "Configured key name; default: the key matching the payload's fee payer."},
        },
        "required": ["payload"],
    });
    let mut sign_args = payload_args.clone();
    if let Some(props) = sign_args
        .get_mut("properties")
        .and_then(Value::as_object_mut)
    {
        props.insert(
            "intent".to_owned(),
            json!({"type": "string", "description": "Why this is signed; recorded in the audit log."}),
        );
    }
    json!([
        {"name": "check", "description": "Run every check and a simulation on a payload. Never signs.", "inputSchema": payload_args},
        {"name": "sign", "description": "Check, simulate, sign, send and confirm a payload. Returns the JSON report.", "inputSchema": sign_args},
        {"name": "key_show", "description": "Show a key this token may use: pubkey, class, approval, profile and balance.",
         "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    ])
}

fn call_tool(cfg: &Config, token: &TokenConfig, params: &Value) -> Result<Value, (i64, String)> {
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let name = params.get("name").and_then(Value::as_str);
    let (text, is_error) = match name {
        Some(tool @ ("check" | "sign")) => match engine_call(cfg, token, &args, tool == "sign") {
            Ok(report) => {
                let ok = matches!(report.outcome, Outcome::Ok | Outcome::Confirmed);
                (
                    serde_json::to_string_pretty(&report).unwrap_or_default(),
                    !ok,
                )
            }
            Err(e) => (format!("error: {e:#}"), true),
        },
        Some("key_show") => key_show(cfg, token, &args),
        _ => return Err((-32602, format!("unknown tool {name:?}"))),
    };
    Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
}

fn key_show(cfg: &Config, token: &TokenConfig, args: &Value) -> (String, bool) {
    let name = args.get("name").and_then(Value::as_str).unwrap_or_default();
    if !token.keys.iter().any(|k| k == name) {
        return (format!("error: this token may not use key {name:?}"), true);
    }
    let Ok(key) = cfg.key(name) else {
        return (format!("error: no key {name:?}"), true);
    };
    let balance = Rpc::new(&cfg.rpc_url).balance(&key.pubkey).ok();
    let info = json!({
        "name": key.name,
        "pubkey": key.pubkey.to_string(),
        "class": format!("{:?}", key.class).to_lowercase(),
        "approval": format!("{:?}", key.approval).to_lowercase(),
        "profile": key.profile.map(|p| p.to_string()),
        "balance_lamports": balance,
    });
    (
        serde_json::to_string_pretty(&info).unwrap_or_default(),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve() -> ServeConfig {
        ServeConfig {
            listen: String::new(),
            allowed_hosts: vec!["127.0.0.1".into(), "localhost".into()],
            tokens: vec![TokenConfig {
                name: "t".into(),
                sha256: token_hash("secret"),
                keys: vec!["k".into()],
            }],
        }
    }

    #[test]
    fn host_names() {
        assert_eq!(host_name("127.0.0.1:8790"), "127.0.0.1");
        assert_eq!(host_name("localhost"), "localhost");
        assert_eq!(host_name("[::1]:8790"), "::1");
        assert_eq!(host_name("evil.example:80/x"), "evil.example");
    }

    #[test]
    fn tokens_match_by_hash_only() {
        let s = serve();
        assert_eq!(token_for(&s, "secret").map(|t| t.name.as_str()), Some("t"));
        assert!(token_for(&s, "Secret").is_none());
        assert!(token_for(&s, "").is_none());
    }

    #[test]
    fn initialize_negotiates_the_version() {
        assert_eq!(
            initialize(&json!({"protocolVersion": "2025-06-18"}))["protocolVersion"],
            "2025-06-18"
        );
        assert_eq!(
            initialize(&json!({"protocolVersion": "1999-01-01"}))["protocolVersion"],
            MCP_LATEST
        );
    }

    /// A live server on a random port, with keys `mine` (in the token) and `other` (not).
    fn live(tag: &str) -> (String, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "sa-forge-signer-serve-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[keys.mine]\nclass = \"session\"\npubkey = \"{MINE}\"\n[keys.other]\nclass = \"session\"\npubkey = \"{OTHER}\"\n\
                 [serve]\nlisten = \"127.0.0.1:0\"\n[[serve.tokens]]\nname = \"t\"\nsha256 = \"{}\"\nkeys = [\"mine\"]\n",
                token_hash("secret")
            ),
        )
        .unwrap();
        let cfg = Arc::new(Config::load(&cfg_path, true).unwrap());
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || serve_on(&server, &cfg));
        (format!("http://127.0.0.1:{port}"), dir)
    }

    const MINE: &str = "7JJhMrnvgqxS6MW59QQcr2Ki1NjZ7SrAjST4YtAFE8zR";
    const OTHER: &str = "2vFWMdAXYjEXe1ounwAgm4gP9z4uLBPqjh1P8eDH7gFH";

    fn post(url: &str, token: Option<&str>, host: Option<&str>, body: &Value) -> (u16, String) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut req = agent.post(url);
        if let Some(t) = token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        if let Some(h) = host {
            req = req.header("Host", h);
        }
        let mut resp = req.send_json(body).unwrap();
        (
            resp.status().as_u16(),
            resp.body_mut().read_to_string().unwrap(),
        )
    }

    #[test]
    fn serves_health_auth_and_mcp_over_http() {
        let (base, dir) = live("mcp");
        let mut health = ureq::get(&format!("{base}/health")).call().unwrap();
        assert_eq!(
            health.body_mut().read_to_string().unwrap(),
            r#"{"status":"ok"}"#
        );

        let mcp = format!("{base}/mcp");
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}});
        assert_eq!(post(&mcp, None, None, &init).0, 401);
        assert_eq!(post(&mcp, Some("wrong"), None, &init).0, 401);
        assert_eq!(
            post(&mcp, Some("secret"), Some("evil.example"), &init).0,
            403
        );

        let (status, body) = post(&mcp, Some("secret"), None, &init);
        assert_eq!(status, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(v["result"]["serverInfo"]["name"], "sa-forge-signer");

        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert_eq!(post(&mcp, Some("secret"), None, &note).0, 202);

        let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        let v: Value = serde_json::from_str(&post(&mcp, Some("secret"), None, &list).1).unwrap();
        assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 3);

        let unknown = json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"});
        let v: Value = serde_json::from_str(&post(&mcp, Some("secret"), None, &unknown).1).unwrap();
        assert_eq!(v["error"]["code"], -32601);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_token_cannot_use_another_key() {
        let (base, dir) = live("auth");
        let payload = json!({"version": 1, "summary": "s", "transaction": {"fee_payer": OTHER, "instructions": [
            {"program_id": "ComputeBudget111111111111111111111111111111", "accounts": [], "data": [2, 64, 66, 15, 0]}]}});
        let (status, body) = post(
            &format!("{base}/v1/check"),
            Some("secret"),
            None,
            &json!({"payload": payload}),
        );
        assert_eq!(status, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["failed_check"], "authorized");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn drain_waits_for_running_requests_up_to_the_deadline() {
        let quick = std::thread::spawn(|| std::thread::sleep(Duration::from_millis(50)));
        assert_eq!(drain(vec![quick], Duration::from_secs(5)), 0);
        let slow = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(3)));
        let start = Instant::now();
        assert_eq!(drain(vec![slow], Duration::from_millis(200)), 1);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn unblock_ends_the_accept_loop() {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let stopper = Arc::clone(&server);
        let cfg = Arc::new(
            Config::load(std::path::Path::new("/nonexistent/config.toml"), false).unwrap(),
        );
        let loop_thread = std::thread::spawn(move || serve_on(&server, &cfg).len());
        std::thread::sleep(Duration::from_millis(100));
        stopper.unblock();
        assert_eq!(loop_thread.join().unwrap(), 0);
    }

    #[test]
    fn tools_are_listed_with_schemas() {
        let names: Vec<String> = tools()
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["check", "sign", "key_show"]);
        assert!(tools()[1]["inputSchema"]["properties"]["intent"].is_object());
        assert!(tools()[0]["inputSchema"]["properties"]["intent"].is_null());
    }
}
