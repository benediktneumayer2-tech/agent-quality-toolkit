//! The AQT core as a child process: JSON lines over its stdin and stdout, logs on its stderr.
//! It first writes {"event":"ready","body":{...}}, then answers each {"id","method","path","body"} request
//! with a line carrying the same id. Requests may overlap. EOF on its stdin makes it exit.
//! Other events ({"event":"queue",...}) go to the handler given at the start; it outlives restarts.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::{oneshot, watch};

const READY_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const RESTARTS: u32 = 1;

#[derive(Clone)]
enum State {
    Starting,
    Ready(Value),
    Failed(String),
}

type OnEvent = Box<dyn Fn(&str, &Value) + Send + Sync>;

pub struct Core {
    command: Vec<String>,
    on_event: OnEvent,
    state: watch::Sender<State>,
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Option<Child>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    restarts: AtomicU32,
    stopping: AtomicBool,
}

impl Core {
    pub fn start(command: Vec<String>, on_event: impl Fn(&str, &Value) + Send + Sync + 'static) -> Arc<Core> {
        let core = Arc::new(Core {
            command,
            on_event: Box::new(on_event),
            state: watch::channel(State::Starting).0,
            stdin: Mutex::new(None),
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            restarts: AtomicU32::new(0),
            stopping: AtomicBool::new(false),
        });
        core.spawn();
        core
    }

    pub fn command_line(&self) -> String {
        self.command.join(" ")
    }

    fn spawn(self: &Arc<Self>) {
        let mut command = Command::new(&self.command[0]);
        command.args(&self.command[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.state.send_replace(State::Failed(format!(
                    "could not start the AQT core ({}): {error}",
                    self.command_line()
                )));
                return;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        *self.stdin.lock().unwrap() = child.stdin.take();
        *self.child.lock().unwrap() = Some(child);
        // stderr: passed on to ours; the last lines go into the error shown when the core stops
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let kept = tail.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[aqt core] {line}");
                let mut kept = kept.lock().unwrap();
                if kept.len() == 3 {
                    kept.pop_front();
                }
                kept.push_back(line);
            }
        });
        let core = self.clone();
        thread::spawn(move || {
            core.read(stdout);
            core.exited(&tail);
        });
    }

    fn read(&self, stdout: impl std::io::Read) {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                eprintln!("[aqt core] not a JSON line on stdout: {line:.200}");
                continue;
            };
            if let Some(event) = message.get("event").and_then(Value::as_str) {
                let body = message.get("body").cloned().unwrap_or(Value::Null);
                if event == "ready" {
                    self.state.send_replace(State::Ready(body));
                } else {
                    (self.on_event)(event, &body);
                }
                continue;
            }
            if let Some(id) = message.get("id").and_then(Value::as_str) {
                if let Some(answer) = self.pending.lock().unwrap().remove(id) {
                    let _ = answer.send(message);
                }
            }
        }
    }

    /// stdout closed: the core has stopped. Waiting requests fail; it is restarted once.
    fn exited(self: &Arc<Self>, tail: &Mutex<VecDeque<String>>) {
        self.state.send_replace(State::Starting);
        self.stdin.lock().unwrap().take();
        self.pending.lock().unwrap().clear();
        let child = self.child.lock().unwrap().take();
        let status = child.map(|mut child| child.wait());
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut detail = match &status {
            Some(Ok(status)) => status.to_string(),
            Some(Err(error)) => error.to_string(),
            None => "unknown status".into(),
        };
        if matches!(&status, Some(Ok(s)) if s.code().is_some_and(|code| code != 0)) {
            thread::sleep(Duration::from_millis(100)); // its last stderr lines: the error it ended with
            let lines: Vec<String> = tail.lock().unwrap().iter().cloned().collect();
            if !lines.is_empty() {
                detail = format!("{detail}: {}", lines.join(" / "));
            }
        }
        if self.restarts.fetch_add(1, Ordering::SeqCst) < RESTARTS {
            eprintln!("[aqt desktop] the core stopped ({detail}); starting it again");
            self.spawn();
        } else {
            let message = format!("the AQT core stopped again ({detail}); close and reopen the app");
            eprintln!("[aqt desktop] {message}");
            self.state.send_replace(State::Failed(message));
        }
    }

    /// The body of the core's ready event, once it has started.
    pub async fn ready(&self) -> Result<Value, String> {
        let mut state = self.state.subscribe();
        let state = tokio::time::timeout(READY_TIMEOUT, state.wait_for(|s| !matches!(s, State::Starting)))
            .await
            .map_err(|_| format!("the AQT core did not start within {} s", READY_TIMEOUT.as_secs()))?
            .map(|state| state.clone())
            .map_err(|_| "the AQT core is gone".to_string())?;
        match state {
            State::Ready(body) => Ok(body),
            State::Failed(message) => Err(message),
            State::Starting => unreachable!(),
        }
    }

    /// One request; the answer is the core's whole response line.
    pub async fn request(&self, method: &str, path: &str, body: Value) -> Result<Value, String> {
        if !matches!(method, "GET" | "POST") || !path.starts_with("/api/") {
            return Err(format!("not an API request: {method} {path:.80}"));
        }
        self.ready().await?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst).to_string();
        let (sender, answer) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), sender);
        let line = json!({"id": id, "method": method, "path": path, "body": body}).to_string() + "\n";
        let written = match self.stdin.lock().unwrap().as_mut() {
            Some(stdin) => stdin.write_all(line.as_bytes()).and_then(|_| stdin.flush()).map_err(|e| e.to_string()),
            None => Err("not running".into()),
        };
        if let Err(error) = written {
            self.pending.lock().unwrap().remove(&id);
            return Err(format!("could not reach the AQT core: {error}"));
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, answer).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err("the AQT core stopped before it answered".into()),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(format!("the AQT core did not answer within {} s", REQUEST_TIMEOUT.as_secs()))
            }
        }
    }

    /// App exit: EOF on the core's stdin; killed if it is still there after three seconds.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.stdin.lock().unwrap().take();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut child = self.child.lock().unwrap();
            match child.as_mut().map(|c| c.try_wait()) {
                None | Some(Ok(Some(_))) | Some(Err(_)) => return,
                Some(Ok(None)) if Instant::now() >= deadline => {
                    let _ = child.as_mut().unwrap().kill();
                    return;
                }
                Some(Ok(None)) => {}
            }
            drop(child);
            thread::sleep(Duration::from_millis(50));
        }
    }
}
