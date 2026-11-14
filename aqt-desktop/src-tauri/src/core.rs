//! The AQT core as a child process: JSON lines over its stdin and stdout, logs on its stderr.
//! It first writes {"event":"ready","body":{...}}, then answers each {"id","method","path","body"} request
//! with a line carrying the same id. Requests may overlap. EOF on its stdin makes it exit.
//! Other events ({"event":"queue",...}) go to the handler given at the start; it outlives restarts.
//! The handler also gets {"state": "starting" | "ready" | "failed", "failure"?} as the event "connection"
//! whenever the core's state changes.
//!
//! The command is worked out before each start (`Launch::command`): for another machine that is a probe over
//! SSH, which can also find that the core cannot start there. `Launch::failure` words why it stopped.

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

#[derive(Clone)]
enum State {
    Starting,
    Ready(Value),
    Failed(Value), // {"kind", "message", ...}: why the core is not running
}

/// How the core stopped for good: it could not be started, or it ended (exit code, last stderr lines).
pub struct Ended {
    pub command: String,
    pub spawn_error: Option<std::io::Error>,
    pub code: Option<i32>,
    pub status: String,
    pub stderr: Vec<String>,
}

type Resolve = Box<dyn Fn() -> Result<Vec<String>, Value> + Send + Sync>;
type Describe = Box<dyn Fn(&Ended) -> Value + Send + Sync>;

/// What to start and how to word its end. `restarts`: how often it is started again after it stopped.
pub struct Launch {
    pub command: Resolve,
    pub failure: Describe,
    pub restarts: u32,
}

impl Launch {
    /// A core on this computer: the command as given, started again once.
    pub fn local(command: Vec<String>) -> Launch {
        Launch {
            command: Box::new(move || Ok(command.clone())),
            failure: Box::new(|ended| {
                let message = match &ended.spawn_error {
                    Some(error) => format!("could not start the AQT core ({}): {error}", ended.command),
                    None => format!("the AQT core stopped again ({}); close and reopen the app", detail(ended)),
                };
                json!({"kind": "stopped", "message": message})
            }),
            restarts: 1,
        }
    }
}

/// "exit status: 2: <its last stderr lines>"
pub fn detail(ended: &Ended) -> String {
    if ended.stderr.is_empty() {
        ended.status.clone()
    } else {
        format!("{}: {}", ended.status, ended.stderr.join(" / "))
    }
}

/// Why a request got no answer. `sent`: the request had reached the core (or the SSH connection to it), so
/// whatever it asked for may have happened; it is never sent again.
pub struct RequestError {
    pub message: String,
    pub sent: bool,
}

type OnEvent = Box<dyn Fn(&str, &Value) + Send + Sync>;

pub struct Core {
    launch: Launch,
    command: Mutex<String>,
    on_event: OnEvent,
    state: watch::Sender<State>,
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Option<Child>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    restarts: AtomicU32,
    stopping: AtomicBool,
}

/// No console window for a child of the windowed app on Windows (the core, ssh).
pub fn no_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = command;
}

impl Core {
    /// Starts the core in the background; `ready` waits for it.
    pub fn start(launch: Launch, on_event: impl Fn(&str, &Value) + Send + Sync + 'static) -> Arc<Core> {
        let core = Arc::new(Core {
            launch,
            command: Mutex::new(String::new()),
            on_event: Box::new(on_event),
            state: watch::channel(State::Starting).0,
            stdin: Mutex::new(None),
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            restarts: AtomicU32::new(0),
            stopping: AtomicBool::new(false),
        });
        let first = core.clone();
        thread::spawn(move || first.spawn()); // a remote machine is probed first, which takes a moment
        core
    }

    pub fn command_line(&self) -> String {
        self.command.lock().unwrap().clone()
    }

    fn set_state(&self, state: State) {
        let event = match &state {
            State::Starting => json!({"state": "starting"}),
            State::Ready(_) => json!({"state": "ready"}),
            State::Failed(failure) => json!({"state": "failed", "failure": failure}),
        };
        self.state.send_replace(state);
        (self.on_event)("connection", &event);
    }

    /// {"state": "starting" | "ready" | "failed", "failure"?}
    pub fn status(&self) -> Value {
        match &*self.state.borrow() {
            State::Starting => json!({"state": "starting"}),
            State::Ready(_) => json!({"state": "ready"}),
            State::Failed(failure) => json!({"state": "failed", "failure": failure}),
        }
    }

    fn spawn(self: &Arc<Self>) {
        let args = match (self.launch.command)() {
            Ok(args) => args,
            Err(failure) => {
                if !self.stopping.load(Ordering::SeqCst) {
                    eprintln!("[aqt desktop] {}", failure["message"].as_str().unwrap_or("the core cannot start"));
                    self.set_state(State::Failed(failure));
                }
                return;
            }
        };
        *self.command.lock().unwrap() = args.join(" ");
        let mut command = Command::new(&args[0]);
        command.args(&args[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        no_window(&mut command);
        let mut slot = self.child.lock().unwrap(); // held until the child is stored, so that `stop` sees it
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                drop(slot);
                let ended = Ended { command: args.join(" "), spawn_error: Some(error), code: None, status: String::new(), stderr: vec![] };
                self.set_state(State::Failed((self.launch.failure)(&ended)));
                return;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        *self.stdin.lock().unwrap() = child.stdin.take();
        *slot = Some(child);
        drop(slot);
        // stderr: passed on to ours; the last lines go into the error shown when the core stops (not its log of
        // requests, which over SSH would hide ssh's own last words)
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let kept = tail.clone();
        let stderr_done = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[aqt core] {line}");
                if line.starts_with("aqt core GET ") || line.starts_with("aqt core POST ") {
                    continue;
                }
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
            core.exited(&tail, stderr_done);
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
                    self.set_state(State::Ready(body));
                } else if event != "connection" {
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

    /// stdout closed: the core has stopped. Waiting requests fail; it is started again `restarts` times.
    fn exited(self: &Arc<Self>, tail: &Mutex<VecDeque<String>>, stderr_done: thread::JoinHandle<()>) {
        self.stdin.lock().unwrap().take();
        self.pending.lock().unwrap().clear();
        let child = self.child.lock().unwrap().take();
        let status = child.map(|mut child| child.wait());
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        self.set_state(State::Starting);
        // its last stderr lines: the error it ended with (ssh's own error, for a remote machine)
        let deadline = Instant::now() + Duration::from_millis(500);
        while !stderr_done.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let (code, status) = match &status {
            Some(Ok(status)) => (status.code(), status.to_string()),
            Some(Err(error)) => (None, error.to_string()),
            None => (None, "unknown status".into()),
        };
        let stderr: Vec<String> = if code.is_some_and(|code| code != 0) { tail.lock().unwrap().iter().cloned().collect() } else { vec![] };
        let ended = Ended { command: self.command_line(), spawn_error: None, code, status, stderr };
        if self.restarts.fetch_add(1, Ordering::SeqCst) < self.launch.restarts {
            eprintln!("[aqt desktop] the core stopped ({}); starting it again", detail(&ended));
            self.spawn();
        } else {
            let failure = (self.launch.failure)(&ended);
            eprintln!("[aqt desktop] {}", failure["message"].as_str().unwrap_or("the AQT core stopped"));
            self.set_state(State::Failed(failure));
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
            State::Failed(failure) => Err(failure["message"].as_str().unwrap_or("the AQT core is not running").to_string()),
            State::Starting => unreachable!(),
        }
    }

    /// One request; the answer is the core's whole response line.
    pub async fn request(&self, method: &str, path: &str, body: Value) -> Result<Value, RequestError> {
        let unsent = |message: String| RequestError { message, sent: false };
        if !matches!(method, "GET" | "POST") || !path.starts_with("/api/") {
            return Err(unsent(format!("not an API request: {method} {path:.80}")));
        }
        self.ready().await.map_err(unsent)?;
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
            return Err(unsent(format!("could not reach the AQT core: {error}")));
        }
        let sent = |message: String| RequestError { message, sent: true };
        match tokio::time::timeout(REQUEST_TIMEOUT, answer).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(sent("the AQT core stopped before it answered".into())),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(sent(format!("the AQT core did not answer within {} s", REQUEST_TIMEOUT.as_secs())))
            }
        }
    }

    /// App exit or another machine: EOF on the core's stdin; killed if it is still there after three seconds.
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
