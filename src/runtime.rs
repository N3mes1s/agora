use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::cell::RefCell;
use std::collections::HashMap;

pub fn var(name: &str) -> Option<String> {
    if let Some(value) = test_runtime_lookup(name) {
        return value;
    }

    std::env::var(name).ok()
}

pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = TEST_RUNTIME.with(|state| state.borrow().home.clone()) {
        return Some(home);
    }
    if let Some(Some(home)) = test_runtime_lookup("HOME") {
        return Some(PathBuf::from(home));
    }

    dirs::home_dir()
}

pub fn unix_now() -> u64 {
    if let Some(now) = TEST_RUNTIME.with(|state| state.borrow().now) {
        return now;
    }

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn sleep(duration: Duration) {
    let advanced = TEST_RUNTIME.with(|state| {
        let mut state = state.borrow_mut();
        if !state.sleep_advances_time {
            return false;
        }
        let now = state.now.get_or_insert_with(system_unix_now);
        *now = now.saturating_add(duration.as_secs());
        true
    });
    if advanced {
        return;
    }

    std::thread::sleep(duration);
}

fn system_unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Default)]
struct TestRuntimeState {
    env: HashMap<String, Option<String>>,
    home: Option<PathBuf>,
    now: Option<u64>,
    sleep_advances_time: bool,
}

thread_local! {
    static TEST_RUNTIME: RefCell<TestRuntimeState> = RefCell::new(TestRuntimeState::default());
}

fn test_runtime_lookup(name: &str) -> Option<Option<String>> {
    TEST_RUNTIME.with(|state| state.borrow().env.get(name).cloned())
}

#[derive(Clone, Default)]
pub struct TestRuntime {
    state: TestRuntimeState,
}

impl TestRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        self.state.home = Some(home.clone());
        self.state
            .env
            .insert("HOME".to_string(), Some(home.to_string_lossy().to_string()));
        self
    }

    pub fn var(mut self, name: &str, value: impl Into<String>) -> Self {
        self.state.env.insert(name.to_string(), Some(value.into()));
        self
    }

    pub fn unset_var(mut self, name: &str) -> Self {
        self.state.env.insert(name.to_string(), None);
        self
    }

    pub fn now(mut self, now: u64) -> Self {
        self.state.now = Some(now);
        self
    }

    pub fn advance_sleep(mut self) -> Self {
        self.state.sleep_advances_time = true;
        self
    }

    pub fn install(self) {
        TEST_RUNTIME.with(|state| *state.borrow_mut() = self.state);
    }

    pub fn enter(self) -> TestRuntimeGuard {
        let previous = snapshot();
        TEST_RUNTIME.with(|state| *state.borrow_mut() = self.state);
        TestRuntimeGuard { previous }
    }
}

pub struct TestRuntimeGuard {
    previous: TestRuntimeState,
}

impl Drop for TestRuntimeGuard {
    fn drop(&mut self) {
        TEST_RUNTIME.with(|state| *state.borrow_mut() = self.previous.clone());
    }
}

pub fn clear_test_runtime() {
    TEST_RUNTIME.with(|state| *state.borrow_mut() = TestRuntimeState::default());
}

fn snapshot() -> TestRuntimeState {
    TEST_RUNTIME.with(|state| state.borrow().clone())
}

pub fn spawn_with_current<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let current = snapshot();
    std::thread::spawn(move || {
        TEST_RUNTIME.with(|state| *state.borrow_mut() = current);
        f()
    })
}

#[cfg(test)]
mod tests {
    use super::{TestRuntime, clear_test_runtime, sleep, spawn_with_current, unix_now, var};
    use std::time::Duration;

    #[test]
    fn test_runtime_overrides_env_and_home() {
        let _guard = TestRuntime::new()
            .home("/tmp/agora-runtime-home")
            .var("AGORA_AGENT_ID", "runtime-agent")
            .enter();

        assert_eq!(var("AGORA_AGENT_ID").as_deref(), Some("runtime-agent"));
        assert_eq!(var("HOME").as_deref(), Some("/tmp/agora-runtime-home"));
    }

    #[test]
    fn test_runtime_sleep_can_advance_fake_clock() {
        clear_test_runtime();
        let _guard = TestRuntime::new().now(100).advance_sleep().enter();
        sleep(Duration::from_secs(5));
        assert_eq!(unix_now(), 105);
    }

    #[test]
    fn test_runtime_spawns_with_current_context() {
        let _guard = TestRuntime::new()
            .var("AGORA_AGENT_ID", "runtime-thread")
            .enter();
        let handle = spawn_with_current(|| var("AGORA_AGENT_ID"));
        assert_eq!(handle.join().unwrap().as_deref(), Some("runtime-thread"));
    }
}
