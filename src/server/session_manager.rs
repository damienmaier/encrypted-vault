use std::collections::HashMap;
use std::time::Instant;
use dryoc::rng;
use crate::data::{Token, TOKEN_LENGTH_BYTES};

pub struct SessionManager {
    sessions: HashMap<Token, Session>,
    timeout: u64,
}

struct Session {
    organization_name: String,
    last_activity_time: Instant,
}

impl SessionManager {
    pub fn new(timeout: u64) -> Self {
        Self { sessions: HashMap::new(), timeout }
    }

    pub fn new_session(&mut self, organization_name: &str) -> Token {
        self.purge_sessions();

        let token = rng::randombytes_buf(TOKEN_LENGTH_BYTES);
        self.sessions.insert(
            token.clone(),
            Session {
                organization_name: organization_name.to_string(),
                last_activity_time: Instant::now(),
            },
        );
        token
    }

    pub fn get_organization_name_from_token(&mut self, token: &Token) -> Option<String> {
        self.purge_sessions();

        Some(self.sessions.get(token)?.organization_name.clone())
    }

    pub fn end_session(&mut self, token: &Token){
        self.sessions.remove(token);
    }

    fn purge_sessions(&mut self) {
        self.sessions.retain(|_, session|
            session.last_activity_time.elapsed().as_secs() < self.timeout);
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;
    use dryoc::rng;
    use crate::data::TOKEN_LENGTH_BYTES;
    use crate::server::session_manager::SessionManager;

    #[test]
    fn tokens() {
        let mut session_manager = SessionManager::new(60);

        let token1 = session_manager.new_session("org1");
        let token2 = session_manager.new_session("org2");
        let token3 = session_manager.new_session("org3");

        assert_eq!(session_manager.get_organization_name_from_token(&token2).unwrap(), "org2");
        assert_eq!(session_manager.get_organization_name_from_token(&token1).unwrap(), "org1");
        assert_eq!(session_manager.get_organization_name_from_token(&token3).unwrap(), "org3");
    }

    #[test]
    fn end_session() {
        let mut session_manager = SessionManager::new(60);

        let token = session_manager.new_session("org");
        session_manager.end_session(&token);
        assert!(session_manager.get_organization_name_from_token(&token).is_none());
    }

    #[test]
    fn timeout() {
        let mut session_manager = SessionManager::new(1);
        let token = session_manager.new_session("org1");
        sleep(Duration::from_secs(2));
        assert!(session_manager.get_organization_name_from_token(&token).is_none());
    }

    #[test]
    fn wrong_token() {
        let mut session_manager = SessionManager::new(60);
        session_manager.new_session("org1");
        session_manager.new_session("org2");
        session_manager.new_session("org3");

        assert!(
            session_manager.get_organization_name_from_token(
                &rng::randombytes_buf(TOKEN_LENGTH_BYTES)
            ).is_none()
        );
    }
}