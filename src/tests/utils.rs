use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

pub(super) fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}