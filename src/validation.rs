pub fn validate_name(name: &str) -> Result<(), ()> {
    if name.len() < 1 || name.len() > 100 || !name.chars().all(|c|c.is_ascii_alphanumeric()){
        Err(())
    } else{
        Ok(())
    }
}