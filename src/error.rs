#[derive(Debug, PartialEq)]
pub enum VaultError {
    ServerError,
    FileError,
    ValidationError,
    PasswordNotStrong(Option<String>),
    NotEnoughUsers,
    DocumentNotFound,
    CryptographyError,
    InputError,
}

impl From<&Option<zxcvbn::feedback::Feedback>> for VaultError {
    fn from(feedback_option: &Option<zxcvbn::feedback::Feedback>) -> Self {
        Self::PasswordNotStrong(
            feedback_option.as_ref().map(|feedback| {
                let warning_text = feedback.warning()
                    .map(|warning| warning.to_string() + "\n")
                    .unwrap_or("".to_string());

                let suggestions = feedback.suggestions()
                    .iter()
                    .map(|suggestion| suggestion.to_string())
                    .fold("".to_string(), |suggestion1, suggestion2| format!("{suggestion1}{suggestion2}\n"));

                format!("{warning_text}Suggestions:\n{suggestions}")
            })
        )
    }
}
