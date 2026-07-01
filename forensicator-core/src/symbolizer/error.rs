use std::fmt;

#[derive(Debug)]
pub enum SymbolizerError {
    Io(std::io::Error),
    PdbParse(String),
    NoSymbols(String),
}

impl fmt::Display for SymbolizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolizerError::Io(e) => write!(f, "I/O error: {e}"),
            SymbolizerError::PdbParse(msg) => write!(f, "PDB parse error: {msg}"),
            SymbolizerError::NoSymbols(name) => {
                write!(f, "no public symbols in PDB for module '{name}'")
            }
        }
    }
}

impl std::error::Error for SymbolizerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SymbolizerError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SymbolizerError {
    fn from(e: std::io::Error) -> Self {
        SymbolizerError::Io(e)
    }
}
