use std::io::Write;
use std::process::{Command, Stdio};

const APP: &str = "vt-lens";

pub enum Action {
    Load,
    Save(String),
    Clear,
}

pub enum Outcome {
    Loaded(String),
    Saved,
    Cleared,
}

pub fn perform(provider: &'static str, action: Action) -> Result<Outcome, String> {
    let mut command = Command::new("secret-tool");
    match &action {
        Action::Load => {
            command.arg("lookup");
        }
        Action::Save(_) => {
            command.args(["store", "--label=VT Lens provider key"]);
        }
        Action::Clear => {
            command.arg("clear");
        }
    }
    command.args(["app", APP, "provider", provider]);
    command.stderr(Stdio::null()).stdout(Stdio::piped());
    if matches!(action, Action::Save(_)) {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().map_err(|_| "No se pudo abrir el llavero del sistema".to_string())?;
    if let Action::Save(ref key) = action {
        child.stdin.take().ok_or("No se pudo abrir el llavero del sistema")?
            .write_all(key.as_bytes())
            .map_err(|_| "No se pudo guardar la clave en el llavero".to_string())?;
    }
    let output = child.wait_with_output().map_err(|_| "El llavero no respondió".to_string())?;
    if !output.status.success() {
        return Err("Llavero no disponible o clave no encontrada".to_string());
    }
    match action {
        Action::Load => {
            let key = String::from_utf8(output.stdout).map_err(|_| "La clave del llavero no es texto UTF-8".to_string())?;
            Ok(Outcome::Loaded(key.trim_end_matches(['\r', '\n']).to_string()))
        }
        Action::Save(_) => Ok(Outcome::Saved),
        Action::Clear => Ok(Outcome::Cleared),
    }
}
