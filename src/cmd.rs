use crate::error::{Error, Result};
use log::{debug, warn};
use std::process::Command;

#[derive(Clone)]
pub struct CmdBuilder {
    program: String,
    args: Vec<String>,
    dry_run: bool,
}

impl CmdBuilder {
    #[inline]
    pub fn new(program: &str) -> Self {
        CmdBuilder {
            program: program.to_string(),
            args: Vec::new(),
            dry_run: false,
        }
    }

    #[inline]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    #[inline]
    pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    #[inline]
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn execute(&self) -> Result<String> {
        let cmd_str = format!("{} {}", self.program, self.args.join(" "));
        debug!("Executing: {}", cmd_str);

        if self.dry_run {
            Ok(String::new())
        } else {
            let output = Command::new(&self.program)
                .args(&self.args)
                .output()
                .map_err(|e| Error::CommandFailed(e.to_string()))?;

            if !output.status.success() {
                return Err(Error::CommandFailed(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }

            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }
}
