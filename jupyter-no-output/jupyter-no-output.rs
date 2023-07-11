#!/usr/bin/env rust-script
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1.0.*"
//! serde_json = "1.0.*"
//! ```

use std::process::{Command, ExitCode};

use anyhow::{self, bail};
use serde_json::Value;

fn main() -> ExitCode {
    let out = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .expect("git status cmd fail");
    if !out.status.success() {
        println!("git status cmd exited with status {:?}", out.status.code());
        return ExitCode::from(1);
    }

    let out_str = std::str::from_utf8(&out.stdout).expect("non-UTF-8 output from git status");
    for line in out_str.lines() {
        // Only consider lines with first col A or M and ending w/ ".ipynb"
        let ch = line.chars().next().expect("blank line in git output?!?");
        if ch != 'A' && ch != 'M' {
            continue;
        }
        if !line.ends_with(".ipynb") {
            continue;
        }

        let path = &line[3..line.len()];

        if let Err(e) = verify_notebook_file(path) {
            println!("ERROR(git hook) for notebook {:?}: {}", path, e);
            println!("You may be able to fix this by opening the notebook in Jupyter, selecting Kernel->Restart & Clear Output, saving it, and then adding the changes in git");
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}

fn verify_notebook_file(path: &str) -> anyhow::Result<()> {
    let out = Command::new("git")
        .args(["show", &format!(":{}", path)])
        .output()
        .expect("git show cmd fail");
    if !out.status.success() {
        bail!("git show cmd exited with status {:?}", out.status.code());
    }

    // TODO: make this streaming rather than having the whole file in memory at once; the
    // deserialized JSON will still be in memory all at once, so OOM will still be possible but
    // less likely.
    let out_str = std::str::from_utf8(&out.stdout).expect("non-UTF-8 output from git show cmd");
    let v: Value = serde_json::from_str(out_str)?;

    let jup_map = v
        .as_object()
        .expect("Jupyter NB not an object at top level?!?");
    if !jup_map["cells"].is_array() {
        bail!("`cells` top-level key is not an array");
    }

    for (i, cell) in jup_map["cells"].as_array().unwrap().iter().enumerate() {
        if !cell.is_object() {
            bail!("cells[{}] is not an object", i);
        }
        if !cell.as_object().unwrap().contains_key("outputs") {
            continue;
        }
        if !cell["outputs"].is_array() {
            bail!("`outputs` key in cells[{}] is not an array", i);
        }
        let output_vec = cell["outputs"].as_array().unwrap();
        if !output_vec.is_empty() {
            bail!("outputs array for cells[{}] is not empty", i);
        }
    }

    Ok(())
}
