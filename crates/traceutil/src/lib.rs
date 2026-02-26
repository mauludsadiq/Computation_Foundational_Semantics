use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use chrono::Local;

fn ts_compact_utc() -> String {
    Local::now().format("%Y%m%d_%H%M%S").to_string()
}

pub fn run_stamp() -> String {
    ts_compact_utc()
}

pub struct Trace {
    name: String,
    path: PathBuf,
    w: BufWriter<File>,
}

impl Trace {
    pub fn new(out_dir: &Path, run_stamp: &str, name: &str) -> io::Result<Self> {
        fs::create_dir_all(out_dir)?;
        let filename = format!("run_{run_stamp}_{name}.log");
        let path = out_dir.join(filename);
        let f = File::create(&path)?;
        Ok(Self {
            name: name.to_string(),
            path,
            w: BufWriter::new(f),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn banner(&mut self, title: &str) {
        let name = self.name.clone();
        let file = self.path.display().to_string();
        self.line("");
        self.line("============================================================");
        self.kv("TRACE", &name);
        self.kv("TITLE", title);
        self.kv("FILE", &file);
        self.line("============================================================");
        self.line("");
    }

    pub fn section(&mut self, title: &str) {
        self.line("");
        self.line("------------------------------------------------------------");
        self.line(title);
        self.line("------------------------------------------------------------");
    }

    pub fn kv(&mut self, k: &str, v: &str) {
        self.line(&format!("{k}: {v}"));
    }

    pub fn line(&mut self, s: &str) {
        let _ = writeln!(io::stdout(), "{s}");
        let _ = io::stdout().flush();
        let _ = writeln!(self.w, "{s}");
        let _ = self.w.flush();
    }

    pub fn bytes_hex_preview(&mut self, label: &str, bytes: &[u8]) {
        let take = bytes.len().min(64);
        let mut out = String::new();
        for b in &bytes[..take] {
            out.push_str(&format!("{:02x}", b));
        }
        if bytes.len() > take {
            out.push_str("...");
        }
        self.kv(label, &format!("len={} hex64={}", bytes.len(), out));
    }
}
