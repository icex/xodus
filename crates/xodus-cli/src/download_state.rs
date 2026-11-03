// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferestre contributors.
//! Installation ownership and durable progress stored as verified output bytes.
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const INCOMPLETE: &str = ".ferestre-update-incomplete-v1";
const LOCK: &str = ".ferestre-streaming.lock";

fn regular(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.uid() != unsafe { nix::libc::geteuid() } {
        return Err(io::Error::other(
            "Installation state is not a private regular file",
        ));
    }
    Ok(())
}
pub fn incomplete(root: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(root.join(INCOMPLETE)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn open_lock(root: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options.open(root.join(LOCK))?;
    regular(&file)?;
    Ok(file)
}
pub fn writer(root: &Path) -> io::Result<File> {
    let file = open_lock(root, true)?;
    FileExt::try_lock_exclusive(&file).map_err(|_| {
        io::Error::other("This installation is being used by another game or download")
    })?;
    Ok(file)
}
pub fn player(root: &Path) -> io::Result<Option<File>> {
    if incomplete(root)? {
        return Err(io::Error::other(
            "Resume the interrupted update before playing this game",
        ));
    }
    let file = match open_lock(root, true) {
        Ok(file) => Some(file),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match open_lock(root, false) {
                Ok(file) => Some(file),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    if let Some(file) = &file {
        FileExt::try_lock_shared(file).map_err(|_| {
            io::Error::other("Finish the current installation operation before playing")
        })?;
        let flags = rustix::io::fcntl_getfd(file)?;
        rustix::io::fcntl_setfd(file, flags - rustix::io::FdFlags::CLOEXEC)?;
    }
    if incomplete(root)? {
        return Err(io::Error::other(
            "Resume the interrupted update before playing this game",
        ));
    }
    Ok(file)
}
pub fn begin(root: &Path) -> io::Result<()> {
    let path = root.join(INCOMPLETE);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(b"1\n")?;
            file.sync_all()?;
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&path)?;
            regular(&file)?;
        }
        Err(e) => return Err(e),
    }
    File::open(root)?.sync_all()
}
pub fn finish(root: &Path) -> io::Result<()> {
    match fs::remove_file(root.join(INCOMPLETE)) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    File::open(root)?.sync_all()
}
/// Resolve package names component by component. Package-controlled links are
/// refused before creating directories or replacing files outside the library.
pub fn destination(root: &Path, name: &str) -> io::Result<PathBuf> {
    let relative = msixvc::xvd::package_relative_path(name)?;
    if relative.components().next().is_some_and(|p| {
        let name = p.as_os_str().to_string_lossy().to_ascii_lowercase();
        name.starts_with(".ferestre-") || name.starts_with(".xodus-")
    }) {
        return Err(io::Error::other(
            "The package names reserved installation state",
        ));
    }
    let mut path = root.to_path_buf();
    let pieces: Vec<_> = relative.components().collect();
    for (index, piece) in pieces.iter().enumerate() {
        path.push(piece.as_os_str());
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::other("Refusing a link in an installation path"));
            }
            Ok(m) if index + 1 < pieces.len() && !m.is_dir() => {
                return Err(io::Error::other(
                    "An installation parent is not a directory",
                ));
            }
            Ok(m) if index + 1 == pieces.len() && (!m.is_file() || m.nlink() != 1) => {
                return Err(io::Error::other(
                    "Refusing a non-private installation target",
                ));
            }
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if index + 1 < pieces.len() {
                    fs::create_dir(&path)?;
                    File::open(path.parent().unwrap())?.sync_all()?;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}
/// The stage is keyed by package-controlled file identity, not by iteration
/// order. It survives process death; every saved page is reverified on resume.
pub fn partial(root: &Path, name: &str, identity: &[u8]) -> io::Result<(PathBuf, File)> {
    let folder = root.join(".ferestre-transfer");
    match fs::symlink_metadata(&folder) {
        Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
            return Err(io::Error::other("Invalid transfer staging directory"));
        }
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&folder)?;
            File::open(root)?.sync_all()?;
        }
        Err(e) => return Err(e),
    }
    let mut digest = Sha256::new();
    digest.update(name.as_bytes());
    digest.update([0]);
    digest.update(identity);
    let token: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let basename = format!("{token}.part");
    let path = folder.join(basename);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&path)?;
    regular(&file)?;
    File::open(&folder)?.sync_all()?;
    Ok((path, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn barrier_survives_writer_exit_and_prevents_play_until_commit() {
        let t = tempfile::tempdir().unwrap();
        let lock = writer(t.path()).unwrap();
        assert!(player(t.path()).is_err());
        begin(t.path()).unwrap();
        drop(lock);
        assert!(player(t.path()).is_err());
        finish(t.path()).unwrap();
        let game = player(t.path()).unwrap();
        assert!(writer(t.path()).is_err());
        drop(game);
        assert!(writer(t.path()).is_ok());
    }
    #[test]
    fn persistent_stage_is_bound_to_name_and_package_layout() {
        let t = tempfile::tempdir().unwrap();
        let (p, mut f) = partial(t.path(), "Game.dat", b"one").unwrap();
        f.write_all(b"saved data").unwrap();
        f.sync_all().unwrap();
        drop(f);
        assert_eq!(
            partial(t.path(), "Game.dat", b"one")
                .unwrap()
                .1
                .metadata()
                .unwrap()
                .len(),
            10
        );
        assert_ne!(p, partial(t.path(), "Game.dat", b"two").unwrap().0);
        assert_ne!(p, partial(t.path(), "Other.dat", b"one").unwrap().0);
    }
    #[test]
    fn links_and_nonregular_state_cannot_escape_the_destination() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), t.path().join("linked")).unwrap();
        assert!(destination(t.path(), "linked/game.exe").is_err());
        assert!(destination(t.path(), "../escape").is_err());
        assert!(destination(t.path(), ".ferestre-transfer/escape").is_err());
        assert!(destination(t.path(), ".xodus-streaming.msixvc").is_err());
        std::os::unix::fs::symlink(outside.path(), t.path().join(".ferestre-transfer")).unwrap();
        assert!(partial(t.path(), "Game.dat", b"x").is_err());
        std::os::unix::fs::symlink("missing", t.path().join(INCOMPLETE)).unwrap();
        assert!(incomplete(t.path()).unwrap());
        assert!(begin(t.path()).is_err());
    }
}
