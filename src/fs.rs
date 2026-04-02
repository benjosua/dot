use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum ObservedTarget {
    Missing,
    Symlink {
        target: PathBuf,
    },
    File {
        hash: String,
        text: Option<String>,
        mode: u32,
    },
    Directory,
    Unreadable,
}

pub fn inspect_target(path: &Path) -> Result<ObservedTarget> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                let target = match fs::read_link(path) {
                    Ok(target) => target,
                    Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                        return Ok(ObservedTarget::Unreadable);
                    }
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("read symlink target {}", path.display()));
                    }
                };
                return Ok(ObservedTarget::Symlink { target });
            }

            if metadata.is_dir() {
                return Ok(ObservedTarget::Directory);
            }

            let bytes = match fs::read(path) {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    return Ok(ObservedTarget::Unreadable);
                }
                Err(err) => {
                    return Err(err).with_context(|| format!("read file {}", path.display()));
                }
            };
            let hash = hex::encode(Sha256::digest(&bytes));
            let text = String::from_utf8(bytes).ok();
            Ok(ObservedTarget::File {
                hash,
                text,
                mode: metadata.permissions().mode() & 0o7777,
            })
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(ObservedTarget::Missing),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => Ok(ObservedTarget::Unreadable),
        Err(err) => Err(err).with_context(|| format!("inspect {}", path.display())),
    }
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))
}

pub fn create_symlink(link: &Path, source: &Path) -> Result<()> {
    symlink(source, link)
        .with_context(|| format!("create symlink {} -> {}", link.display(), source.display()))
}

pub fn copy_file(source: &Path, target: &Path) -> Result<()> {
    fs::copy(source, target)
        .with_context(|| format!("copy {} -> {}", source.display(), target.display()))?;
    Ok(())
}

pub fn remove_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).with_context(|| format!("remove directory {}", path.display()))
        }
        Ok(_) => fs::remove_file(path).with_context(|| format!("remove file {}", path.display())),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))
}

pub fn parent_requires_privilege(target: &Path) -> bool {
    let mut probe = target.parent();
    while let Some(path) = probe {
        match fs::metadata(path) {
            Ok(_) => return !path_is_writable(path),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                probe = path.parent();
            }
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return true,
            Err(_) => return false,
        }
    }
    false
}

fn path_is_writable(path: &Path) -> bool {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn inspect_target_marks_unreadable_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        fs::write(&path, "hidden").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let observed = inspect_target(&path).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(observed, ObservedTarget::Unreadable));
    }
}
