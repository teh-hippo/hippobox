pub mod ref_parser;

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Walk the images directory tree, yielding `(repo_path, tag, file_path)` for each
/// stored image JSON file.
pub fn walk_stored_images(images_dir: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut results = Vec::new();
    if !images_dir.exists() {
        return Ok(results);
    }
    let mut stack = vec![images_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(tag) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".json"))
            else {
                continue;
            };
            let repo = path
                .parent()
                .unwrap_or(&dir)
                .strip_prefix(images_dir)
                .map_or_else(|_| String::new(), |r| r.to_string_lossy().to_string());
            results.push((repo, tag.to_string(), path));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let results = walk_stored_images(tmp.path()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn walk_missing_dir() {
        let results = walk_stored_images(Path::new("/nonexistent/path")).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn walk_finds_json_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("registry/repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("latest.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("v1.json"), "{}").unwrap();
        // Non-json file should be ignored.
        std::fs::write(repo_dir.join("notes.txt"), "hi").unwrap();

        let mut results = walk_stored_images(tmp.path()).unwrap();
        results.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "registry/repo");
        assert_eq!(results[0].1, "latest");
        assert_eq!(results[1].1, "v1");
    }
}
