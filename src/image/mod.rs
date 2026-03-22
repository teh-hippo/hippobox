pub mod manifest;
pub mod ref_parser;

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Walk the images directory tree, yielding `(repo_path, tag, file_path)` for each
/// stored image JSON file.
pub fn walk_stored_images(images_dir: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut results = Vec::new();
    if !images_dir.exists() { return Ok(results); }
    let mut stack = vec![images_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { stack.push(path); continue; }
            let Some(tag) = path.file_name().and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".json")) else { continue };
            let repo = path.parent().unwrap_or(&dir)
                .strip_prefix(images_dir).map_or_else(|_| String::new(), |r| r.to_string_lossy().to_string());
            results.push((repo, tag.to_string(), path));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_stored_images_scenarios() {
        // Missing dir
        assert!(walk_stored_images(Path::new("/nonexistent/path")).unwrap().is_empty());

        // Empty dir
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(walk_stored_images(tmp.path()).unwrap().is_empty());

        // Finds JSON files, ignores non-JSON
        let repo_dir = tmp.path().join("registry/repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("latest.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("v1.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("notes.txt"), "hi").unwrap();

        let mut results = walk_stored_images(tmp.path()).unwrap();
        results.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(results.len(), 2);
        assert_eq!((results[0].0.as_str(), results[0].1.as_str()), ("registry/repo", "latest"));
        assert_eq!(results[1].1, "v1");
    }
}
