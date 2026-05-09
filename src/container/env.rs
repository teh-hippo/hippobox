//! Container env and argv assembly. Layers user CLI args on top of OCI image
//! `Cmd`/`Entrypoint`/`Env`, with sensible per-OS defaults.

use crate::image::ContainerConfig;
use crate::platform::{Os, Target};
use anyhow::{Result, bail};

pub(super) fn apply_env_overrides(
    mut vars: Vec<String>,
    overrides: &[String],
) -> Result<Vec<String>> {
    for ov in overrides {
        let Some((key, _)) = ov.split_once('=') else {
            bail!("invalid env override {ov:?}, expected KEY=VALUE")
        };
        if key.is_empty() {
            bail!("invalid env override {ov:?}, empty key");
        }
        match env_find_mut(&mut vars, key) {
            Some(existing) => ov.clone_into(existing),
            None => vars.push(ov.clone()),
        }
    }
    Ok(vars)
}

pub(crate) fn env_find_mut<'a>(vars: &'a mut [String], key: &str) -> Option<&'a mut String> {
    vars.iter_mut()
        .find(|v| v.split_once('=').is_some_and(|(k, _)| k == key))
}

pub(crate) fn build_argv(
    cc: Option<&ContainerConfig>,
    user_cmd: Vec<String>,
) -> Result<Vec<String>> {
    let tail = if user_cmd.is_empty() {
        cc.and_then(|c| c.cmd.clone()).unwrap_or_default()
    } else {
        user_cmd
    };
    let argv = match cc.and_then(|c| c.entrypoint.as_deref()) {
        Some(ep) => ep.iter().cloned().chain(tail).collect(),
        None => tail,
    };
    if argv.is_empty() {
        bail!("no CMD or ENTRYPOINT in image config and no command provided");
    }
    Ok(argv)
}

pub(crate) fn build_env_vars(
    cc: Option<&ContainerConfig>,
    user_env: &[String],
    target: &Target,
) -> Result<Vec<String>> {
    let mut env_vars = cc
        .and_then(|c| c.env.as_deref())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_vec())
        .unwrap_or_else(|| match target.os {
            Os::Windows => vec![],
            _ => vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()],
        });
    if target.os != Os::Windows {
        for (key, default) in [("HOME", "/root"), ("TERM", "xterm")] {
            if env_find_mut(&mut env_vars, key).is_none() {
                env_vars.push(format!("{key}={default}"));
            }
        }
    }
    apply_env_overrides(env_vars, user_env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ContainerConfig;
    use crate::platform::Target;

    #[test]
    fn env_overrides_and_find_mut() {
        // env_find_mut lookups
        let mut vars = vec![
            "PATH=/usr/bin".into(),
            "HOME=/root".into(),
            "TERM=xterm".into(),
        ];
        assert_eq!(
            env_find_mut(&mut vars, "HOME").unwrap().as_str(),
            "HOME=/root"
        );
        assert_eq!(
            env_find_mut(&mut vars, "PATH").unwrap().as_str(),
            "PATH=/usr/bin"
        );
        for key in ["MISSING", "PAT", "PATHX"] {
            assert!(env_find_mut(&mut vars, key).is_none());
        }
        assert!(env_find_mut(&mut Vec::<String>::new(), "ANY").is_none());

        // apply_env_overrides
        let ov = apply_env_overrides;
        assert_eq!(
            ov(
                vec!["PATH=/usr/bin".into(), "HOME=/root".into()],
                &["HOME=/home/user".into()]
            )
            .unwrap(),
            vec!["PATH=/usr/bin", "HOME=/home/user"]
        );
        assert_eq!(
            ov(vec!["PATH=/usr/bin".into()], &["FOO=bar".into()]).unwrap(),
            vec!["PATH=/usr/bin", "FOO=bar"]
        );
        assert_eq!(
            ov(vec!["PATH=/usr/bin".into()], &["FOO=a=b=c".into()]).unwrap(),
            vec!["PATH=/usr/bin", "FOO=a=b=c"]
        );
        assert_eq!(ov(vec![], &["EMPTY=".into()]).unwrap(), vec!["EMPTY="]);
        assert_eq!(
            ov(
                vec!["A=1".into(), "B=2".into(), "C=3".into()],
                &["B=new".into(), "D=4".into(), "A=replaced".into()]
            )
            .unwrap(),
            vec!["A=replaced", "B=new", "C=3", "D=4"]
        );
        let orig = vec!["PATH=/usr/bin".into(), "HOME=/root".into()];
        assert_eq!(ov(orig.clone(), &[]).unwrap(), orig);
        assert!(ov(vec![], &["NOEQUALS".into()]).is_err());
        assert!(ov(vec![], &["=value".into()]).is_err());
    }

    #[test]
    fn build_argv_all_cases() {
        let mk = |ep, cmd| ContainerConfig {
            entrypoint: ep,
            cmd,
            ..Default::default()
        };
        // User cmd overrides image CMD
        let cc = mk(None, Some(vec!["default-cmd".into()]));
        assert_eq!(
            build_argv(Some(&cc), vec!["custom".into()]).unwrap(),
            ["custom"]
        );
        // Entrypoint + CMD combined
        let cc = mk(
            Some(vec!["/ep.sh".into()]),
            Some(vec!["a1".into(), "a2".into()]),
        );
        assert_eq!(
            build_argv(Some(&cc), vec![]).unwrap(),
            ["/ep.sh", "a1", "a2"]
        );
        // User cmd replaces CMD but keeps entrypoint
        let cc = mk(Some(vec!["/ep.sh".into()]), Some(vec!["default".into()]));
        assert_eq!(
            build_argv(Some(&cc), vec!["override".into()]).unwrap(),
            ["/ep.sh", "override"]
        );
        // Entrypoint only
        let cc = mk(Some(vec!["/bin/server".into()]), None);
        assert_eq!(build_argv(Some(&cc), vec![]).unwrap(), ["/bin/server"]);
        // CMD only (multi-arg)
        let cc = mk(
            None,
            Some(vec!["/bin/sh".into(), "-c".into(), "echo hi".into()]),
        );
        assert_eq!(
            build_argv(Some(&cc), vec![]).unwrap(),
            ["/bin/sh", "-c", "echo hi"]
        );
        // No image config, user provides command
        assert_eq!(
            build_argv(None, vec!["/bin/bash".into()]).unwrap(),
            ["/bin/bash"]
        );
        // Error: no CMD, no entrypoint, no user command
        let cc = ContainerConfig::default();
        for e in [
            build_argv(Some(&cc), vec![]).unwrap_err(),
            build_argv(None, vec![]).unwrap_err(),
        ] {
            assert!(format!("{e}").contains("no CMD or ENTRYPOINT"));
        }
    }

    #[test]
    fn build_env_vars_all_cases() {
        let linux = Target::parse("linux/amd64").unwrap();
        let win = Target::parse("windows/amd64").unwrap();
        let darwin = Target::parse("darwin/arm64").unwrap();

        // No image config — should get default PATH, HOME, and TERM
        let vars = build_env_vars(None, &[], &linux).unwrap();
        assert!(vars.iter().any(|v| v.starts_with("PATH=")));
        assert!(vars.iter().any(|v| v == "HOME=/root"));
        assert!(vars.iter().any(|v| v == "TERM=xterm"));

        // Windows target — no Linux defaults injected
        assert!(build_env_vars(None, &[], &win).unwrap().is_empty());

        // Darwin target — same defaults as Linux
        let dvars = build_env_vars(None, &[], &darwin).unwrap();
        assert!(dvars.iter().any(|v| v.starts_with("PATH=")));
        assert!(dvars.iter().any(|v| v == "HOME=/root"));

        // Image-provided env is preserved; missing TERM is injected
        let cc = ContainerConfig {
            env: Some(vec![
                "PATH=/custom/bin".into(),
                "HOME=/app".into(),
                "APP_MODE=production".into(),
            ]),
            ..Default::default()
        };
        let vars = build_env_vars(Some(&cc), &[], &linux).unwrap();
        assert!(vars.iter().any(|v| v == "PATH=/custom/bin"));
        assert!(vars.iter().any(|v| v == "HOME=/app"));
        assert!(vars.iter().any(|v| v == "APP_MODE=production"));
        assert!(vars.iter().any(|v| v == "TERM=xterm"));

        // User overrides replace image env
        let cc2 = ContainerConfig {
            env: Some(vec!["PATH=/usr/bin".into(), "FOO=old".into()]),
            ..Default::default()
        };
        let vars =
            build_env_vars(Some(&cc2), &["FOO=new".into(), "BAR=added".into()], &linux).unwrap();
        assert!(vars.iter().any(|v| v == "FOO=new"));
        assert!(vars.iter().any(|v| v == "BAR=added"));
        assert!(!vars.iter().any(|v| v == "FOO=old"));

        // Empty image env falls back to defaults; Windows gets nothing
        let cc3 = ContainerConfig {
            env: Some(vec![]),
            ..Default::default()
        };
        let vars = build_env_vars(Some(&cc3), &[], &linux).unwrap();
        assert!(vars.iter().any(|v| v.starts_with("PATH=/usr/local/")));
        let wvars = build_env_vars(Some(&cc3), &[], &win).unwrap();
        assert!(!wvars.iter().any(|v| v.starts_with("PATH=")));
    }
}
