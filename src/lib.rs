#![allow(clippy::needless_return)]

use std::cmp;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use grep::printer;
use grep::searcher::Searcher;
use ignore::gitignore::Gitignore;
use ignore::WalkBuilder;
use termcolor::BufferWriter;

#[cfg(test)]
use termcolor::ColorChoice;

mod ignore_info;
mod matcher;

fn predefined_secret_regexes() -> Vec<&'static str> {
    return vec![
        "(?:r|s)k_live_[0-9a-zA-Z]{24}",            // stripe
        "(?:AC[a-z0-9]{32}|SK[a-z0-9]{32})",        // twilio
        "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", // github
        "(?:^|\\W)eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?", // jwt
        "xox(?:a|b|p|o|s|r)-(?:\\d+-)+[a-z0-9]+",   // slack
        "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", // slack webhooks
        "//.+/:_authToken=[A-Za-z0-9-_]+",            // legacy npm
        "npm_[A-Za-z0-9]{36}",                        // modern npm tokens
        "AccountKey=[a-zA-Z0-9+/=]{88}",              // azure storage
        "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}", // sendgrid
        "[0-9a-z]{32}-us[0-9]{1,2}",                  // mailchimp
        r"sq0csp-[0-9A-Za-z\\\-_]{43}",               // square
        "AIzaSy[A-Za-z0-9-_]{33}",                    // gcp api key
        "glpat-[A-Za-z0-9_/-]{20,}",                  // gitlab
        "[A-Za-z]+://[A-Za-z0-9-_.~%]+:([A-Za-z0-9-_.~%]+)@[A-Za-z]+\\.[A-Za-z0-9]+", // URLs with passwords
        // Private keys
        "AGE-SECRET-KEY-[A-Z0-9]{59}", // age secret key
        "-----BEGIN DSA PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN EC PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN OPENSSH PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN RSA PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----(?:$|[^-]{63}[^-]*-----END)",
        "PuTTY-User-Key-File-2",
        "s-s4t2(?:ud|af)-[abcdef0123456789]{64}", // intra42 client secret
        matcher::RANDOM_STRING_REGEX,
    ];
}

fn combined_regex(regexes: &[&str]) -> String {
    let mut combined = String::from("(");
    for secret_regex in regexes {
        if combined.len() > 1 {
            combined.push('|');
        }
        combined.push_str(secret_regex);
    }
    combined.push(')');
    combined
}

pub fn find_secrets(
    paths: &[PathBuf],
    additional_patterns: &[String],
    strict_ignore: bool,
    only_matching: bool,
    writer: BufferWriter,
) -> Result<usize, Box<dyn Error>> {
    let predefined_patterns = predefined_secret_regexes();

    let mut all_patterns: Vec<&str> =
        Vec::with_capacity(predefined_patterns.len() + additional_patterns.len());
    all_patterns.extend(predefined_patterns.iter());
    for p in additional_patterns {
        all_patterns.push(p.as_str());
    }

    let combined = combined_regex(&all_patterns);

    let ignore_info = ignore_info::get_ignore_info()?;

    let matcher = matcher::IgnoringMatcher::new(&combined, ignore_info.ignore_secrets)?;

    let match_count = Arc::new(AtomicUsize::new(0));
    let match_count_result = match_count.clone();

    let bufwtr = Arc::new(writer);

    let mut to_search = Vec::<PathBuf>::new();
    if strict_ignore && ignore_info.ignore_matcher.is_some() {
        let ignore_matcher = ignore_info.ignore_matcher.unwrap();
        for path in paths {
            if !is_ignored(path, &ignore_matcher) {
                to_search.push(path.clone());
            }
        }
    } else {
        for path in paths {
            to_search.push(path.clone());
        }
    }

    if to_search.is_empty() {
        return Ok(0);
    }

    let mut walk_builder = WalkBuilder::new(&to_search[0]);
    for additional_path in &to_search[1..] {
        walk_builder.add(additional_path);
    }
    if ignore_info.ignore_file_path.is_some() {
        walk_builder.add_custom_ignore_filename(ignore_info.ignore_file_path.unwrap());
    }

    let parallel_walker = walk_builder
        .threads(cmp::min(12, num_cpus::get()))
        .build_parallel();

    parallel_walker.run(move || {
        let bufwtr = bufwtr.clone();

        let mut printer_builder = printer::StandardBuilder::new();
        printer_builder.only_matching(only_matching);
        let mut printer = printer_builder.build(bufwtr.buffer());

        let matcher = matcher.clone();
        let mut searcher = Searcher::new();
        let match_count_result = match_count_result.clone();

        Box::new(move |result| {
            let entry = match result {
                Err(err) => {
                    eprintln!("{}", err);
                    return ignore::WalkState::Continue;
                }
                Ok(dent) => {
                    if !dent.file_type().map_or(false, |ft| ft.is_file()) {
                        return ignore::WalkState::Continue;
                    }
                    dent
                }
            };
            printer.get_mut().clear();
            let mut sink = printer.sink_with_path(&matcher, entry.path());
            let result = searcher.search_path(&matcher, entry.path(), &mut sink);
            if sink.match_count() > 0 {
                let match_count_result = match_count_result.clone();
                let file_match_count = sink.match_count() as usize;
                (*match_count_result).fetch_add(file_match_count, Ordering::SeqCst);
            }
            if let Err(err) = result {
                eprintln!("{}: {}", entry.path().display(), err);
            } else if let Err(err) = bufwtr.print(printer.get_mut()) {
                eprintln!("{}: {}", entry.path().display(), err);
            }

            ignore::WalkState::Continue
        })
    });

    Ok(match_count.fetch_max(0, Ordering::SeqCst))
}

fn is_ignored(path: &Path, ignore_matcher: &Gitignore) -> bool {
    if let Some(parent) = path.parent() {
        let parent_ignored = is_ignored(parent, ignore_matcher);
        if parent_ignored {
            return true;
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let is_dir = metadata.is_dir();
        if ignore_matcher.matched(path, is_dir).is_ignore() {
            return true;
        }
    }
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn no_false_positives() {
        let res = find_secrets(
            &[PathBuf::from("test/none")],
            &[],
            false,
            false,
            BufferWriter::stdout(ColorChoice::Never),
        );
        assert_eq!(res.unwrap(), 0)
    }

    #[test]
    fn no_false_negatives() {
        for maybe_entry in fs::read_dir("test/one_per_line").unwrap() {
            let entry = maybe_entry.unwrap();
            let contents = fs::read_to_string(entry.path()).unwrap();
            let res = find_secrets(
                &[entry.path()],
                &[],
                false,
                false,
                BufferWriter::stdout(ColorChoice::Never),
            );
            assert_eq!(
                res.unwrap(),
                contents.matches('\n').count(),
                "{:?}",
                entry.file_name()
            );
        }
        for maybe_entry in fs::read_dir("test/one_per_file").unwrap() {
            let entry = maybe_entry.unwrap();
            let res = find_secrets(
                &[entry.path()],
                &[],
                false,
                false,
                BufferWriter::stdout(ColorChoice::Never),
            );
            assert_eq!(res.unwrap(), 1, "{:?}", entry.file_name());
        }
    }

    #[test]
    fn strict_ignore_works() {
        let res = find_secrets(
            &[PathBuf::from("test")],
            &[],
            true,
            false,
            BufferWriter::stdout(ColorChoice::Never),
        );
        assert_eq!(res.unwrap(), 0);

        let res = find_secrets(
            &[
                PathBuf::from("test/one_per_line/aws"),
                PathBuf::from("test/one_per_line/azure"),
            ],
            &[],
            true,
            false,
            BufferWriter::stdout(ColorChoice::Never),
        );
        assert_eq!(res.unwrap(), 0);
    }
}
