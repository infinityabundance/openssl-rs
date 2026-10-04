//! Phase 16.4 — `apps/lib/opt.c`: the `openssl` command option parser.
//!
//! `apps/openssl.c`'s dispatcher hands each command its own `argv`, and every
//! command parses it through this module. The landed surface is the parser's
//! *control* shape — `opt_init`, `opt_next`'s flag/value split (`-name`,
//! `--name`, `-name=value`, `-h` as an alias of `help`, `--` as the
//! end-of-options marker), the "does not take a value"/"needs a value" refusal
//! arms, the rest-argument readers and `opt_check_rest_arg` — which is what the
//! dispatcher and the `help`/`list`/`version` commands 16.4 lands drive.
//!
//! ## Recorded divergences (module header)
//!
//! * **The option identity is the option's name, not its `retval`.** The
//!   authority's `OPTIONS.retval` is a command-local enumerator
//!   (`apps/list.c:1618-1660` and its siblings); it is not an authority ABI and no
//!   two commands share it. The generated [`crate::apps::tables`] carries `name`
//!   and `valtype` — exactly what the option-*list* reader reads
//!   (`apps/list.c:1151-1163`) — so [`OptMatch`] names the matched flag instead of
//!   returning its enumerator. The dispatcher compares names, so the observed
//!   behaviour of every landed command is the authority's.
//! * **Value syntax checking is reduced to the string types.** `opt_next` in the
//!   authority syntax-checks numeric (`p`/`n`/`N`/`l`/`u`/`M`/`U`), directory
//!   (`/`) and format (`c`/`E`/`F`/`f`/`A`/`a`) values through `opt_int`,
//!   `opt_format` and friends. The landed commands (`help`, `list`, `version`)
//!   read only string (`s`) and flag (`-`) options, so the rejected-value arms for
//!   the other types are the boundary rather than an observed value. See
//!   `docs/PHASE-16-SUBPHASES.md` §3.4.
//! * **`opt_help` is not landed.** It formats a whole option table with section
//!   headers and wrapped help text; no landed command calls it, so `-help` on
//!   `help`/`list`/`version` would reach `command not landed` rather than the
//!   authority's table. Recorded here rather than stubbed with a wrong body.
//! * **`opt_set_unknown_name`'s sentinel row is reconstructed, not generated.**
//!   The authority's `dgst`/`ocsp`/`ts` option tables carry a row whose name is
//!   `""` and whose `retval` is the command's digest-arm enumerator
//!   (`apps/dgst.c:102`); `opt_init` records it as the `unknown` slot
//!   (`apps/lib/opt.c:232-237`) and `opt_next` returns it for any unmatched option
//!   (`apps/lib/opt.c:1025-1032`). [`crate::apps::tables`] drops empty-name rows,
//!   so [`Opts::enable_unknown`] reconstructs that one slot: an unmatched option
//!   becomes [`OptMatch::Value`] with the empty name and the unmatched body as its
//!   value, exactly the `OPT_*`/`opt_unknown()` pair those three bodies read. A
//!   second unmatched option answers the authority's `Multiple %s or unknown
//!   options` refusal. No other landed command enables it, so its behaviour is
//!   unchanged.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::tables::Opt;

/// The result of [`Opts::next`], the crate's stand-in for the authority's
/// `OPT_*`/command-enumerator return value. See the module header for why the
/// identity is the name rather than the enumerator.
pub enum OptMatch<'a> {
    /// The command's `-help` flag, including the authority's `-h` alias.
    Help,
    /// A flag that takes no value.
    Flag(&'a str),
    /// A value-taking option and the value it consumed.
    Value(&'a str, String),
    /// The parser's refusal arm: the authority's `opt_printf_stderr` text.
    Error(String),
    /// End of options (`apps/lib/opt.c:892-915`).
    End,
}

/// `apps/lib/opt.c`'s parser state (the file-scope statics at `opt.c:37-47`).
pub struct Opts<'a> {
    opts: &'a [Opt],
    argv: Vec<String>,
    index: usize,
    arg: Option<String>,
    prog: String,
    /// `unknown_name` (`apps/lib/opt.c:44`): the argument `opt_set_unknown_name`
    /// named, or `None` when the command did not call it. `Some` is the authority's
    /// `unknown != NULL` (its table carried the sentinel row).
    unknown_name: Option<&'static str>,
    /// `dunno` (`apps/lib/opt.c:43`): the body of the unmatched option `opt_next`
    /// last returned, read back through `opt_unknown()`.
    dunno: Option<String>,
}

/// `const char *opt_path_end(const char *)` — `apps/lib/opt.c:121-132`, the
/// Linux arm.
fn path_end(filename: &str) -> &str {
    match filename.rfind('/') {
        Some(i) => &filename[i + 1..],
        None => filename,
    }
}

/// `char *opt_progname(const char *argv0)` — `apps/lib/opt.c:134-143`.
pub fn progname(argv0: &str) -> String {
    path_end(argv0).to_string()
}

#[allow(clippy::should_implement_trait)] // `next` mirrors the authority's `opt_next`
impl<'a> Opts<'a> {
    /// `char *opt_init(int ac, char **av, const OPTIONS *o)` — `apps/lib/opt.c:161-240`.
    ///
    /// `argv` is the command's whole `argv` (element 0 is the program name), the
    /// same slice the authority's `main` receives.
    pub fn init(argv: &[String], opts: &'a [Opt]) -> Opts<'a> {
        let prog = argv.first().map(|a| progname(a)).unwrap_or_default();
        Opts {
            opts,
            argv: argv.to_vec(),
            index: 1,
            arg: None,
            prog,
            unknown_name: None,
            dunno: None,
        }
    }

    /// `opt_set_unknown_name(name)` — `apps/lib/opt.c:257-260`. Enables the
    /// unmatched-option arm an option table's empty-name sentinel row would have
    /// selected (see the module header). The three bodies that call the
    /// authority's function (`dgst`, `ocsp`, `ts`) call this instead.
    pub fn enable_unknown(&mut self, name: &'static str) {
        self.unknown_name = Some(name);
    }

    /// `char *opt_unknown(void)` — `apps/lib/opt.c:1051-1054`.
    pub fn unknown(&self) -> Option<&str> {
        self.dunno.as_deref()
    }

    /// `void reset_unknown(void)` — `apps/lib/opt.c:1057-1060`, which `ocsp` calls
    /// before each `-cert`/`-serial` so a digest may precede each of them.
    pub fn reset_unknown(&mut self) {
        self.dunno = None;
    }

    /// The program name `opt_init` derived from `argv[0]`.
    pub fn prog(&self) -> &str {
        &self.prog
    }

    /// `int opt_next(void)` — `apps/lib/opt.c:892-1036`, reduced as the module
    /// header records.
    pub fn next(&mut self) -> OptMatch<'a> {
        self.arg = None;
        if self.index >= self.argv.len() {
            return OptMatch::End;
        }
        let p = self.argv[self.index].clone();
        if !p.starts_with('-') {
            return OptMatch::End;
        }
        self.index += 1;
        if p == "--" {
            return OptMatch::End;
        }
        // `opt.c:917-919`: allow `-name` and `--name`.
        let body = p.trim_start_matches('-');
        let (name, inline) = match body.find('=') {
            Some(i) => (&body[..i], Some(body[i + 1..].to_string())),
            None => (body, None),
        };
        let lookup = if name == "h" { "help" } else { name };
        for o in self.opts {
            if o.name != lookup {
                continue;
            }
            if o.valtype == 0 || o.valtype == b'-' {
                if inline.is_some() {
                    return OptMatch::Error(format!(
                        "{}: Option -{} does not take a value",
                        self.prog, name
                    ));
                }
                return if lookup == "help" {
                    OptMatch::Help
                } else {
                    OptMatch::Flag(o.name)
                };
            }
            let value = match inline {
                Some(v) => v,
                None => {
                    if self.index >= self.argv.len() {
                        return OptMatch::Error(format!(
                            "{}: Option -{} needs a value",
                            self.prog, o.name
                        ));
                    }
                    let v = self.argv[self.index].clone();
                    self.index += 1;
                    v
                }
            };
            self.arg = Some(value.clone());
            return OptMatch::Value(o.name, value);
        }
        // `if (unknown != NULL) { ... dunno = p; return unknown->retval; }` —
        // `apps/lib/opt.c:1025-1032`. The sentinel's `retval` is reconstructed as a
        // `Value` with the empty name, carrying the unmatched body so the command
        // reads it the way it reads `opt_unknown()`.
        if let Some(what) = self.unknown_name {
            if let Some(prev) = &self.dunno {
                return OptMatch::Error(format!(
                    "{}: Multiple {} or unknown options: -{} and -{}",
                    self.prog, what, prev, name
                ));
            }
            self.dunno = Some(name.to_string());
            return OptMatch::Value("", name.to_string());
        }
        OptMatch::Error(format!("{}: Unknown option: -{}", self.prog, name))
    }

    /// `char *opt_arg(void)` — `apps/lib/opt.c:1039-1042`.
    pub fn arg(&self) -> Option<&str> {
        self.arg.as_deref()
    }

    /// `char **opt_rest(void)` — `apps/lib/opt.c:1063-1066`.
    pub fn rest(&self) -> &[String] {
        &self.argv[self.index.min(self.argv.len())..]
    }

    /// `int opt_num_rest(void)` — `apps/lib/opt.c:1069-1077`.
    pub fn num_rest(&self) -> usize {
        self.rest().len()
    }

    /// `int opt_check_rest_arg(const char *expected)` — `apps/lib/opt.c:1079-1102`,
    /// returning the authority's 0/1 and printing its message to stderr.
    pub fn check_rest_arg(&self, expected: Option<&str>) -> bool {
        let first = self.rest().first().map(|s| s.as_str()).unwrap_or("");
        if first.is_empty() {
            if expected.is_none() {
                return true;
            }
            eprintln!(
                "{}: Missing argument: {}",
                self.prog,
                expected.unwrap_or("")
            );
            return false;
        }
        if expected.is_some() {
            let extra = self.rest().get(1).map(|s| s.as_str()).unwrap_or("");
            if extra.is_empty() {
                return true;
            }
            eprintln!(
                "{}: Extra argument after {}: \"{}\"",
                self.prog,
                expected.unwrap_or(""),
                extra
            );
            return false;
        }
        eprintln!("{}: Extra option: \"{}\"", self.prog, first);
        false
    }
}
