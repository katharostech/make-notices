use std::{
    collections::HashSet,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Parser;
use license::{Exception, License};
use once_cell::sync::Lazy;
use regex::{bytes::Regex as BytesRegex, Regex};
use serde::ser::SerializeMap;
use spdx::{Expression, LicenseReq, ParseMode};
use std::fmt::Write;

/// Commandline arguments
static ARGS: Lazy<Args> = Lazy::new(Args::parse);
#[derive(Parser)]
struct Args {
    /// The Path to the config
    #[clap(default_value = "notices.toml")]
    config_file: PathBuf,
}

/// Configuration data.
static CONFIG: Lazy<Config> = Lazy::new(|| {
    match (|| -> anyhow::Result<_> {
        if let Ok(config_file) = std::fs::read_to_string(&ARGS.config_file) {
            Ok(toml::de::from_str(&config_file)?)
        } else {
            Ok(Config::default())
        }
    })() {
        Ok(v) => v,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    }
});

#[derive(serde::Deserialize, Default, Debug)]
struct Config {
    /// The licenses that are allowed
    #[serde(deserialize_with = "license_reqs")]
    allowed_licenses: Vec<LicenseReq>,
    #[serde(default)]
    ignore_packages: Vec<String>,
}

fn license_reqs<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<LicenseReq>, D::Error> {
    d.deserialize_seq(LicenseReqVisitor)
}

struct LicenseReqVisitor;
impl<'de> serde::de::Visitor<'de> for LicenseReqVisitor {
    type Value = Vec<LicenseReq>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "An SPDX license requirement specifier")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;
        let mut licenses = Vec::new();
        while let Some(elem) = seq.next_element::<String>()? {
            let expr = Expression::parse_mode(&elem, ParseMode::LAX)
                .map_err(|e| A::Error::custom(e.to_string()))?;
            let mut reqs = expr.requirements();
            licenses.push(reqs.next().unwrap().req.clone());
            if reqs.next().is_some() {
                return Err(A::Error::custom("License must be a single requirement"));
            }
        }
        Ok(licenses)
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Dep {
    name: String,
    package_url: String,
    license_id: String,
    notices: HashSet<String>,
}

#[derive(Default)]
pub struct Notices {
    dependencies: Vec<Dep>,
    licences: Vec<LicenseReq>,
}

impl serde::Serialize for Notices {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;

        let licenses = self.get_license_texts();

        map.serialize_entry("dependencies", &self.dependencies)?;
        map.serialize_entry("licenses", &licenses)?;

        map.end()
    }
}

impl std::fmt::Debug for Notices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notices")
            .field("dependencies", &self.dependencies)
            .field(
                "licences",
                &self
                    .licences
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Notices {
    fn add_license(&mut self, req: LicenseReq) {
        if !self.licences.iter().any(|x| x == &req) {
            self.licences.push(req);
        }
    }

    fn get_license_texts(&self) -> Vec<(String, String)> {
        self.licences
            .iter()
            .map(|x| {
                (x.to_string(), {
                    let mut license_text = x
                        .license
                        .id()
                        .unwrap()
                        .name
                        .parse::<&dyn License>()
                        .unwrap()
                        .text()
                        .to_string();
                    if let Some(exception) = x
                        .exception
                        .map(|x| x.name.parse::<&dyn Exception>().unwrap().text())
                    {
                        write!(license_text, "\n\nWITH EXCEPTION:\n\n{exception}").ok();
                    }
                    license_text
                })
            })
            .collect()
    }
}

fn main() {
    // Initialize the logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = start() {
        log::error!("{e:?}");
        std::process::exit(1);
    }

    log::info!("Done 🎉");
}

fn start() -> anyhow::Result<()> {
    log::debug!("{:?}", *CONFIG);

    // Initialize empty notices
    let mut notices = Notices::default();

    // Collect notices for supported package managers
    cargo::collect_notices(&mut notices).context("Collecting cargo notices failed")?;
    pnpm::collect_notices(&mut notices).context("Collecting pnpm notices failed")?;

    // Create an HTML report
    {
        let notices_html = generate::html(&notices);
        std::fs::write("3rd-party-notices.html", notices_html.as_bytes())?;
    }
    // Create a JSON report
    {
        let notices_json = generate::json(&notices);
        std::fs::write("3rd-party-notices.json", notices_json.as_bytes())?;
    }
    // Create a Markdown report
    {
        let notices_markdown = generate::markdown(&notices);
        std::fs::write("3rd-party-notices.md", notices_markdown.as_bytes())?;
    }

    Ok(())
}

/// Regular expression for copyright filenames to search
static COPYRIGHT_FILE_RE: Lazy<BytesRegex> = Lazy::new(|| {
    BytesRegex::new("(?i)(license.*|copying.*|readme.*|copyright.*|notice.*)").unwrap()
});

/// Regex for matching on copyright statements
static COPYRIGHT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)copyright.*(©|\(c\)).*$").unwrap());

/// Regex to help rule out false positives for copyright statements
static NOT_COPYRIGHT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?i)(year|notice|holder|owner|interest|yyyy)").unwrap());

/// Get all of the copyright notices
fn scan_for_notices(out: &mut HashSet<String>, path: &Path) -> anyhow::Result<()> {
    // Add NOTICE file contents in accordance with Apache-2.0 license
    let notice_path = path.join("NOTICE");
    if notice_path.exists() {
        let text = std::fs::read_to_string(&notice_path)
            .context(format!("Could not read file {notice_path:?}"))?;
        out.insert(text);
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;

        if entry.file_type()?.is_file() && COPYRIGHT_FILE_RE.is_match(entry.file_name().as_bytes())
        {
            let file = std::fs::read_to_string(entry.path())?;
            let matches = COPYRIGHT_RE.find_iter(&file);
            for m in matches {
                let s = m.as_str();
                if !NOT_COPYRIGHT_RE.is_match(s) {
                    out.insert(s.into());
                }
            }
        }
    }

    Ok(())
}

fn handle_package_license(license: &str, notices: &mut Notices) -> anyhow::Result<()> {
    // Get the package license
    let license_expr = Expression::parse_mode(license, ParseMode::LAX)?;

    // Validate license is allowed
    license_expr
                .evaluate_with_failures(|req| CONFIG.allowed_licenses.iter().any(|x| x == req))
                .map_err(|failed_licenses| {
                    let mut msg =
                        String::from("None of the following licenses were allowed in the `allowed_licenses` configuration: ");
                    let len = failed_licenses.len();
                    for (i, lic) in failed_licenses.into_iter().enumerate() {
                        write!(msg, "{}{}", lic.req, if i != len - 1 { ", " } else { "" }).ok();
                    }
                    anyhow::format_err!(msg)
                })?;

    for req in license_expr.requirements() {
        let req = req.req.clone();
        notices.add_license(req);
    }

    Ok(())
}

mod cargo {
    use cargo_metadata::MetadataCommand;

    use super::*;

    pub fn collect_notices(notices: &mut Notices) -> anyhow::Result<()> {
        let metadata = MetadataCommand::new()
            .verbose(true)
            .exec()
            .context("Running `cargo metadata` failed")?;

        // TODO: filter out build/dev dependencies and dependencies not associated to the desired
        // target.

        // Iterate over packages
        let packages = metadata
            .packages
            .into_iter()
            // Exclude local packages
            .filter(|x| x.source.is_some());

        for package in packages {
            let source = package.source.unwrap();
            let name = package.name;
            if CONFIG.ignore_packages.contains(&name) {
                continue;
            }
            let version = package.version;
            let license = package
                .license
                .ok_or_else(|| anyhow::format_err!("Package {name} does not have a license"))?;

            // Make sure the crate is from crates.io
            let package_url = if source.is_crates_io() {
                format!("https://crates.io/crates/{name}/{version}")
            } else {
                source.repr.clone()
            };

            handle_package_license(&license, notices)?;

            // Scan the package for copyright notices
            let dep_notices = {
                let mut out = HashSet::default();
                let package_path = package.manifest_path.parent().unwrap();

                // Add authors from the crate metadata
                if !package.authors.is_empty() {
                    out.insert(format!("Authors: {}", package.authors.join(", ")));
                }

                scan_for_notices(&mut out, package_path.as_ref())?;

                out
            };

            notices.dependencies.push(Dep {
                package_url,
                name,
                license_id: license,
                notices: dep_notices,
            });
        }

        Ok(())
    }
}

mod pnpm {
    use std::{collections::HashMap, process::Command};

    use super::*;

    #[derive(serde::Deserialize)]
    struct PnpmListItem {
        dependencies: HashMap<String, PnpmListDep>,
        #[serde(rename = "devDependencies")]
        dev_dependencies: HashMap<String, PnpmListDep>,
    }

    #[derive(serde::Deserialize)]
    struct PnpmListDep {
        path: PathBuf,
    }

    #[derive(serde::Deserialize)]
    struct PackageJson {
        name: String,
        version: String,
        license: Option<String>,
    }

    pub fn collect_notices(notices: &mut Notices) -> anyhow::Result<()> {
        if !Path::new("pnpm-lock.yaml").exists() {
            log::info!("Skipping pnpm packages because lockfile not found");
            return Ok(());
        }

        let cmd_out = Command::new("pnpm").arg("list").arg("--json").output()?;
        if !cmd_out.status.success() {
            anyhow::bail!("Error running `pnpm list`");
        }
        let pnpm_list: Vec<PnpmListItem> =
            serde_json::from_slice(&cmd_out.stdout).context("Error parsing pnpm list output")?;

        for pkg in pnpm_list {
            for (_, item) in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
                let package_json_path = item.path.join("package.json");
                let package: PackageJson = serde_json::from_reader(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(package_json_path)?,
                )?;
                let name = package.name;
                let version = package.version;

                if CONFIG.ignore_packages.contains(&name) {
                    continue;
                }

                let license = package
                    .license
                    .ok_or_else(|| anyhow::format_err!("Package {name} doesn't have a license"))?;

                handle_package_license(&license, notices)?;

                let mut dep_notices = HashSet::default();
                scan_for_notices(&mut dep_notices, &item.path)?;

                notices.dependencies.push(Dep {
                    package_url: format!("https://www.npmjs.com/package/{name}/v/{version}"),
                    name,
                    license_id: license,
                    notices: dep_notices,
                });
            }
        }

        Ok(())
    }
}

mod generate {
    use super::*;

    pub fn html(notices: &Notices) -> String {
        let mut out = String::new();

        writeln!(out, "<html>").ok();
        writeln!(out, "<head>").ok();
        writeln!(
            out,
            r"<style>
                table {{
                    border-collapse: collapse;
                }}
                a {{
                    color: hsl(200, 40%, 50%);
                }}
                body {{
                    padding: 1em;
                    color: hsl(0, 0%, 80%) !important;
                    background: hsl(0, 0%, 15%);
                }}
                td {{
                    border-bottom: 1px solid hsl(0, 0%, 20%);
                    padding: 4px;
                }}
                pre {{
                    margin: 2em;
                    background: hsl(0, 0%, 20%);
                    padding: 2em;
                }}
            </style>"
        )
        .ok();
        writeln!(out, "</head>").ok();
        writeln!(out, "<body>").ok();
        writeln!(out, "<h1>3rd Party Notices</h1>").ok();

        writeln!(out, "<h2>Dependencies</h2>").ok();
        html_deps_table(&mut out, &notices.dependencies);

        writeln!(out, "<h2>Licenses</h2>").ok();

        for (id, text) in &notices.get_license_texts() {
            writeln!(out, "<h3>{id}</h3>").ok();
            writeln!(out, "<pre style=\"text-wrap:wrap\">\n{text}\n</pre>",).ok();
        }

        writeln!(out, "</body>").ok();
        writeln!(out, "</html>").ok();

        out
    }

    pub fn markdown(notices: &Notices) -> String {
        let mut out = String::new();

        writeln!(out, "# 3rd Party Notices").ok();
        writeln!(out, "## Dependencies").ok();

        html_deps_table(&mut out, &notices.dependencies);

        writeln!(out, "## Licenses").ok();

        for (id, text) in &notices.get_license_texts() {
            writeln!(out, "### {id}").ok();
            writeln!(out, "```\n{text}\n```").ok();
        }

        out
    }

    pub fn json(notices: &Notices) -> String {
        serde_json::to_string_pretty(notices).unwrap()
    }

    fn html_deps_table(out: &mut impl std::fmt::Write, deps: &[Dep]) {
        writeln!(out, "<table>").ok();
        writeln!(out, "<thead>").ok();
        writeln!(out, "<tr>").ok();
        writeln!(out, "<th>Name</th>").ok();
        writeln!(out, "<th>Package URL</th>").ok();
        writeln!(out, "<th>License ID</th>").ok();
        writeln!(out, "<th>Notices</th>").ok();
        writeln!(out, "</tr>").ok();
        writeln!(out, "</thead>").ok();

        writeln!(out, "<tbody>").ok();
        for Dep {
            name,
            package_url,
            license_id,
            notices,
        } in deps
        {
            let notices_escaped = html_escape::encode_text(
                &notices.clone().into_iter().collect::<Vec<_>>().join("\n"),
            )
            .replace('\n', "<br />");
            writeln!(out, "<tr>").ok();
            writeln!(
                out,
                "<td>{name}</td><td><a href=\"{package_url}\">{package_url}</a></td><td>{license_id}</td><td>{notices_escaped}</td>"
            )
            .ok();
            writeln!(out, "</tr>").ok();
        }
        writeln!(out, "</tbody>").ok();

        writeln!(out, "</table>\n").ok();
    }
}
