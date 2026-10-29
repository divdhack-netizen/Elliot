//! elliot-catalog — the typed tool-catalog model, its YAML loader, and the
//! structural validation that mirrors `catalog/schema/tool-entry.schema.yaml`.
//!
//! The catalog is the contract shared by the agent (grounding), the tool runner
//! (validation) and the user (extension). This crate owns the Rust side: it
//! deserializes an entry and enforces the schema's **safe-by-construction**
//! invariants so that a malformed or unsafe entry cannot become a [`ToolEntry`]:
//!
//! - every struct is `deny_unknown_fields` → no free-form fields can be
//!   smuggled in (mirrors `additionalProperties: false`);
//! - `target.scope_checked` must be `true` → scope checking cannot be disabled;
//! - a `flag` of type `string` must carry a `pattern`;
//! - a `flag` of type `path` must declare `confined_to` **and** `access`;
//! - a `flag` of type `enum` must list non-empty `values`;
//! - `target.kind: flag` requires the carrying `flag` name;
//! - `id` and flag `name` match their schema patterns.
//!
//! Deserialization handles the shape; [`ToolEntry::validate`] enforces the
//! cross-field rules. [`ToolEntry::load`] does both.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Risk level. Ordered: `passive < low < intrusive < dangerous`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intrusiveness {
    Passive,
    Low,
    Intrusive,
    Dangerous,
}

impl Intrusiveness {
    fn rank(self) -> u8 {
        match self {
            Intrusiveness::Passive => 0,
            Intrusiveness::Low => 1,
            Intrusiveness::Intrusive => 2,
            Intrusiveness::Dangerous => 3,
        }
    }
}

impl PartialOrd for Intrusiveness {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Intrusiveness {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Standard,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Positional,
    Flag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Host,
    Cidr,
    HostOrCidr,
    Url,
    PortRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cardinality {
    One,
    OneOrMore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagType {
    Bool,
    Int,
    Enum,
    String,
    Path,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    RawSocket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinedTo {
    ProjectDir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_targets: Option<u32>,
    pub timeout_seconds: Option<u32>,
    pub max_rate: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub kind: TargetKind,
    /// Required when `kind == Flag`: the flag that carries the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<String>,
    #[serde(rename = "type")]
    pub target_type: TargetType,
    pub cardinality: Cardinality,
    pub scope_checked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flag {
    pub name: String,
    #[serde(rename = "type")]
    pub flag_type: FlagType,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intrusiveness: Option<Intrusiveness>,
    #[serde(default)]
    pub repeatable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_privilege: Option<Privilege>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined_to: Option<ConfinedTo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    pub id: String,
    pub binary: String,
    pub source: Source,
    pub description: String,
    pub base_intrusiveness: Intrusiveness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    pub target: Target,
    pub flags: Vec<Flag>,
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("parse: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid entry: {0}")]
    Invalid(String),
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// The bundled `standard/` catalog, compiled into the binary.
///
/// Listed explicitly rather than globbed (no `include_dir` dependency): adding a
/// standard entry means adding a line here, and `standard_catalog_loads` fails
/// if a listed entry is invalid.
const STANDARD_CATALOG: &[&str] = &[include_str!("../../../catalog/standard/nmap.yaml")];

/// Load and validate **every** bundled standard entry.
///
/// The standard catalog ships inside the binary, so this never touches the
/// filesystem.
pub fn load_standard() -> Result<Vec<ToolEntry>, CatalogError> {
    STANDARD_CATALOG
        .iter()
        .map(|yaml| ToolEntry::load(yaml))
        .collect()
}

/// Load and validate one user-authored (`custom`) entry from disk.
pub fn load_file(path: impl AsRef<Path>) -> Result<ToolEntry, CatalogError> {
    let path = path.as_ref();
    let yaml = std::fs::read_to_string(path).map_err(|source| CatalogError::Io {
        path: path.display().to_string(),
        source,
    })?;
    ToolEntry::load(&yaml)
}

impl ToolEntry {
    /// Parse a YAML entry and validate it. The only way to obtain a validated
    /// entry.
    pub fn load(yaml: &str) -> Result<Self, CatalogError> {
        let entry: ToolEntry = serde_yaml::from_str(yaml)?;
        entry.validate()?;
        Ok(entry)
    }

    /// Enforce the cross-field invariants the JSON Schema encodes. Shape is
    /// already guaranteed by deserialization; this adds the conditional rules.
    pub fn validate(&self) -> Result<(), CatalogError> {
        let bad = |m: String| Err(CatalogError::Invalid(m));

        if !is_valid_id(&self.id) {
            return bad(format!("id {:?} must match ^[a-z0-9][a-z0-9_-]*$", self.id));
        }
        if self.binary.is_empty() {
            return bad("binary must not be empty".into());
        }
        if self.description.is_empty() {
            return bad("description must not be empty".into());
        }

        // Scope checking can never be disabled.
        if !self.target.scope_checked {
            return bad("target.scope_checked must be true".into());
        }
        if self.target.kind == TargetKind::Flag && self.target.flag.is_none() {
            return bad("target.kind=flag requires target.flag".into());
        }

        let mut seen = std::collections::HashSet::new();
        for flag in &self.flags {
            if !is_valid_flag_name(&flag.name) {
                return bad(format!(
                    "flag {:?} must match ^-{{1,2}}[A-Za-z0-9][A-Za-z0-9-]*$",
                    flag.name
                ));
            }
            if !seen.insert(flag.name.as_str()) {
                return bad(format!("duplicate flag {:?}", flag.name));
            }
            if flag.description.is_empty() {
                return bad(format!("flag {:?} description must not be empty", flag.name));
            }
            match flag.flag_type {
                FlagType::String if flag.pattern.is_none() => {
                    return bad(format!("string flag {:?} requires a pattern", flag.name));
                }
                FlagType::Path if flag.confined_to.is_none() || flag.access.is_none() => {
                    return bad(format!(
                        "path flag {:?} requires confined_to and access",
                        flag.name
                    ));
                }
                FlagType::Enum if flag.values.as_ref().is_none_or(|v| v.is_empty()) => {
                    return bad(format!("enum flag {:?} requires non-empty values", flag.name));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Look up a flag by its exact name.
    pub fn flag(&self, name: &str) -> Option<&Flag> {
        self.flags.iter().find(|f| f.name == name)
    }
}

fn is_valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    id.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_valid_flag_name(name: &str) -> bool {
    let rest = match name.strip_prefix("--").or_else(|| name.strip_prefix('-')) {
        Some(r) => r,
        None => return false,
    };
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const NMAP: &str = include_str!("../../../catalog/standard/nmap.yaml");

    #[test]
    fn golden_nmap_entry_loads_and_validates() {
        let entry = ToolEntry::load(NMAP).expect("nmap.yaml should load");
        assert_eq!(entry.id, "nmap");
        assert_eq!(entry.base_intrusiveness, Intrusiveness::Low);
        assert_eq!(entry.target.kind, TargetKind::Positional);
        assert!(entry.target.scope_checked);
        // -sS is the privileged SYN scan.
        let ss = entry.flag("-sS").unwrap();
        assert_eq!(ss.requires_privilege, Some(Privilege::RawSocket));
        assert_eq!(ss.intrusiveness, Some(Intrusiveness::Intrusive));
        // -oX is a confined, writable path.
        let ox = entry.flag("-oX").unwrap();
        assert_eq!(ox.flag_type, FlagType::Path);
        assert_eq!(ox.confined_to, Some(ConfinedTo::ProjectDir));
        assert_eq!(ox.access, Some(Access::Write));
    }

    #[test]
    fn intrusiveness_is_ordered() {
        assert!(Intrusiveness::Passive < Intrusiveness::Low);
        assert!(Intrusiveness::Low < Intrusiveness::Intrusive);
        assert!(Intrusiveness::Intrusive < Intrusiveness::Dangerous);
        assert_eq!(
            Intrusiveness::Low.max(Intrusiveness::Intrusive),
            Intrusiveness::Intrusive
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let yaml = NMAP.to_string() + "\nsurprise: true\n";
        assert!(ToolEntry::load(&yaml).is_err());
    }

    #[test]
    fn string_flag_without_pattern_is_rejected() {
        let yaml = r#"
id: t
binary: t
source: custom
description: d
base_intrusiveness: low
target: { kind: positional, type: host, cardinality: one, scope_checked: true }
flags:
  - name: "--q"
    type: string
    description: no pattern here
"#;
        let err = ToolEntry::load(yaml).unwrap_err();
        assert!(matches!(err, CatalogError::Invalid(_)));
    }

    #[test]
    fn scope_checked_false_is_rejected() {
        let yaml = r#"
id: t
binary: t
source: custom
description: d
base_intrusiveness: low
target: { kind: positional, type: host, cardinality: one, scope_checked: false }
flags: []
"#;
        let err = ToolEntry::load(yaml).unwrap_err();
        assert!(matches!(err, CatalogError::Invalid(_)));
    }

    #[test]
    fn standard_catalog_loads_with_unique_ids() {
        let entries = load_standard().expect("the bundled standard catalog must load");
        assert!(!entries.is_empty(), "the standard catalog cannot be empty");

        let mut ids = std::collections::HashSet::new();
        for entry in &entries {
            entry
                .validate()
                .unwrap_or_else(|e| panic!("{} failed validation: {e}", entry.id));
            assert!(ids.insert(entry.id.clone()), "duplicate catalog id: {}", entry.id);
        }
    }

    #[test]
    fn load_file_reads_a_custom_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.yaml");
        std::fs::write(
            &path,
            r#"
id: prober
binary: prober
source: custom
description: a custom entry
base_intrusiveness: passive
target: { kind: positional, type: host, cardinality: one, scope_checked: true }
flags: []
"#,
        )
        .unwrap();

        let entry = load_file(&path).expect("a well-formed custom entry loads");
        assert_eq!(entry.id, "prober");
        assert_eq!(entry.source, Source::Custom);
    }

    #[test]
    fn load_file_reports_a_missing_file() {
        let err = load_file("/definitely/not/a/real/entry.yaml").unwrap_err();
        assert!(matches!(err, CatalogError::Io { .. }), "got {err:?}");
    }

    /// Best-effort drift guard between the JSON Schema and the Rust model.
    ///
    /// This is **not** a JSON Schema validator: it only compares the schema's
    /// top-level `required` list with the fields the Rust model treats as
    /// required (a field is required here when it has no `#[serde(default)]`).
    /// Nested rules (`target`, `flags`) are not covered.
    #[test]
    fn top_level_required_fields_match_the_model() {
        let schema = include_str!("../../../catalog/schema/tool-entry.schema.yaml");
        assert_eq!(
            top_level_required(schema),
            vec![
                "id",
                "binary",
                "source",
                "description",
                "base_intrusiveness",
                "target",
                "flags",
            ],
            "schema and ToolEntry have drifted apart"
        );
    }

    /// Pull the top-level (unindented) `required:` list out of the schema YAML.
    fn top_level_required(schema: &str) -> Vec<String> {
        for line in schema.lines() {
            // Indented `required:` lists belong to nested objects; skip them.
            let Some(rest) = line.strip_prefix("required:") else {
                continue;
            };
            let inner = rest
                .trim()
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or_else(|| panic!("unexpected `required` syntax: {rest:?}"));
            return inner
                .split(',')
                .map(|f| f.trim().to_string())
                .filter(|f| !f.is_empty())
                .collect();
        }
        panic!("the schema has no top-level `required:` list");
    }

    #[test]
    fn target_flag_kind_requires_flag_name() {
        let yaml = r#"
id: t
binary: t
source: custom
description: d
base_intrusiveness: low
target: { kind: flag, type: url, cardinality: one, scope_checked: true }
flags: []
"#;
        assert!(ToolEntry::load(yaml).is_err());
    }
}
