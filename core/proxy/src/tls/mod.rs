//! TLS support for the MITM path.
//!
//! Per-host leaf certificates are generated on the fly and cached in memory by
//! hudsucker's [`RcgenAuthority`](hudsucker::certificate_authority::RcgenAuthority);
//! this crate only owns the *root* CA (see [`ca`]). There is therefore no
//! separate per-host cache module.

pub mod ca;
