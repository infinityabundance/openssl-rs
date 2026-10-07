//! Phase 23 — the typed compatibility-policy layer.
//!
//! Phase 23.7's first half is a **typed** compatibility policy rather than a bag of booleans
//! (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7). Each axis of a compatibility
//! generation is a meaningful enum, and an [`AuthoritySpec`] is the record of which value each
//! axis takes for one authority. The default authority is the committed alias
//! `forensics/multitrack/default-authority.json`, never the catalogue's newest release
//! (`docs/AUTHORITY_POLICY.md`).
//!
//! The layer is **consumed by the build**: `build.rs` reads the `OPENSSL_RS_COMPAT` build
//! parameter, refuses an unknown value, emits the resolved selection and the committed default
//! authority as compile-time constants, and — only when the selection is a historical epoch —
//! sets the `openssl_rs_compat_facades` cfg that compiles the façades. So the authority selection
//! is explicit, singular, validated and recorded, and the default 3.6.4 production build carries
//! no façade (D534, and the hard bound in the 23.7 brief).
//!
//! SPDX-License-Identifier: Apache-2.0

/// The ABI epoch an authority belongs to: whether the public contract predates or follows the
/// 1.1.0 provider/opacity transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbiEpoch {
    /// The pre-1.1.0 contract: transparent public aggregates, engines, no providers.
    PreOneOneZero,
    /// The modern contract: opaque public aggregates, a provider store, deprecated engines.
    ModernProvider,
}

/// The public-layout epoch: whether a public aggregate is fully defined in an installed header
/// (transparent) or only forward-declared there (opaque).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicLayoutEpoch {
    /// The generation before the 1.1.0 opacity transition: `struct evp_md_ctx_st` and
    /// `struct hmac_ctx_st`, for example, are defined in full in an installed header.
    TransparentPreOneOneZero,
    /// The generation from 1.1.0 forward: those aggregates are opaque in the installed headers
    /// and complete only in an internal one.
    OpaquePostOneOneZero,
}

/// The initialisation model: whether a caller must explicitly initialise the library or the
/// distribution initialises itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitModel {
    /// A caller-visible `OPENSSL_init()`; there is no automatic initialisation.
    ExplicitGlobalInit,
    /// `OPENSSL_init_crypto` runs automatically and `OPENSSL_cleanup` tears it down.
    AutomaticInit,
}

/// The threading model: who supplies the locks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadModel {
    /// The application installs locking and thread-id callbacks; the library calls them.
    ApplicationLockingCallbacks,
    /// The library carries its own thread abstraction; the app-locking callbacks are no-ops.
    InternalThreadSupport,
}

/// The algorithm-registry model: how a method is found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlgorithmRegistryModel {
    /// Static `EVP_MD`/`EVP_CIPHER` method tables and the `*_add_all_*` registration walk.
    LegacyMethodTables,
    /// The provider store and the `EVP_*_fetch` query surface.
    ProviderFetch,
}

/// The ENGINE architecture model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EngineModel {
    /// Engines are the extension mechanism and are built in and loadable.
    BuiltInEngines,
    /// Engines exist but are deprecated in favour of providers; the built-in set is reduced.
    DeprecatedEngines,
    /// Engine support is compiled out entirely (`OPENSSL_NO_ENGINE`).
    NoEngine,
}

/// The provider architecture model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProviderModel {
    /// The release predates the provider model; there is no provider store.
    NoProviders,
    /// The 3.0-plus provider store is present and loadable.
    ProviderStore,
}

/// The default protocol-behaviour model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtocolDefaults {
    /// The pre-1.1.0 defaults (for example, the legacy cipher list).
    LegacyDefaults,
    /// The modern defaults applied by the provider era.
    ModernDefaults,
}

/// The CLI model of the `openssl` program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CliModel {
    /// The classic per-command option parsing.
    ClassicCli,
    /// The configuration- and provider-aware CLI.
    ConfigDrivenCli,
}

/// The compatibility spec of one authority: the value every policy axis takes for it.
///
/// It is a record, not a comparison: nothing here derives one authority's compatibility from
/// another's, and there is no ordering. A difference between two specs is a set of named axes.
#[derive(Debug)]
pub struct AuthoritySpec {
    /// The authority id (`forensics/authorities/AUTHORITIES.json` or the historical registry).
    pub id: &'static str,
    /// The upstream release id the authority is over.
    pub release: &'static str,
    /// Whether this is the committed default authority.
    pub default: bool,
    /// The ABI epoch.
    pub abi_epoch: AbiEpoch,
    /// The public-layout epoch.
    pub public_layout_epoch: PublicLayoutEpoch,
    /// The initialisation model.
    pub init: InitModel,
    /// The threading model.
    pub thread: ThreadModel,
    /// The algorithm-registry model.
    pub algorithms: AlgorithmRegistryModel,
    /// The ENGINE model.
    pub engine: EngineModel,
    /// The provider model.
    pub provider: ProviderModel,
    /// The protocol-defaults model.
    pub protocols: ProtocolDefaults,
    /// The CLI model.
    pub cli: CliModel,
}

/// The modern 3.6.4 production authority: the committed default.
pub const PRODUCTION_3_6_4: AuthoritySpec = AuthoritySpec {
    id: "openssl-3.6.4-production",
    release: "openssl-3.6.4",
    default: true,
    abi_epoch: AbiEpoch::ModernProvider,
    public_layout_epoch: PublicLayoutEpoch::OpaquePostOneOneZero,
    init: InitModel::AutomaticInit,
    thread: ThreadModel::InternalThreadSupport,
    algorithms: AlgorithmRegistryModel::ProviderFetch,
    engine: EngineModel::DeprecatedEngines,
    provider: ProviderModel::ProviderStore,
    protocols: ProtocolDefaults::ModernDefaults,
    cli: CliModel::ConfigDrivenCli,
};

/// The 0.9.8zh historical authority: the pre-1.1.0 generation whose façades 23.7 establishes.
pub const HISTORICAL_0_9_8ZH: AuthoritySpec = AuthoritySpec {
    id: "openssl-0.9.8zh-historical",
    release: "openssl-0.9.8zh",
    default: false,
    abi_epoch: AbiEpoch::PreOneOneZero,
    public_layout_epoch: PublicLayoutEpoch::TransparentPreOneOneZero,
    init: InitModel::ExplicitGlobalInit,
    thread: ThreadModel::ApplicationLockingCallbacks,
    algorithms: AlgorithmRegistryModel::LegacyMethodTables,
    engine: EngineModel::BuiltInEngines,
    provider: ProviderModel::NoProviders,
    protocols: ProtocolDefaults::LegacyDefaults,
    cli: CliModel::ClassicCli,
};

/// The authorities this policy layer names, in a fixed order.
pub const SPECS: &[&AuthoritySpec] = &[&PRODUCTION_3_6_4, &HISTORICAL_0_9_8ZH];

/// The authority id the committed default alias resolves to, as `build.rs` injected it.
pub const COMMITTED_DEFAULT_AUTHORITY: &str = env!("OPENSSL_RS_DEFAULT_AUTHORITY");

/// The compatibility selection `build.rs` resolved for this build.
pub const SELECTED_AUTHORITY: &str = env!("OPENSSL_RS_COMPAT_SELECTION");

/// The spec for an authority id, or `None` when the id is not one this layer names.
///
/// A `None` is a refusal rather than a fallback: `build.rs` refuses an unknown
/// `OPENSSL_RS_COMPAT` value at build time, so an id that reaches here and is not named is a
/// policy defect, not something to paper over with a default.
pub fn spec_for_id(id: &str) -> Option<&'static AuthoritySpec> {
    SPECS.iter().copied().find(|s| s.id == id)
}

/// The spec selected for this build.
///
/// `build.rs` validated the selection and set `OPENSSL_RS_COMPAT_SELECTION` to one of the ids
/// this layer names, so the lookup always resolves. The `unwrap_or` is the committed default
/// rather than a panic: a `build.rs` regression should degrade to the production authority it is
/// required to default to, never to an unspecified one.
pub fn selected() -> &'static AuthoritySpec {
    spec_for_id(SELECTED_AUTHORITY).unwrap_or(&PRODUCTION_3_6_4)
}

/// Whether the selected build activates the historical ABI façades.
///
/// The default 3.6.4 production candidate selects the opaque epoch and activates none; only a
/// historical selection does, and `build.rs` compiles the façade modules then and only then.
pub fn facades_active() -> bool {
    selected().public_layout_epoch == PublicLayoutEpoch::TransparentPreOneOneZero
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_resolves_to_the_committed_alias_and_the_production_authority() {
        // The default selection is the committed alias's authority, and that authority is the
        // 3.6.4 production candidate — never the catalogue's newest release.
        assert_eq!(selected().id, COMMITTED_DEFAULT_AUTHORITY);
        assert_eq!(COMMITTED_DEFAULT_AUTHORITY, PRODUCTION_3_6_4.id);
        assert!(selected().default);
    }

    #[test]
    fn an_unknown_authority_has_no_spec_and_the_named_ones_do() {
        assert!(spec_for_id("openssl-3.6.4-production").is_some());
        assert!(spec_for_id("openssl-0.9.8zh-historical").is_some());
        assert!(spec_for_id("openssl-4.0.3").is_none());
        assert!(spec_for_id("").is_none());
    }

    #[test]
    fn the_historical_selection_is_the_pre_1_1_0_epoch() {
        let found = spec_for_id("openssl-0.9.8zh-historical");
        assert!(found.is_some());
        if let Some(s) = found {
            assert!(!s.default);
            assert_eq!(s.abi_epoch, AbiEpoch::PreOneOneZero);
            assert_eq!(
                s.public_layout_epoch,
                PublicLayoutEpoch::TransparentPreOneOneZero
            );
            assert_eq!(s.init, InitModel::ExplicitGlobalInit);
            assert_eq!(s.thread, ThreadModel::ApplicationLockingCallbacks);
            assert_eq!(s.provider, ProviderModel::NoProviders);
            assert_eq!(s.engine, EngineModel::BuiltInEngines);
        }
    }

    #[test]
    fn the_default_selection_activates_no_facades() {
        // The required property: the production selection is the opaque epoch, so the façades
        // are not active and `build.rs` compiles none.
        assert_eq!(
            selected().public_layout_epoch,
            PublicLayoutEpoch::OpaquePostOneOneZero
        );
        assert!(!facades_active());
    }
}
