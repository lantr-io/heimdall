use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use frost_secp256k1_tr::Identifier;

use heimdall::cardano::blockfrost_chain::BlockfrostCardanoChain;
use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
use heimdall::cardano::mock::MockCardanoPegInSource;
use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
use heimdall::cardano::pegin_source::CardanoPegInSource;
use heimdall::cardano::treasury_datum::TreasuryConfig;
use heimdall::config::HeimdallConfig;
use heimdall::epoch::mocks::{MockCardanoChain, OsRngSource, SeededRngSource, SystemClock};
use heimdall::epoch::run_epoch_loop;
use heimdall::epoch::state::SpoIdentity;
use heimdall::epoch::traits::{CardanoChain, Clock, PeerNetwork, RngSource};
use heimdall::federation::roster::FederationMember;
use heimdall::federation::{
    CeremonyLimits, FederationKeyState, FederationRoster, ceremony, persist as federation_persist,
    spend as federation_spend,
};
use heimdall::frost::xonly::group_xonly;
use heimdall::http::peer_network::HttpPeerNetwork;
use heimdall::http::server::router;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "heimdall",
    about = "Bifrost Bridge SPO program",
    version = env!("HEIMDALL_VERSION")
)]
struct Cli {
    /// Log verbosity: `error`, `warn`, `info` (default), `debug`, `trace`, or a
    /// full `RUST_LOG` directive like `warn,heimdall::cardano=debug`. Outranks
    /// `RUST_LOG` and `[log] level` in the config file.
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Log format: `auto` (default — `journal` under systemd, else `plain`),
    /// `plain`, `journal`, or `json`. Outranks `HEIMDALL_LOG_FORMAT` and
    /// `[log] format` in the config file.
    #[arg(long, global = true, value_name = "FORMAT")]
    log_format: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run this SPO's node: the epoch loop that participates in the DKG,
    /// co-signs Treasury Movements with the rest of the roster, and drives
    /// the key handoff at each boundary.
    ///
    /// Every registered SPO runs one of these. They point at the same chain,
    /// discover the roster from it (and thus their own listen port and FROST
    /// index), and reach each other over the authenticated HTTP transport —
    /// this is the only distributed signing path heimdall has. Contrast
    /// `run-mover`, which builds and signs movements in ONE process.
    ///
    /// Named `demo` until 2026-08-15, which was wrong in the way that
    /// matters: it is the SPO daemon, and the name said not to run it.
    ///
    /// TODO: add a `--chain` flag (once a real `CardanoChain` impl
    /// exists) to select between `mock` and a live Cardano follower.
    /// Today the mock path is hardwired to `MockCardanoChain`, and the
    /// `--min-signers`, `--max-signers`, `--base-port` flags are only
    /// used to parameterize that mock chain — a real deployment would
    /// read none of those from the CLI.
    RunSpo {
        /// Path to a TOML configuration file. Omitted fields use
        /// compiled defaults. CLI flags override TOML values.
        #[arg(long)]
        config: Option<String>,
        /// Legacy fallback: this SPO's 1-based roster index, used only for the
        /// config/mock fixture demo (whose roster carries no bifrost_id_pk). With
        /// a real on-chain roster the node identifies itself by its bifrost key.
        #[arg(long)]
        index: Option<u16>,
        /// Minimum signers (threshold). Mock-chain only.
        #[arg(long)]
        min_signers: Option<u16>,
        /// Maximum signers (total SPOs in the roster). Mock-chain only.
        #[arg(long)]
        max_signers: Option<u16>,
        /// Base port: SPO `i` listens on `base_port + i - 1`. Mock-chain only.
        #[arg(long)]
        base_port: Option<u16>,
        /// Use a deterministic seeded RNG so the cycle is bit-for-bit
        /// reproducible across runs. Demo-only.
        #[arg(long)]
        deterministic: bool,
        /// DEMO-ONLY: inject a DKG fault so this node misbehaves, to exercise
        /// the fault-proof / SPO-ban flow live in the scenario harness. Kinds:
        /// `equivocate-round1`. Never set in production.
        #[arg(long)]
        inject_fault: Option<String>,
        /// Blockfrost project ID (e.g. `preprodXXXXXX`). Network is
        /// auto-detected from the key prefix. If set, UTxOs are
        /// queried from Blockfrost instead of a local node.
        #[arg(long)]
        blockfrost_project_id: Option<String>,
        /// Path to a running Cardano node's Unix socket. If set, the
        /// peg-in source is the live node via pallas N2C. Ignored if
        /// `--blockfrost-project-id` is given.
        #[arg(long)]
        cardano_socket: Option<String>,
        /// Cardano network magic (`764824073` mainnet, `1` preprod,
        /// `2` preview). Required with `--cardano-socket`.
        #[arg(long)]
        cardano_magic: Option<u64>,
        /// How long (seconds) `CollectPegins` polls the source before
        /// freezing the observed set.
        #[arg(long)]
        pegin_window_secs: Option<u64>,
        /// Interval (ms) between successive peg-in polls inside the
        /// collection window.
        #[arg(long)]
        pegin_poll_ms: Option<u64>,
        /// BIP-39 mnemonic (12/15/24 words, space-separated) for the
        /// Cardano wallet that pays fees and signs the oracle-update tx.
        /// The payment key is derived at `m/1852'/1815'/0'/0/0`
        /// (CIP-1852), the wallet address is derived from that key, and
        /// UTxOs are queried from Blockfrost automatically. Without
        /// this, the demo runs in dry-run mode (no Cardano publish).
        #[arg(long)]
        cardano_mnemonic: Option<String>,
    },
    /// Print the bootstrap treasury Taproot address (Bitcoin side; the Cardano
    /// state UTxO is created by bootstrap-treasury-info).
    BootstrapTreasury {
        /// Path to a TOML configuration file.
        #[arg(long)]
        config: Option<String>,
        /// Federation CSV timeout in blocks (overrides TOML).
        #[arg(long)]
        federation_csv_blocks: Option<u16>,
    },
    /// Print the treasury Taproot address for a given FROST group key: internal key
    /// `Y_51`, recovery leaf `(y_federation, federation_csv_blocks)` — the same tree
    /// `sweep-pegins` and the auto-mover sign against.
    ///
    /// The deployer's counterpart to `bootstrap-treasury`: that one prints the GENESIS
    /// address, where `Y_51 = y_federation` because no roster exists yet; this one
    /// prints the address the treasury lives at once a roster does. Both derive from
    /// local values on purpose — they run before there is a Config UTxO to read.
    FrostTreasury {
        /// Path to a TOML configuration file.
        #[arg(long)]
        config: Option<String>,
        /// 32-byte x-only FROST group key as hex. Omit to derive it from the
        /// deterministic demo DKG (`demo.min_signers` / `demo.max_signers`) — the same
        /// key `sweep-pegins` reproduces.
        #[arg(long)]
        frost_key: Option<String>,
        /// The federation fallback key `y_federation` (32-byte x-only hex): the key in
        /// the treasury tree's CSV recovery leaf, published as Config #11. Omit ONLY for
        /// the bootstrap treasury, where it equals `Y_51` — on a deployed bridge the two
        /// differ, and defaulting it to `Y_51` prints an address the bridge never uses.
        #[arg(long)]
        y_federation: Option<String>,
        /// Federation CSV timeout in blocks (overrides TOML). Hashed into the recovery
        /// leaf, so it changes the address.
        #[arg(long)]
        federation_csv_blocks: Option<u16>,
    },
    /// Self-send the bootstrap treasury UTXO so the treasury becomes output[0]
    /// (normalises a faucet funding tx; see internal-docs decisions D1).
    /// Key-path spend signed with the single y_fed key. Prints the signed tx —
    /// heimdall does not send it (WI-086).
    TreasurySelfSend {
        #[arg(long)]
        config: Option<String>,
        /// Funding outpoint to spend, as <txid>:<vout>.
        #[arg(long)]
        outpoint: String,
        /// Input amount in satoshis.
        #[arg(long)]
        amount_sat: u64,
    },
    /// Produce the four air-gapped registration values, on a machine that
    /// touches no chain and no network (WI-092).
    ///
    /// `register-spo` accepts the cold and Bifrost signatures in place of the two
    /// key files, so a pool's cold key never has to reach a networked block
    /// producer — the key type exists for exactly that. Nothing could produce the
    /// cold half, though: it is a RAW Ed25519 signature over the registration
    /// message, `cardano-cli` has no raw-sign command, and the usual community
    /// signer's CIP-8 mode signs a WRAPPED payload, so a signature made the
    /// obvious way verifies nowhere and says nothing about why. This command is
    /// the signer.
    ///
    /// Run it beside your cold key, copy the four printed flags to the node, and
    /// pass them to `register-spo`. Both signatures are verified here before
    /// printing, so a mistyped URL fails on the air-gapped machine rather than
    /// after a fee is spent.
    SignRegistration {
        #[arg(long)]
        config: Option<String>,
        /// Pool cold SIGNING key: a `cold.skey` TextEnvelope, a path to one, or
        /// raw 32-byte hex. Falls back to `cardano.cold_skey_path`.
        #[arg(long)]
        cold_skey: Option<String>,
        /// Bifrost identity secret key: 32-byte hex or a path. Falls back to
        /// `[bifrost].skey_path`.
        #[arg(long)]
        bifrost_skey: Option<String>,
        /// This SPO's Bifrost endpoint URL. MUST be byte-identical to the one
        /// `register-spo` uses: it is signed over, so any difference — a
        /// trailing slash, a different port — invalidates both signatures. Set
        /// `[bifrost].url` instead and neither command can get it wrong.
        #[arg(long)]
        bifrost_url: Option<String>,
    },
    /// Print this node's Bifrost identity — the public half of
    /// `[bifrost].skey_path`. Read-only; touches no chain and no secret beyond
    /// reading the key file.
    ///
    /// This is the value other people need from you: the other federation
    /// members put it in their `[federation].members`, and `register-spo` binds
    /// it on chain. It also reports where this node sits in the configured
    /// federation, so a mismatched member list is visible before a ceremony
    /// rather than as a stall during one.
    BifrostId {
        #[arg(long)]
        config: Option<String>,
    },
    /// Form the initial federation (WI-087): run the distributed key generation
    /// that produces `federation_setup_Y`, the key in the CSV recovery leaf of
    /// the treasury and of every peg-in deposit. Genesis publishes it as Config
    /// #11, and from then on it is called `y_federation` — the setup name marks
    /// the window in which it lives on the members' own machines and nowhere
    /// else.
    ///
    /// This is the FIRST thing that happens when a bridge is stood up — before
    /// genesis, before the Config exists — so it reads no chain state at all. Its
    /// participants are the typed-in `[federation]` roster, and it waits for ALL
    /// of them: a member absent from the ceremony can never sign the key it
    /// produces. Every member runs this command, with the same member list and
    /// the same `min_signers`.
    ///
    /// The share is persisted `0600` under `protocol.state_dir`; re-running with
    /// a share already there just prints the key again. Losing every copy loses
    /// the recovery path for good — the ceremony cannot reproduce the same key.
    FederationDkg {
        #[arg(long)]
        config: Option<String>,
        /// Give up on a round after N seconds instead of waiting indefinitely.
        /// The ceremony has no deadline of its own — a forming federation is not
        /// late for anything — so this is for an operator who wants the command
        /// to return rather than sit.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Keep serving this node's ceremony payloads for N seconds after its
        /// own share is derived (default 120).
        ///
        /// A member that finishes first still holds payloads its slower peers
        /// have not fetched, and an endpoint that disappears is indistinguishable
        /// from one that published nothing — so exiting immediately can strand a
        /// peer that was seconds behind. 0 exits at once.
        #[arg(long, default_value_t = 120)]
        serve_after_secs: u64,
    },
    /// Sign one 32-byte message AS THE FEDERATION — a FROST session among the
    /// members, producing a single BIP-340 signature under `Y_federation`.
    ///
    /// The generic half of `federation-spend`, for the authorizations that are
    /// not Bitcoin transactions. The one that exists today is Update-Y as the
    /// federation (spec [UY-5], dead-roster recovery): run `update-y
    /// --federation`, take the `sign message:` line it prints, sign it here with
    /// the other members, and pass the result back as `--signature`.
    ///
    /// Every participating member runs this with the SAME `--message` and
    /// `--signers`.
    FederationSign {
        #[arg(long)]
        config: Option<String>,
        /// The 32-byte message to sign, hex.
        #[arg(long)]
        message: String,
        /// Which members will sign, as roster indices (default: all). Every
        /// participant must pass the same list — see `federation-spend`.
        #[arg(long, value_delimiter = ',')]
        signers: Vec<u16>,
        /// Give up on a signing round after N seconds (default 300).
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Keep serving for N seconds after the signature is aggregated
        /// (default 60), so a co-signer one poll behind can still fetch.
        #[arg(long, default_value_t = 60)]
        serve_after_secs: u64,
    },
    /// FEDERATION emergency spend of the treasury (scenario 3, N23): a Taproot
    /// SCRIPT-PATH spend via the `y_fed` CSV leaf — the fallback for when the FROST
    /// group is dark. The treasury UTxO must already be `federation_csv_blocks`
    /// deep on Bitcoin. Change returns to the same treasury address (federation
    /// self-send); the on-chain key rotation to y_federation is separate (N10b).
    /// Prints the signed tx — heimdall does not send it (WI-086).
    ///
    /// Signs with whichever federation key this node holds: a `federation-dkg`
    /// share means a FROST session among the members (every one of them runs this
    /// same command, with the same arguments), while `bitcoin.y_fed_seed_hex`
    /// means the single-key federation that predates WI-087.
    FederationSpend {
        #[arg(long)]
        config: Option<String>,
        /// Treasury outpoint to spend, as <txid>:<vout>.
        #[arg(long)]
        outpoint: String,
        /// Treasury input amount in satoshis.
        #[arg(long)]
        amount_sat: u64,
        /// The treasury's current internal key (32-byte x-only hex = its FROST
        /// group key Y_51), needed to rebuild the treasury Taproot tree + the
        /// leaf control block. Omit for the bootstrap treasury, where Y_51 =
        /// y_fed (as `bootstrap-treasury` prints it).
        #[arg(long)]
        y51: Option<String>,
        /// Which federation members will sign, as roster indices
        /// (`--signers 1,3,4`; `federation-dkg` prints the numbering). Every
        /// participant MUST pass the same list: FROST binds each share to the
        /// exact set of co-signers, so two members that assumed different sets
        /// produce an aggregate that verifies against nothing. Default: all
        /// members. Ignored by the single-key federation.
        #[arg(long, value_delimiter = ',')]
        signers: Vec<u16>,
        /// Give up on a signing round after N seconds (default 300). Distributed
        /// federation only.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Keep serving this node's signing payloads for N seconds after the
        /// signature is aggregated (default 60). The transaction is printed
        /// first, so this only delays the process exiting.
        ///
        /// Without it the first member to aggregate exits and stops answering,
        /// and a co-signer one poll behind waits for a share it can no longer
        /// fetch. Distributed federation only; 0 exits at once.
        #[arg(long, default_value_t = 60)]
        serve_after_secs: u64,
    },
    /// Print the Cardano wallet base address + payment key hash (the TM-NFT mint
    /// authority) derived from the configured mnemonic / $HEIMDALL_MNEMONIC.
    WalletAddress {
        #[arg(long)]
        config: Option<String>,
    },
    /// Bootstrap (K1 / init) the Cardano `treasury_info` state UTxO: one-shot mint
    /// of the treasury NFT plus the initial TreasuryDatum (bifrost identity root –
    /// empty unless --identity-root, FROST group key, federation fields).
    /// Spends a wallet UTxO as the one-shot; prints the signed tx, submits only
    /// with --submit. (Cardano side; bootstrap-treasury prints the BTC-side
    /// Taproot address.)
    ///
    /// LEGACY, for the same reason as `bootstrap-registry`, and more sharply:
    /// `binocular deploy-bridge` mints the Treasury state NFT inside the federation
    /// transaction, alongside the registry and ban roots. It has to. A one-shot mint
    /// handler requires its outpoint to be an INPUT of the minting tx, so a genesis
    /// that derives `treasury_info` from the federation one-shot and then spends that
    /// outpoint on the other two roots leaves the Treasury state NFT unmintable by
    /// anyone, for ever — and the instance that results has no Treasury state UTxO, so
    /// no SPO can register ([REG-6] pins the registry to it) and Update-Y is
    /// unreachable. Picking a different outpoint for this command does not rescue it:
    /// that derives a policy the Config does not name and the registry root is not
    /// bound to.
    ///
    /// So run it only against a bridge whose genesis predates that (WI-082), or to
    /// recover a genesis that failed partway. On a bridge deployed the current way,
    /// the one-shot is already spent and this command will say so rather than build a
    /// tx that cannot mint.
    BootstrapTreasuryInfo {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap output ref, as
        /// <cardano_tx_hash>:<index>. Parameterizes the registry policy. NOT
        /// treasury_info: rev 5.5 runs the chain Config → treasury → registry
        /// ([PRE-3], [PRE-4]), so this command takes the treasury's own one-shot from
        /// `cardano.treasury_bootstrap` and the arrow points the other way. It must
        /// still be unspent when the registry linked list itself is bootstrapped
        /// later — pick a wallet UTxO that will be left alone until then.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// 32-byte x-only key seeded into current_spos_frost_key. In Phase 1 this
        /// is Y_federation (the federation is the key-path signer until the first
        /// DKG), so it normally equals the Config's #11 y_federation.
        #[arg(long)]
        frost_key: String,
        /// 32-byte hex bifrost identity root seeded into the datum (spec
        /// [PRE-2] – e.g. a replacement deployment carrying registered SPOs
        /// forward). Omit for the empty MPF root (fresh deployment).
        #[arg(long)]
        identity_root: Option<String>,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Bootstrap the spos_registry linked list: spend the one-shot outref that
    /// parameterizes the registry policy and mint the "reg-root" anchor NFT to
    /// the registry script address. Prints the signed tx, submits only with
    /// --submit. Must confirm before any register-spo can be built.
    ///
    /// LEGACY. `binocular deploy-bridge` mints this root as the first genesis
    /// transaction, so a bridge deployed at or after WI-068 already has one and
    /// its one-shot is spent. Kept for a bridge that predates that, and for
    /// recovering a genesis that failed between its two transactions.
    BootstrapRegistry {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap output ref, as
        /// <cardano_tx_hash>:<index>. Must still be an unspent wallet UTxO,
        /// and the same value that parameterized bootstrap-treasury-info.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Deploy the spos_registry script as a reference script (output #0 at the
    /// wallet's own address, reclaimable). register_spo references it instead
    /// of embedding the ~12 KB script twice, which would not fit in the 16 KB
    /// tx-size limit.
    DeployRegistryRef {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The federation one-shot outpoint (<tx_hash>:<index>) every federation
        /// script is compile-parameterized by. OPTIONAL since WI-090: the bridge
        /// publishes it at Config #12 and a node reads it from there. Pass it only
        /// for a genesis command that runs before the Config exists, or to build
        /// against a bridge whose Config this node is not reading.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
        /// Deploy even though this wallet already holds a reference script for
        /// the same script. For replacing a copy that is about to be spent —
        /// otherwise the duplicate just locks another ~55 ADA.
        #[arg(long)]
        force: bool,
    },
    /// Deploy a DKG fault-verifier as a CIP-33 reference script and print its
    /// policy id (hash) for `fault_proof_policies`. Dry-run (default) prints the
    /// hash without submitting (round1/round2 need only their hash for the
    /// equivocation path); `--kind equivocation --submit` deploys the ref.
    DeployFaultRef {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The federation one-shot outpoint (<tx_hash>:<index>) every federation
        /// script is compile-parameterized by. OPTIONAL since WI-090: the bridge
        /// publishes it at Config #12 and a node reads it from there. Pass it only
        /// for a genesis command that runs before the Config exists, or to build
        /// against a bridge whose Config this node is not reading.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Which fault verifier: `round1` | `round2` | `equivocation`.
        #[arg(long)]
        kind: String,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
        /// Deploy even though this wallet already holds a reference script for
        /// the same script. For replacing a copy that is about to be spent —
        /// otherwise the duplicate just locks another ~55 ADA.
        #[arg(long)]
        force: bool,
    },
    /// Deploy the `spo_bans` validator as a CIP-33 reference script and print its
    /// policy id (the ban-list policy). `spo_bans` is parameterized by the registry
    /// hash + the 3 fault-verifier policy hashes (derived here from the blueprint) +
    /// the ban-schedule params + the ban-list bootstrap outref, so the printed hash
    /// matches what `DkgFaultBanFlow::from_config` recomputes.
    DeploySpoBansRef {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The federation one-shot outpoint (<tx_hash>:<index>) every federation
        /// script is compile-parameterized by. OPTIONAL since WI-090: the bridge
        /// publishes it at Config #12 and a node reads it from there. Pass it only
        /// for a genesis command that runs before the Config exists, or to build
        /// against a bridge whose Config this node is not reading.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// The ban-list one-shot bootstrap output ref (<tx_hash>:<index>).
        #[arg(long)]
        ban_bootstrap: String,
        /// Ban-schedule params. Genesis-only: they must equal what the bridge
        /// Config will publish at params[4..6], which is what every node reads
        /// once the Config exists — there is no local copy any more.
        #[arg(long)]
        base_ban_duration_ms: i64,
        #[arg(long)]
        max_faults_before_permanent: i64,
        #[arg(long)]
        max_validity_window_ms: i64,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
        /// Deploy even though this wallet already holds a reference script for
        /// the same script. For replacing a copy that is about to be spent —
        /// otherwise the duplicate just locks another ~55 ADA.
        #[arg(long)]
        force: bool,
    },
    /// Register the stake credential of every withdraw-using script heimdall
    /// deploys, so their withdraw-zero paths are admissible. Conway rejects a
    /// withdrawal whose reward account is unregistered
    /// (`WithdrawalsNotInRewardsCERTS`), and certificates validate against the
    /// PRE-transaction ledger state, so this cannot be folded into the
    /// withdrawing tx. Today the set is `spo_bans` alone — `peg_in`/`peg_out`
    /// are registered by binocular's `deploy-bridge` / `register-bridge-creds`,
    /// and re-registering an existing credential is a ledger error. Idempotent:
    /// already-registered credentials are skipped. Run after
    /// `bootstrap-ban-list`, before any withdraw path.
    InitScripts {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The federation one-shot outpoint (<tx_hash>:<index>) every federation
        /// script is compile-parameterized by. OPTIONAL since WI-090: the bridge
        /// publishes it at Config #12 and a node reads it from there. Pass it only
        /// for a genesis command that runs before the Config exists, or to build
        /// against a bridge whose Config this node is not reading.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// The ban-list one-shot bootstrap output ref (<tx_hash>:<index>).
        #[arg(long)]
        ban_bootstrap: String,
        /// Ban-schedule params. Genesis-only: they must equal what the bridge
        /// Config will publish at params[4..6], which is what every node reads
        /// once the Config exists — there is no local copy any more.
        #[arg(long)]
        base_ban_duration_ms: i64,
        #[arg(long)]
        max_faults_before_permanent: i64,
        #[arg(long)]
        max_validity_window_ms: i64,
        /// Override the protocol stake-key deposit (lovelace) instead of
        /// reading it from /epochs/latest/parameters.
        #[arg(long)]
        key_deposit: Option<u64>,
        /// Actually submit via Blockfrost (default: report state only).
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the register_spo tx: bind this
    /// pool's cold-key identity to a Bifrost identity (secp256k1 key + URL),
    /// mint the membership token, insert the registration node into the
    /// on-chain linked list and advance the treasury bifrost_identity_root.
    /// Submission is gated on the R2 min-stake check
    /// (cardano.min_stake_lovelace vs the pool's epoch-snapshot active stake).
    RegisterSpo {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap output ref (<tx_hash>:<index>)
        /// that parameterizes the registry policy (and through it treasury_info).
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Pool cold signing key: 32-byte hex, or a path to a file holding that
        /// hex or a cardano-cli TextEnvelope (cborHex "5820" || 32 bytes).
        /// Omit for the air-gapped flow (--cold-vkey + --cold-sig).
        #[arg(long)]
        cold_skey: Option<String>,
        /// Air-gapped: 32-byte cold verification key, hex.
        #[arg(long)]
        cold_vkey: Option<String>,
        /// Air-gapped: 64-byte Ed25519 signature (hex) over the registration
        /// message. Run without it first to print the exact message to sign.
        #[arg(long)]
        cold_sig: Option<String>,
        /// Bifrost identity secret key: 32-byte hex or a path to a file with
        /// it. Omit for the air-gapped flow (--bifrost-id-pk + --bifrost-sig).
        #[arg(long)]
        bifrost_skey: Option<String>,
        /// Air-gapped: 32-byte x-only bifrost public key, hex.
        #[arg(long)]
        bifrost_id_pk: Option<String>,
        /// Air-gapped: 64-byte BIP340 Schnorr signature (hex) over
        /// sha2_256(registration message).
        #[arg(long)]
        bifrost_sig: Option<String>,
        /// This SPO's Bifrost endpoint URL (where DKG data is published).
        /// Falls back to `[bifrost].url`, which is the better place for it: the
        /// registration message commits to these exact bytes, so one value read
        /// by both this and `sign-registration` cannot drift between them.
        #[arg(long)]
        bifrost_url: Option<String>,
        /// Override the registry reference-script UTxO (<tx_hash>:<index>).
        /// Not needed for the usual case: the one `deploy-registry-ref` left
        /// key-locked at this wallet is discovered automatically. Pass this to
        /// use a reference script held anywhere else — another SPO's, or one at
        /// an address that is not this wallet.
        #[arg(long)]
        registry_ref: Option<String>,
        /// Actually submit via Blockfrost (requires passing the min-stake gate).
        #[arg(long)]
        submit: bool,
    },
    /// Update-Y: rotate `current_spos_frost_key` in the treasury_info state UTxO
    /// to the incoming roster's Y_51' (the DKG key handoff — §Update-Y). The
    /// OUTGOING key signs (BIP340) a domain-tagged message committing to the
    /// spent outpoint, epoch and new key; with --federation the FEDERATION key
    /// (y_federation) signs instead (spec [UY-5], e.g. dead-roster recovery).
    /// Submission is permissionless. Prints the signed tx, submits only with
    /// --submit. In Phase 1 the outgoing key is Y_federation, so the y_fed seed
    /// signs by default.
    UpdateY {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap output ref (<tx_hash>:<index>)
        /// that parameterizes the registry policy (and through it treasury_info).
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// The incoming roster's x-only Y_51' (32-byte hex) — the new key.
        #[arg(long)]
        new_key: String,
        /// Epoch number bound into the signed message (8-byte BE).
        #[arg(long)]
        epoch: u64,
        /// Sign with this 32-byte hex secret key (the OUTGOING key; with
        /// --federation, the FEDERATION key). Omit to sign with the config
        /// y_fed seed (Phase 1), or use --signature (air-gapped).
        #[arg(long)]
        signer_skey: Option<String>,
        /// Air-gapped: 64-byte BIP340 signature (hex) over the update-y message.
        /// Run without it first to print the exact 32-byte message to sign.
        #[arg(long)]
        signature: Option<String>,
        /// Authorize as the FEDERATION (spec [UY-5]): the signature is checked
        /// against the spent datum's y_federation instead of
        /// current_spos_frost_key. The federation may name any successor key.
        #[arg(long)]
        federation: bool,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Bootstrap the spo_bans ban list: spend the one-shot outref that
    /// parameterizes the ban policy and mint the "ban-root" anchor NFT to the
    /// ban script address (WI-015). Prints the signed tx, submits only with
    /// --submit. Precondition for any apply-ban. The fault-policy set +
    /// ban-schedule params come from [cardano] config.
    ///
    /// LEGACY, for the same reason as `bootstrap-registry`: genesis mints this
    /// root before the Config exists, which is what makes a bridge unable to
    /// exist without a ban list. Kept for a pre-WI-068 bridge and for recovery.
    BootstrapBanList {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap outref (<tx_hash>:<index>) —
        /// its policy hash is a spo_bans parameter.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// The spo_bans one-shot bootstrap outref (<tx_hash>:<index>). Must be an
        /// unspent wallet UTxO, and should match cardano.ban_bootstrap (the value
        /// apply-ban reads to re-derive the same ban policy).
        #[arg(long)]
        ban_bootstrap: String,
        /// Ban-schedule params, for GENESIS only: the ban root is minted before
        /// the Config NFT that names it exists, so there is nothing to read them
        /// from yet. Required when this node cannot read a bridge Config;
        /// refused when it can, since the Config is then authoritative.
        #[arg(long)]
        base_ban_duration_ms: Option<i64>,
        #[arg(long)]
        max_faults_before_permanent: Option<i64>,
        #[arg(long)]
        max_validity_window_ms: Option<i64>,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the spo_bans.ApplyBan tx: consume a
    /// published FaultProof and write the ban-list node (WI-018). The
    /// fault-policy set + ban-schedule params come from [cardano] config.
    ApplyBan {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The federation one-shot outpoint (<tx_hash>:<index>) every federation
        /// script is compile-parameterized by. OPTIONAL since WI-090: the bridge
        /// publishes it at Config #12 and a node reads it from there. Pass it only
        /// for a genesis command that runs before the Config exists, or to build
        /// against a bridge whose Config this node is not reading.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// The accused pool id (28-byte hex).
        #[arg(long)]
        accused_pool_id: String,
        /// The fault evidence hash (32-byte hex) that binds the FaultProof token.
        #[arg(long)]
        evidence_hash: String,
        /// Fault policy kind: round1, round2, or equivocation.
        #[arg(long)]
        fault_kind: String,
        /// The spo_bans reference-script UTxO (<tx_hash>:<index>): the script is
        /// used three times in the tx and would not fit embedded.
        #[arg(long)]
        spo_bans_ref: String,
        /// Actually submit via Blockfrost.
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the fault_verifier.PublishProof tx:
    /// mint the FaultProof token and park it at the wallet for a later
    /// apply-ban to consume (WI-018).
    FaultProofMint {
        #[arg(long)]
        config: Option<String>,
        /// Override the embedded contract blueprint with a `plutus.json` file.
        /// Development, and bridges built from a contracts release this heimdall
        /// predates; the embedded copy is the normal path.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap outref (<tx_hash>:<index>): the
        /// fault_verifier policy is parameterized by the registry policy id (the
        /// EquivocationProof branch references registration nodes).
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Captured DKG evidence JSON file. Invalid-payload evidence must
        /// include the Halo2 proof bytes expected by the verifier policy.
        #[arg(long)]
        evidence_file: String,
        /// Actually submit via Blockfrost.
        #[arg(long)]
        submit: bool,
    },
    /// Read + verify the on-chain SPO registry and print the DKG roster:
    /// reconstructs the spos_registry linked list, cross-checks the rebuilt
    /// identity-trie root against the treasury_info datum, and orders
    /// participants by bifrost_id_pk. Read-only.
    ShowRoster {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json). Falls back to
        /// cardano.registry_blueprint.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap outref (<tx_hash>:<index>).
        /// Falls back to cardano.registry_bootstrap.
        #[arg(long)]
        registry_bootstrap: Option<String>,
    },
    /// Scan binocular's on-chain peg-in requests over N2C, then build → sign →
    /// (optionally) broadcast the Treasury Movement sweeping the treasury + all
    /// discovered deposits into a new treasury output[0]. Key-path spend signed
    /// with the single y_fed key. See internal-docs sweep-pegins-handoff.md.
    SweepPegins {
        #[arg(long)]
        config: Option<String>,
        /// Path to a running Cardano node's Unix socket (e.g. /tmp/yaci-node.socket).
        #[arg(long)]
        cardano_socket: String,
        /// Cardano network magic (`42` for the yaci devnet).
        #[arg(long)]
        cardano_magic: u64,
        /// Current treasury outpoint to sweep, as <txid>:<vout>. Omit (together with
        /// --treasury-amount-sat) to chain-source the treasury from the Cardano tip
        /// Confirmed-TM (WI-028); pass both to override.
        #[arg(long, requires = "treasury_amount_sat")]
        treasury_outpoint: Option<String>,
        /// Treasury input amount in satoshis. Omit to chain-source from Cardano.
        #[arg(long, requires = "treasury_outpoint")]
        treasury_amount_sat: Option<u64>,
        /// Execute the side effects: POST the Treasury Movement to Cardano. Without
        /// it the TM is built, signed and printed only. Nothing here reaches Bitcoin —
        /// the binocular watchtower relays the signed TM from the posted UnconfirmedTm
        /// record (WI-086).
        #[arg(long)]
        broadcast: bool,
        /// Override the locally-built signed TM with these raw BTC tx bytes (hex). Use when
        /// the on-chain TM bytes are fixed (already confirmed on Bitcoin) but the local builder
        /// would produce different bytes (e.g. different PIR set). The Cardano TM datum will
        /// contain these bytes.
        #[arg(long)]
        existing_tm_hex: Option<String>,
        /// Peg-in BTC outpoint(s) `<txid>:<vout>` to DROP from the sweep even though their
        /// PegInRequest still sits at the peg-in address. Use for deposits already swept into
        /// the current treasury whose PIR was never consumed by a mint — re-including them would
        /// double-spend an outpoint that no longer exists. Repeatable.
        #[arg(long = "exclude-pegin")]
        exclude_pegin: Vec<String>,
    },
    /// Rebuild the completed-peg-outs trie from Cardano history and persist it to
    /// `protocol.state_dir`.
    ///
    /// Needed on a cold start, after losing `cpo-trie.json`, or when joining a
    /// bridge that already has peg-out history: without a correct trie this node
    /// proposes roots its peers refuse, and refuses the roots they propose.
    ///
    /// The rebuild needs the inline datums of already-SPENT outputs, which a
    /// UTxO-set API cannot serve. Two backends can supply them: Kupo when
    /// `cardano.kupo_url` is set (recommended for SPOs — one request per address),
    /// otherwise the Blockfrost-compatible API from `cardano.blockfrost_project_id`,
    /// which walks the address transaction history instead (many more requests;
    /// meant for test environments, demos, and non-SPO tooling).
    ///
    /// Both run the SAME algorithm. Every step is checked against the root each
    /// Treasury Movement attested, so a garbled data-availability hint costs time,
    /// never correctness.
    ReconstructCpoTrie {
        #[arg(long)]
        config: Option<String>,
        /// Print the reconstructed root and entry count without writing
        /// `cpo-trie.json`.
        #[arg(long)]
        dry_run: bool,
    },
    /// Rebuild the swept peg-ins (SPI) trie from Cardano history — the SPI twin
    /// of `reconstruct-cpo-trie`. Walks the treasury chain backward from the
    /// bridge state singleton's head over the spent UnconfirmedTm records,
    /// records every confirmed TM's inputs per [SPI-1]/[SPI-3], and refuses to
    /// persist a root the singleton's attested spi_root disagrees with.
    ReconstructSpiTrie {
        #[arg(long)]
        config: Option<String>,
        /// Print the reconstructed root and entry count without writing
        /// `spi-trie.json`.
        #[arg(long)]
        dry_run: bool,
    },
    /// Read-only: chain-source the current Bitcoin treasury from Cardano state
    /// (rev 5.4). Reads the bridge-state singleton's head and amount, checks the
    /// head's scriptPubKey against the candidate treasury trees, and prints its
    /// outpoint / value / scriptPubKey, whether it matches the demo Y_51 treasury
    /// keys, and whether a movement is already in flight against it. Posts
    /// nothing — the same read the auto-mover and `sweep-pegins` use to source
    /// the treasury.
    ShowTreasury {
        #[arg(long)]
        config: Option<String>,
    },
    /// Read-only: print the bridge Config UTxO's operational parameters (WI-040,
    /// rev-5.4 layout) — the values every SPO must agree on to build
    /// byte-identical Treasury Movements. Reads `cardano.config_address` +
    /// `cardano.config_nft_policy_id` at the current chain tip and reports the
    /// nested `params` record (#7): the fee rate, the per-peg-out fee floor,
    /// `min_peg_out_fbtc` and the schedule — plus whether this node would instead
    /// fall back to its local `bitcoin.fee_rate_sat_per_vb`. Posts nothing.
    ShowConfigParams {
        #[arg(long)]
        config: Option<String>,
    },
    /// Background auto-mover (WI-028, N19): at each batch opportunity on the
    /// protocol's slot grid — B_i = epoch_start + i*tm_batch_interval, from the Config
    /// `schedule` — chain-source the current treasury from Cardano (no config edits),
    /// freeze the peg-ins + peg-outs eligible at that batch's stability cutoff, and —
    /// if the treasury is free and there is work — build, FROST-sign and post the next
    /// Treasury Movement. Falls back to `--interval-secs` ticks when no grid is
    /// configured. Skips ticks when nothing is pending or a
    /// movement is already in flight (waits for binocular `confirm-tmtx` to advance
    /// the tip). Runs on the CURRENT contracts with no leader election, so run ONE
    /// instance per bridge. Use `--once` for a single tick and omit `--broadcast`
    /// for a dry run (build + print, no post).
    RunMover {
        #[arg(long)]
        config: Option<String>,
        /// N2C socket — unused on the Blockfrost path the mover uses; defaulted so a
        /// config-driven mover needs only `--config`.
        #[arg(long, default_value = "/dev/null")]
        cardano_socket: String,
        #[arg(long, default_value_t = 1)]
        cardano_magic: u64,
        /// Poll ceiling in seconds, and the tick cadence when there is no batch grid to
        /// follow. With a Config `schedule` the mover builds on the protocol's grid
        /// (B_i = epoch_start + i*tm_batch_interval) and this only bounds how long it
        /// sleeps between chain checks (clamped to 300s).
        #[arg(long, default_value_t = 60)]
        interval_secs: u64,
        /// Run a single tick and exit (for testing).
        #[arg(long)]
        once: bool,
        /// Post the built TM (Cardano + optional Bitcoin per config). Omit for a dry run.
        #[arg(long)]
        broadcast: bool,
        /// Peg-in BTC outpoint(s) `<txid>:<vout>` to DROP from every sweep (see
        /// `sweep-pegins --exclude-pegin`). Repeatable.
        #[arg(long = "exclude-pegin")]
        exclude_pegin: Vec<String>,
    },
}

/// Load the config file and, as the same step, install the log subscriber.
///
/// Every subcommand funnels through here, and the level can come from the file,
/// so this is the earliest point at which the subscriber can be configured. The
/// one diagnostic below it is the unreadable-config error itself, which has to
/// stay a bare `eprintln!` — there is nothing to log through yet.
fn load_config(path: Option<&str>) -> HeimdallConfig {
    let cfg = match path {
        Some(p) => HeimdallConfig::from_file(std::path::Path::new(p)).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }),
        None => HeimdallConfig::default(),
    };
    heimdall::logging::init(&cfg.log);
    cfg
}

/// Run the WI-053 startup checks and refuse to start if any of them failed.
///
/// Prints the whole report either way — an operator watching a fresh install needs
/// to see WHICH bridge and WHICH contracts this node resolved, not merely that it
/// started. Nothing here spends: steps 5 and 6 name the command and stop.
fn run_preflight_gate(cfg: &HeimdallConfig) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let report = rt.block_on(heimdall::preflight::preflight(cfg));
    print!("{}", report.render());
    match report.first_failure() {
        None => Ok(()),
        Some(f) => Err(format!(
            "startup preflight failed at step {} ({}) — refusing to start. \
             Fix what is listed above and re-check with \
             `heimdall run-mover --config <file> --once`.",
            f.n, f.title
        )),
    }
}

/// Resolve a per-bridge value from the CLI flag (override) else the config, exiting
/// with a message that names both the `--flag` and the `cardano.<key>` it can come from.
/// The bridge's identifiers, from the Config UTxO (WI-070).
///
/// The CLI counterpart of what `run_demo` does at startup: one authenticated
/// read, and every peg-in / peg-out / TM identifier derived from it. These used
/// to be four `--flags` backed by four `[cardano]` keys, which is four chances
/// to name a bridge other than the one the Config names.
fn resolve_bridge_contracts(
    cfg: &HeimdallConfig,
) -> Result<heimdall::cardano::config_params::BridgeContracts, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let view = rt.block_on(config_view_async(cfg))?.ok_or(
        "this command needs the bridge Config: set cardano.config_address and \
         cardano.config_nft_policy_id. The peg-in, peg-out and TM identifiers come from it — \
         they are no longer config keys, because a typed copy that disagrees with the chain \
         names a bridge that does not exist and reads as 'nothing pending'",
    )?;
    let mainnet = cfg.cardano.is_mainnet()?;
    view.params
        .bridge_contracts(mainnet)
        .map_err(|e| e.to_string())
}

/// The federation one-shot outpoint for a one-shot CLI command: the explicit
/// flag when given, otherwise Config #12.
///
/// The flag stays for the two cases the chain cannot serve — a GENESIS command
/// that runs before the Config exists, and building against a bridge whose
/// Config this node is not reading — but it is no longer something an operator
/// types for ordinary work (WI-090).
fn resolve_one_shot(cfg: &HeimdallConfig, arg: Option<&str>) -> Result<String, String> {
    if let Some(s) = arg {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let view = rt.block_on(config_view_async(cfg))?.ok_or(
        "--registry-bootstrap was not given and there is no bridge Config to read it from. \
         It is Config #12 since WI-090: set cardano.config_address and \
         cardano.config_nft_policy_id, or pass the outpoint explicitly — which is what a \
         genesis command does, since it runs before the Config exists",
    )?;
    Ok(view.params.federation_one_shot)
}

/// WI-092: the air-gapped half of `register-spo`, as a command that runs where
/// the cold key lives.
///
/// Prints the four flags `register-spo` needs and nothing else, so the operator
/// copies values rather than reproducing a signing scheme. Both signatures are
/// verified here — the same check `spos_registry.ak` performs — so a wrong URL or
/// a wrong key file fails on this machine, before a fee is spent on the other.
fn run_sign_registration(
    cfg: &HeimdallConfig,
    cold_skey: Option<&str>,
    bifrost_skey: Option<&str>,
    bifrost_url: Option<&str>,
) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::Keypair;
    use heimdall::cardano::register_spo::{sign_registration, verify_registration};
    use pallas_crypto::key::ed25519;

    let bifrost_url = &resolve_bifrost_url(cfg, bifrost_url)?;
    let cold_src = cold_skey
        .or(cfg.cardano.cold_skey_path.as_deref())
        .ok_or("no cold key: pass --cold-skey or set cardano.cold_skey_path")?;
    let cold = ed25519::SecretKey::from(parse_key32(cold_src, "--cold-skey")?);

    let secp = Secp256k1::new();
    let bifrost = match bifrost_skey {
        Some(arg) => Keypair::from_seckey_slice(&secp, &parse_key32(arg, "--bifrost-skey")?)
            .map_err(|e| format!("--bifrost-skey: {e}"))?,
        None => cfg
            .load_bifrost_keypair(&secp)
            .map_err(|e| format!("no --bifrost-skey and [bifrost].skey_path: {e}"))?,
    };

    let sigs = sign_registration(&cold, &bifrost, bifrost_url.as_bytes());
    let bifrost_id_pk = bifrost.x_only_public_key().0.serialize();
    // The same verification spos_registry.ak runs. It cannot fail for keys this
    // command just signed with, which is the point: if it ever does, the message
    // construction here and there have diverged, and that must not reach a chain.
    let pool_id = verify_registration(&sigs, &bifrost_id_pk, bifrost_url.as_bytes())
        .map_err(|e| format!("self-check failed, refusing to print: {e}"))?;

    println!("pool id:  {}", hex::encode(pool_id));
    println!();
    println!("Pass these to `register-spo` on the node, with the SAME --bifrost-url:");
    println!();
    println!("    --bifrost-url {bifrost_url} \\");
    println!("    --cold-vkey {} \\", hex::encode(sigs.cold_vkey));
    println!("    --cold-sig {} \\", hex::encode(sigs.cold_sig));
    println!("    --bifrost-id-pk {} \\", hex::encode(bifrost_id_pk));
    println!("    --bifrost-sig {}", hex::encode(sigs.bifrost_sig));
    Ok(())
}

/// Whether this wallet already holds a reference script for `script_hash_hex`.
///
/// The deploy commands are otherwise unconditional, so running one twice parks a
/// SECOND copy of the same script and locks another ~55 ADA in it — for nothing,
/// since every consumer finds the first one by scanning this same wallet. Report
/// the existing UTxO and stop; `--force` is there for the one case that is not a
/// mistake, replacing a copy that is about to be spent.
fn ref_script_already_deployed(
    utxos: &[heimdall::cardano::bf_http::BfUtxo],
    script_hash_hex: &str,
    what: &str,
    force: bool,
) -> bool {
    use heimdall::cardano::ref_script::find_ref_script;
    let Some(found) = find_ref_script(utxos, script_hash_hex) else {
        return false;
    };
    if force {
        println!(
            "{what} reference script already at this wallet ({found}) — deploying another (--force)"
        );
        return false;
    }
    println!("{what} reference script already deployed at this wallet: {found}");
    println!("  Nothing to do: the commands that need it discover it here on their own.");
    println!(
        "  Deploying again would lock another ~55 ADA in a duplicate. Pass --force to do it anyway."
    );
    true
}

/// This node's Bifrost endpoint URL: the flag, else `[bifrost].url`.
///
/// One resolver for both `register-spo` and `sign-registration` because the
/// registration message commits to these EXACT bytes — a trailing slash or a
/// different port between the two invalidates both signatures, and the failure
/// says only "signature does not verify".
fn resolve_bifrost_url(cfg: &HeimdallConfig, arg: Option<&str>) -> Result<String, String> {
    arg.or(cfg.bifrost.url.as_deref())
        .map(str::to_owned)
        .ok_or_else(|| {
            "no Bifrost endpoint URL: pass --bifrost-url or set [bifrost].url. It is published \
             on chain and peers fetch this node's DKG rounds from it, so its port is also the \
             port the daemon binds"
                .to_string()
        })
}

fn main() {
    let cli = Cli::parse();
    // Stashed before the match because `load_config` — which installs the
    // subscriber, since the level can come from the file — cannot see the
    // globals from where it is called.
    heimdall::logging::set_cli_overrides(cli.log_level, cli.log_format);
    match cli.command {
        Commands::RunSpo {
            config,
            index,
            min_signers,
            max_signers,
            base_port,
            deterministic,
            inject_fault,
            blockfrost_project_id,
            cardano_socket,
            cardano_magic,
            pegin_window_secs,
            pegin_poll_ms,
            cardano_mnemonic,
        } => {
            let mut cfg = load_config(config.as_deref());

            // CLI flags override TOML values.
            if let Some(v) = min_signers {
                cfg.demo.min_signers = v;
            }
            if let Some(v) = max_signers {
                cfg.demo.max_signers = v;
            }
            if let Some(v) = base_port {
                cfg.demo.base_port = v;
            }
            if let Some(ref v) = blockfrost_project_id {
                cfg.cardano.blockfrost_project_id = Some(v.clone());
            }
            if let Some(ref v) = cardano_socket {
                cfg.cardano.socket_path = Some(v.clone());
            }
            if let Some(v) = cardano_magic {
                cfg.cardano.network_magic = Some(v);
            }
            if let Some(v) = pegin_window_secs {
                cfg.protocol.pegin_collection_window_secs = v;
            }
            if let Some(v) = pegin_poll_ms {
                cfg.protocol.pegin_poll_interval_ms = v;
            }
            if let Some(ref v) = cardano_mnemonic {
                cfg.cardano.mnemonic = Some(v.clone());
            }
            // Env var fallback: keep the real seed out of heimdall.toml
            // and the repo. Precedence: CLI --cardano-mnemonic > TOML
            // cardano.mnemonic > $HEIMDALL_MNEMONIC.
            if cfg.cardano.mnemonic.is_none() {
                if let Ok(v) = std::env::var("HEIMDALL_MNEMONIC") {
                    if !v.trim().is_empty() {
                        cfg.cardano.mnemonic = Some(v);
                    }
                }
            }

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_spo(cfg, index, deterministic, inject_fault));
        }
        Commands::BootstrapTreasury {
            config,
            federation_csv_blocks,
        } => {
            let mut cfg = load_config(config.as_deref());
            if let Some(v) = federation_csv_blocks {
                cfg.bitcoin.federation_csv_blocks = Some(u32::from(v));
            }
            if let Err(e) = print_bootstrap_treasury(&cfg) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FrostTreasury {
            config,
            frost_key,
            y_federation,
            federation_csv_blocks,
        } => {
            let mut cfg = load_config(config.as_deref());
            if let Some(v) = federation_csv_blocks {
                cfg.bitcoin.federation_csv_blocks = Some(u32::from(v));
            }
            if let Err(e) =
                print_frost_treasury(&cfg, frost_key.as_deref(), y_federation.as_deref())
            {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::TreasurySelfSend {
            config,
            outpoint,
            amount_sat,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_treasury_self_send(&cfg, &outpoint, amount_sat) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::SignRegistration {
            config,
            cold_skey,
            bifrost_skey,
            bifrost_url,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_sign_registration(
                &cfg,
                cold_skey.as_deref(),
                bifrost_skey.as_deref(),
                bifrost_url.as_deref(),
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::BifrostId { config } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = print_bifrost_id(&cfg) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FederationDkg {
            config,
            timeout_secs,
            serve_after_secs,
        } => {
            let cfg = load_config(config.as_deref());
            let rt = tokio::runtime::Runtime::new().unwrap();
            if let Err(e) = rt.block_on(run_federation_dkg(&cfg, timeout_secs, serve_after_secs)) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FederationSign {
            config,
            message,
            signers,
            timeout_secs,
            serve_after_secs,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) =
                run_federation_sign(&cfg, &message, &signers, timeout_secs, serve_after_secs)
            {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FederationSpend {
            config,
            outpoint,
            amount_sat,
            y51,
            signers,
            timeout_secs,
            serve_after_secs,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_federation_spend(
                &cfg,
                &outpoint,
                amount_sat,
                y51.as_deref(),
                &signers,
                timeout_secs,
                serve_after_secs,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::WalletAddress { config } => {
            let cfg = load_config(config.as_deref());
            let mnemonic = resolve_mnemonic(&cfg).unwrap_or_else(|e| {
                error!("Error: {e}");
                std::process::exit(1);
            });
            match (
                heimdall::cardano::wallet::wallet_address_from_mnemonic(&mnemonic),
                heimdall::cardano::wallet::derive_payment_key(&mnemonic),
            ) {
                (Ok(addr), Ok(key)) => {
                    println!("wallet base address: {addr}");
                    println!(
                        "payment key hash:    {}",
                        heimdall::cardano::wallet::pub_key_hash_hex(&key)
                    );
                }
                (Err(e), _) | (_, Err(e)) => {
                    error!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::BootstrapTreasuryInfo {
            config,
            blueprint,
            registry_bootstrap,
            frost_key,
            identity_root,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_bootstrap_treasury_info(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                &frost_key,
                identity_root.as_deref(),
                submit,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::BootstrapRegistry {
            config,
            blueprint,
            registry_bootstrap,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_bootstrap_registry(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                submit,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::DeployRegistryRef {
            config,
            blueprint,
            registry_bootstrap,
            submit,
            force,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_deploy_registry_ref(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                submit,
                force,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::DeployFaultRef {
            config,
            blueprint,
            registry_bootstrap,
            kind,
            submit,
            force,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_deploy_fault_ref(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                &kind,
                submit,
                force,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::DeploySpoBansRef {
            config,
            blueprint,
            registry_bootstrap,
            ban_bootstrap,
            base_ban_duration_ms,
            max_faults_before_permanent,
            max_validity_window_ms,
            submit,
            force,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_deploy_spo_bans_ref(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                &ban_bootstrap,
                base_ban_duration_ms,
                max_faults_before_permanent,
                max_validity_window_ms,
                submit,
                force,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::InitScripts {
            config,
            blueprint,
            registry_bootstrap,
            ban_bootstrap,
            base_ban_duration_ms,
            max_faults_before_permanent,
            max_validity_window_ms,
            key_deposit,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_init_scripts(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                &ban_bootstrap,
                base_ban_duration_ms,
                max_faults_before_permanent,
                max_validity_window_ms,
                key_deposit,
                submit,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::RegisterSpo {
            config,
            blueprint,
            registry_bootstrap,
            cold_skey,
            cold_vkey,
            cold_sig,
            bifrost_skey,
            bifrost_id_pk,
            bifrost_sig,
            bifrost_url,
            registry_ref,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = RegisterSpoArgs {
                blueprint,
                registry_bootstrap,
                cold_skey,
                cold_vkey,
                cold_sig,
                bifrost_skey,
                bifrost_id_pk,
                bifrost_sig,
                bifrost_url,
                registry_ref,
                submit,
            };
            if let Err(e) = run_register_spo(&cfg, &args) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::UpdateY {
            config,
            blueprint,
            registry_bootstrap,
            new_key,
            epoch,
            signer_skey,
            signature,
            federation,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = UpdateYArgs {
                blueprint,
                registry_bootstrap,
                new_key,
                epoch,
                signer_skey,
                signature,
                federation,
                submit,
            };
            if let Err(e) = run_update_y(&cfg, &args) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::BootstrapBanList {
            config,
            blueprint,
            registry_bootstrap,
            ban_bootstrap,
            base_ban_duration_ms,
            max_faults_before_permanent,
            max_validity_window_ms,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_bootstrap_ban_list(
                &cfg,
                blueprint.as_deref(),
                registry_bootstrap.as_deref(),
                &ban_bootstrap,
                (
                    base_ban_duration_ms,
                    max_faults_before_permanent,
                    max_validity_window_ms,
                ),
                submit,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ApplyBan {
            config,
            blueprint,
            registry_bootstrap,
            accused_pool_id,
            evidence_hash,
            fault_kind,
            spo_bans_ref,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = ApplyBanArgs {
                blueprint,
                registry_bootstrap,
                accused_pool_id,
                evidence_hash,
                fault_kind,
                spo_bans_ref,
                submit,
            };
            if let Err(e) = run_apply_ban(&cfg, &args) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FaultProofMint {
            config,
            blueprint,
            registry_bootstrap,
            evidence_file,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = FaultProofMintArgs {
                blueprint,
                registry_bootstrap,
                evidence_file,
                submit,
            };
            if let Err(e) = run_fault_proof_mint(&cfg, &args) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ShowRoster {
            config,
            blueprint,
            registry_bootstrap,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_show_roster(&cfg, blueprint, registry_bootstrap) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::SweepPegins {
            config,
            cardano_socket,
            cardano_magic,
            treasury_outpoint,
            treasury_amount_sat,
            broadcast,
            existing_tm_hex,
            exclude_pegin,
        } => {
            let cfg = load_config(config.as_deref());
            let bridge = match resolve_bridge_contracts(&cfg) {
                Ok(b) => b,
                Err(e) => {
                    error!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = run_sweep_pegins(
                &cfg,
                &cardano_socket,
                cardano_magic,
                &bridge.pegin_script_address,
                &bridge.pegin_policy_id,
                treasury_outpoint.as_deref(),
                treasury_amount_sat,
                &bridge.pegout_script_address,
                &bridge.bridged_token_unit,
                broadcast,
                existing_tm_hex.as_deref(),
                &exclude_pegin,
                false, // auto_mode
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::RunMover {
            config,
            cardano_socket,
            cardano_magic,
            interval_secs,
            once,
            broadcast,
            exclude_pegin,
        } => {
            let cfg = load_config(config.as_deref());

            // WI-053: the startup gate runs BEFORE the per-value resolution below.
            // Order matters twice over. It is what this item exists to fix — the
            // first sign of a misconfiguration used to be a failed transaction,
            // and the worst case produced no sign at all (a node missing a Config
            // locator key ran the wall-clock fallback, which does not agree with
            // the other SPOs). And running it AFTER `resolve_arg` would be nearly
            // useless: that exits the process on the first unset key, so the
            // operator would get one bare line instead of the whole picture.
            if let Err(e) = run_preflight_gate(&cfg) {
                error!("Error: {e}");
                std::process::exit(1);
            }
            let bridge = match resolve_bridge_contracts(&cfg) {
                Ok(b) => b,
                Err(e) => {
                    error!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = run_mover(
                &cfg,
                &cardano_socket,
                cardano_magic,
                &bridge.pegin_script_address,
                &bridge.pegin_policy_id,
                &bridge.pegout_script_address,
                &bridge.bridged_token_unit,
                interval_secs,
                once,
                broadcast,
                &exclude_pegin,
            ) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ShowTreasury { config } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_show_treasury(&cfg) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ShowConfigParams { config } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_show_config_params(&cfg) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ReconstructCpoTrie { config, dry_run } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_reconstruct_cpo_trie(&cfg, dry_run) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ReconstructSpiTrie { config, dry_run } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_reconstruct_spi_trie(&cfg, dry_run) {
                error!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Apply the TM-NFT minting policy and the Config-UTxO locator to the chain. Requires
/// `cardano.tm_script_cbor`, `cardano.config_address` and `cardano.config_nft_policy_id` to be
/// configured together — posting has no scaffold fallback, and the Config UTxO locates the
/// bridge-state singleton the mint redeemer links against. Errors on a half-configured set.
fn apply_tm_policy(
    chain: BlockfrostCardanoChain,
    cfg: &HeimdallConfig,
) -> Result<BlockfrostCardanoChain, String> {
    // The Config-UTxO locator is needed by query_treasury (the singleton read)
    // independently of posting, so apply it whenever configured.
    let chain = match (
        &cfg.cardano.config_address,
        &cfg.cardano.config_nft_policy_id,
    ) {
        (Some(addr), Some(policy)) => {
            let unit = format!(
                "{policy}{}",
                cfg.cardano.config_nft_asset_name.as_deref().unwrap_or("")
            );
            chain.with_config_utxo(addr, &unit)
        }
        (None, None) => chain,
        _ => {
            return Err(
                "set both cardano.config_address and cardano.config_nft_policy_id (or neither)"
                    .into(),
            );
        }
    };
    match &cfg.cardano.tm_script_cbor {
        Some(cbor) => {
            if cfg.cardano.config_address.is_none() {
                return Err(
                    "cardano.tm_script_cbor requires cardano.config_address and \
                     cardano.config_nft_policy_id (the mint redeemer links against the config \
                     anchor)"
                        .into(),
                );
            }
            Ok(chain.with_tm_policy(cbor))
        }
        None => Ok(chain),
    }
}

async fn run_spo(
    cfg: HeimdallConfig,
    index: Option<u16>,
    deterministic: bool,
    inject_fault: Option<String>,
) {
    // The treasury's federation identity: the treasury_info datum where the bridge
    // has one, this node's `[bitcoin]` keys otherwise (WI-069). Fatal on failure —
    // it is an input to the treasury ADDRESS, so continuing on a guess means
    // signing for an address no other SPO is using.
    let federation = match resolve_federation(&cfg).await {
        Ok(f) => {
            info!(
                "[federation] Y_fed {}, csv {} — {}",
                hex::encode(f.y_fed.serialize()),
                f.csv_blocks,
                f.origin
            );
            f
        }
        Err(e) => {
            error!("Error: {e}");
            std::process::exit(1);
        }
    };

    // The fixture provides a fallback roster (SPO identities + ports)
    // until the on-chain SPO registry is wired.
    let fixture = heimdall::epoch::fixture::demo_static_fixture_from_config(&cfg, &federation);

    // The bridge Config, read ONCE (WI-070). It carries the contract identifiers
    // AND the ban/registry identities below, so both come from one read of one
    // authenticated UTxO.
    //
    // The WI-070 decision, made explicitly because the demo is why these were ever
    // local keys: the demo gets NO fixture route back. Either it runs against a
    // deployed bridge, in which case every identifier is the Config's like any
    // other node's; or it runs on the mock chain, where there is no bridge and it
    // needs none of them. The middle case the old keys served — a live chain with
    // hand-typed contract addresses — is exactly the divergence this removes.
    let bridge_config = match config_view_async(&cfg).await {
        Ok(v) => v,
        Err(e) => {
            error!("bridge Config: {e}");
            std::process::exit(1);
        }
    };
    let contracts = match bridge_config.as_ref() {
        None => None,
        Some(v) => {
            let mainnet = cfg.cardano.is_mainnet().unwrap_or_else(|e| {
                error!("Error: {e}");
                std::process::exit(1);
            });
            Some(v.params.bridge_contracts(mainnet).unwrap_or_else(|e| {
                error!("Error: {e}");
                std::process::exit(1);
            }))
        }
    };

    // Both live-chain routes scan real bridge addresses, and they are the Config's.
    //
    // The N2C route reaches here with `contracts == None` unavoidably: reading the
    // Config goes through Blockfrost (`config_locator` needs a project id), so a
    // socket-only node has no way to resolve one however it is configured. Say
    // that, rather than advising two keys that cannot help.
    let live_contracts = || {
        contracts.clone().unwrap_or_else(|| {
            if cfg.cardano.blockfrost_project_id.is_none() {
                error!(
                    "Error: a live-chain demo needs the bridge Config, and reading it \
                     currently requires cardano.blockfrost_project_id — an N2C/socket-only \
                     node cannot resolve the peg-in, peg-out and TM addresses at all. Set a \
                     Blockfrost project id (it may point at a local blockfrost-compatible \
                     backend), or leave both cardano.blockfrost_project_id and \
                     cardano.socket_path unset to run the offline fixture demo"
                );
            } else {
                error!(
                    "Error: a live-chain demo needs the bridge Config — set \
                     cardano.config_address and cardano.config_nft_policy_id. The peg-in, \
                     peg-out and TM addresses come from it; leave \
                     cardano.blockfrost_project_id and cardano.socket_path unset to run the \
                     offline fixture demo instead"
                );
            }
            std::process::exit(1);
        })
    };

    // Chain + pegin source selection:
    // blockfrost_project_id → Blockfrost for both chain + pegin source
    // socket_path           → pallas N2C for pegin source, mock chain
    // neither               → full mock
    let chain: Arc<dyn CardanoChain>;
    let pegin_source: Arc<dyn CardanoPegInSource>;

    if let Some(project_id) = cfg.cardano.blockfrost_project_id.as_deref() {
        let bridge = live_contracts();
        let treasury_config = TreasuryConfig {
            y_51: fixture.y_51,
            y_fed: fixture.y_fed,
            federation_csv_blocks: fixture.federation_csv_blocks,
            // The published refund delay ([CFG-9]). Read from the Config where one exists;
            // this demo path carries the same value the depositor tooling defaults to.
            pegin_refund_timeout_blocks: cfg.bitcoin.pegin_refund_timeout_blocks.unwrap_or(4320),
            treasury_outpoint: fixture.treasury_outpoint,
            treasury_value: fixture.treasury_value,
        };
        let mut bf_chain = BlockfrostCardanoChain::new(
            project_id,
            &bridge.tm_address,
            &bridge.tm_policy_id,
            heimdall::cardano::config_params::TM_ASSET_NAME_HEX,
            treasury_config,
            fixture.roster.clone(),
            cfg.cardano.blockfrost_url.as_deref(),
        )
        // Only reached when no Config UTxO is configured — with one, the batch's
        // fee rate is the Config's (WI-040).
        .with_local_fee_rate(cfg.bitcoin.fee_rate_sat_per_vb);

        // The on-chain bridge-state singleton, so BuildTm can cross-check the
        // persisted trie against it before signing anything. Config #4, so there is
        // no longer a way to run without the check.
        bf_chain = bf_chain.with_cpo_source(
            Some(bridge.bridge_state_policy_id.as_str()),
            cfg.cardano.kupo_url.as_deref(),
        );

        // Peg-out payments (WI-030). The address to scan and the fBTC unit whose
        // quantity is a request's locked amount are Config #7 and #2 — one
        // authenticated source, so the half-configured daemon this used to guard
        // against (peg-out-capable in its own report, blind in practice) can no
        // longer be expressed.
        info!("peg-out requests:     {}", bridge.pegout_script_address);
        bf_chain =
            bf_chain.with_pegout_source(&bridge.pegout_script_address, &bridge.bridged_token_unit);

        if let Some(mnemonic) = &cfg.cardano.mnemonic {
            let wallet_addr = heimdall::cardano::wallet::wallet_address_from_mnemonic(mnemonic)
                .expect("cardano.mnemonic must be a valid BIP-39 mnemonic");
            info!("Cardano wallet address: {wallet_addr}");
            bf_chain = bf_chain
                .with_mnemonic(mnemonic)
                .expect("cardano.mnemonic must be a valid BIP-39 mnemonic");
        }

        bf_chain = bf_chain.with_submit_config(cfg.cardano.submit_oracle);

        // Per-pool stake source for the DKG threshold (default Blockfrost;
        // "yaci_store" for a local yaci-devkit devnet).
        let stake_source =
            heimdall::cardano::stake::StakeSource::from_config(cfg.cardano.stake_source.as_deref())
                .unwrap_or_else(|e| panic!("cardano.stake_source: {e}"));
        bf_chain = bf_chain.with_stake_source(stake_source);
        bf_chain = bf_chain.with_demo_exclude_unstaked(cfg.cardano.demo_exclude_unstaked);

        // The bridge Config, read once at startup. It publishes the ban policy
        // (#8 and params[4..=6]), so a node needs no ban keys of its own — and an unreadable
        // one is fatal rather than a quiet fall back to whatever this operator
        // typed, which is how two nodes end up filtering different rosters.
        // On-chain SPO registry roster (WI-010): configured via
        // cardano.{registry_blueprint, registry_bootstrap, treasury_info_asset_name}.
        // Without it query_roster serves the fixture roster.
        match heimdall::cardano::roster::RegistryRosterSource::resolve(
            &cfg.cardano,
            bridge_config.as_ref().map(|v| &v.params),
        ) {
            Ok(Some(source)) => {
                info!("on-chain SPO registry: {}", source.registry_address);
                info!(
                    "note: eligible roster = registry − active bans; FROST threshold is \
                     stake-weighted (WI-012) — demo.min_signers is ignored on this path"
                );
                // N10c: the same treasury_info the roster is verified against is
                // the one a completed DKG rotates (Update-Y). READING that roster
                // needs only the published ids, but SPENDING the state UTxO needs
                // the compiled script — so the handoff is a capability to report,
                // not one the registry roster implies. Claiming it either way is
                // the expensive mistake: an elected leader that cannot submit
                // fails AFTER a full DKG and a distributed FROST authorization,
                // then repeats that every cycle with nothing in this log to
                // explain it.
                if source.can_hand_off_key() {
                    info!("on-chain key handoff:  enabled (Update-Y after each DKG)");
                } else {
                    warn!(
                        "on-chain key handoff:  NOT possible on this node — the roster comes \
                         from the Config's published identity (#9-#10) and there is no \
                         compiled treasury_info script to spend the state UTxO with. DKG runs \
                         and the group key is derived, but if this node is elected leader the \
                         Update-Y FAILS and the treasury is not handed over. Set \
                         cardano.registry_blueprint + cardano.treasury_policy_id to enable it"
                    );
                }
                bf_chain = bf_chain.with_registry_roster(source);
                // Ban filtering (WI-011/012): from the Config's published ban
                // policy (#8) where the bridge has one, else the local keys.
                match heimdall::cardano::ban_list::BanListSource::resolve(
                    &cfg.cardano,
                    bridge_config.as_ref().map(|v| &v.params),
                ) {
                    Ok(Some(bans)) => {
                        info!(
                            "on-chain ban list:     {} ({})",
                            bans.ban_address, bans.origin
                        );
                        bf_chain = bf_chain.with_ban_source(bans);
                        match heimdall::cardano::blockfrost_chain::DkgFaultBanFlow::from_config(
                            &cfg.cardano,
                            bridge_config.as_ref().map(|v| &v.params),
                        )
                        .await
                        {
                            Ok(Some(flow)) => {
                                info!("automatic DKG fault banning: enabled");
                                bf_chain = bf_chain.with_dkg_fault_ban_flow(flow);
                            }
                            // Reading the ban list and enforcing faults are
                            // separate (WI-060): the roster is filtered either
                            // way, and detection already excludes a cheater
                            // from the ceremony. Without the enforcement keys
                            // the cheating simply costs nothing on chain.
                            Ok(None) => info!(
                                "automatic DKG fault banning: disabled (no fault-enforcement \
                                 keys) — roster IS ban-filtered; faults are detected and \
                                 excluded but not published on chain"
                            ),
                            Err(e) => {
                                error!("DKG fault-ban flow config: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    // Unreachable on this arm since WI-060: the registry roster
                    // is configured here, and `from_config` now refuses rather
                    // than returning None in that case. Kept as a loud failure
                    // rather than a silent unfiltered roster.
                    Ok(None) => {
                        error!(
                            "ban list config: the registry roster is configured but \
                             BanListSource resolved to none — refusing to run an \
                             unfiltered roster"
                        );
                        std::process::exit(1);
                    }
                    // Fail fast with a clear message — NOT a degrade-to-unfiltered:
                    // an unread ban list would admit banned SPOs to the roster. A
                    // misconfig (e.g. ban_bootstrap set but the fault-policy set /
                    // ban-schedule params missing) must stop startup, not silently
                    // disable ban filtering.
                    Err(e) => {
                        error!("ban list config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                error!("registry roster config: {e}");
                std::process::exit(1);
            }
        }

        let bf_chain = apply_tm_policy(bf_chain, &cfg).expect("invalid TM policy config");

        // Everything resolved above is what THIS PROCESS SAW AT BOOT. The
        // federation identity is chain state a governance Update can move, so
        // hand the chain the config it needs to re-resolve #8/#9-#10 on every
        // roster read — otherwise two honest nodes filter different rosters
        // according to when each was last restarted, which is the divergence
        // publishing those fields was meant to end. Startup keeps resolving them
        // anyway: it is what makes the report above real, and it is the only
        // moment a misconfiguration can still be refused before the node runs.
        let bf_chain = bf_chain.with_federation_refresh(cfg.cardano.clone());

        chain = Arc::new(bf_chain);
        pegin_source = Arc::new(BlockfrostPegInSource::new(
            project_id,
            &bridge.pegin_script_address,
            cfg.cardano.blockfrost_url.as_deref(),
        ));
    } else if let Some(socket) = cfg.cardano.socket_path.clone() {
        let magic = cfg
            .cardano
            .network_magic
            .expect("cardano.network_magic required with cardano.socket_path");
        chain = Arc::new(mock_chain_with_rpc(&cfg, fixture.clone()));
        pegin_source = Arc::new(
            PallasPegInSource::from_bech32(
                socket,
                NetworkMagic(magic),
                &live_contracts().pegin_script_address,
            )
            .expect("pallas source"),
        );
    } else {
        chain = Arc::new(mock_chain_with_rpc(&cfg, fixture.clone()));
        pegin_source = Arc::new(MockCardanoPegInSource::new());
    };

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rng: Arc<dyn RngSource> = if deterministic {
        Arc::new(SeededRngSource::new(*b"heimdall-demo-seed-v1-0123456789"))
    } else {
        Arc::new(OsRngSource)
    };

    // Identity (WI-014/WI-023): with an on-chain registry, this node's bifrost
    // key (from [bifrost].skey_path) locates its own roster entry
    // (own_participant). For the no-registry local demo there is no configured
    // key — the per-node identity AND its secret come from `--index` via the
    // fixture's deterministic keypairs.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let configured_keypair = cfg.load_bifrost_keypair(&secp).ok();
    // Whether this node has a real on-chain identity key. Drives whether the
    // epoch loop re-derives its index from the live roster (registry path) or
    // trusts the static configured index (fixture/`--index` demo).
    let has_configured_key = configured_keypair.is_some();

    // WI-014: query the roster at the REAL current epoch (was hardcoded 0).
    let epoch = chain
        .current_epoch()
        .await
        .expect("query current chain epoch");
    let roster = chain
        .query_roster(epoch)
        .await
        .expect("query initial roster");

    let (id, me, keypair) = match configured_keypair {
        // A [bifrost].skey_path was configured: locate ourselves by that key.
        Some(kp) => {
            let bifrost_id_pk = kp.x_only_public_key().0.serialize();
            match roster.own_participant(&bifrost_id_pk) {
                Some((id, info)) => (id, info.clone(), kp),
                None => {
                    // Not in the roster by bifrost key. Against a real registry
                    // roster this is fatal (not registered / banned / URL-excluded).
                    // Fall back to --index ONLY for the legacy fixture demo.
                    let ix = index.unwrap_or_else(|| {
                        panic!(
                            "this node's bifrost_id_pk ({}) is not in the eligible roster for \
                             epoch {epoch} (not registered / banned / URL-excluded) and no \
                             --index fallback was given — refusing to run DKG under an unknown \
                             identity",
                            hex::encode(bifrost_id_pk)
                        )
                    });
                    let id = Identifier::try_from(ix).unwrap();
                    let info = roster
                        .participants
                        .get(&id)
                        .unwrap_or_else(|| panic!("--index {ix} is not in the roster"))
                        .clone();
                    warn!(
                        "[demo] bifrost_id_pk not found in roster; falling back to \
                         --index {ix} (fixture/legacy demo only)"
                    );
                    (id, info, kp)
                }
            }
        }
        // No configured key (WI-023 no-registry demo): both identity and secret
        // come from --index via the fixture's deterministic keypairs, so 3
        // processes sharing one config differ only by `--index`.
        None => {
            let ix = index.unwrap_or_else(|| {
                panic!(
                    "no bifrost identity key — set [bifrost].skey_path (on-chain registry \
                     deployments) or pass --index N for the local no-registry fixture demo"
                )
            });
            let id = Identifier::try_from(ix).unwrap();
            let info = roster
                .participants
                .get(&id)
                .unwrap_or_else(|| panic!("--index {ix} is not in the roster"))
                .clone();
            let kp = *fixture.bifrost_keypairs.get(&id).unwrap_or_else(|| {
                panic!(
                    "--index {ix}: no fixture bifrost keypair — the no-registry demo derives \
                     each node's key from the fixture; set [bifrost].skey_path for a registry \
                     deployment"
                )
            });
            (id, info, kp)
        }
    };
    // The registered `bifrost_url` is what peers FETCH from; it is not necessarily
    // where this process should listen. Unset, the two are the same number — which
    // is fine on a directly-exposed node and impossible behind a reverse proxy that
    // wants the public port for itself. `http.listen_port` separates them, and also
    // lifts the explicit-`:port` requirement on the URL, so a node can advertise a
    // clean `https://spo.example.com` and terminate TLS upstream.
    let port = match cfg.http.listen_port {
        Some(p) => {
            info!(
                "listening on {}:{p} (http.listen_port); peers are directed to {}",
                cfg.http.bind_address, me.bifrost_url
            );
            p
        }
        None => port_from_url(&me.bifrost_url).unwrap_or_else(|e| panic!("{e}")),
    };
    let my_pool_id: [u8; 28] = me.pool_id.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "this node's roster entry has no 28-byte pool_id (got {} bytes) — the \
             authenticated DKG transport needs a registered on-chain roster",
            me.pool_id.len()
        )
    });
    let spo_label = hex::encode(&my_pool_id[..4]);
    let net = Arc::new(HttpPeerNetwork::new(secp, keypair, my_pool_id));
    // The [SPI-4] proof route loads the swept peg-ins trie from
    // `protocol.state_dir` per request; without it the route answers 503.
    net.shared_state().write().await.state_dir = cfg
        .protocol
        .state_dir
        .as_deref()
        .map(std::path::PathBuf::from);
    let app = router(net.shared_state());
    let bind_addr = &cfg.http.bind_address;
    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .expect("bind");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    info!(
        "=== Heimdall SPO {spo_label} ({}-of-{}) ===",
        roster.min_signers, roster.max_signers
    );
    info!("Listening on {bind_addr}:{port}");
    info!(
        "Waiting for the other {} SPOs to come online...",
        roster.max_signers - 1
    );

    let peers: Arc<dyn PeerNetwork> = net;
    // On the registry path, carry this node's stable bifrost key so the loop can
    // re-derive its live index each epoch (see `epoch_start_phase`). Empty on the
    // fixture path, which has no on-chain roster and keeps the configured index.
    let own_bifrost_id_pk = if has_configured_key {
        keypair.x_only_public_key().0.serialize().to_vec()
    } else {
        Vec::new()
    };
    let pegin_policy_id = contracts
        .as_ref()
        .map(|c| {
            let mut out = [0u8; 28];
            // `bridge_contracts` produced this from a 28-byte Config field.
            out.copy_from_slice(&hex::decode(&c.pegin_policy_id).unwrap_or_default());
            out
        })
        .unwrap_or([0u8; 28]);
    let mut config = cfg.to_epoch_config(
        SpoIdentity {
            identifier: id,
            bifrost_id_pk: own_bifrost_id_pk,
            port,
        },
        pegin_policy_id,
    );
    // DEMO-ONLY fault injection (--inject-fault); parse-and-die on a bad kind.
    config.inject_fault = match inject_fault.as_deref() {
        None => None,
        Some(s) => match s.parse::<heimdall::epoch::state::InjectFault>() {
            Ok(k) => Some(k),
            Err(e) => {
                error!("[demo] {e}");
                std::process::exit(2);
            }
        },
    };
    if let Some(k) = config.inject_fault {
        warn!("[demo] ⚠ FAULT INJECTION ENABLED: {k:?} — this node will misbehave in DKG");
    }

    // Phase 1 (WI-095): before the first Update-Y the treasury is locked under
    // y_federation and the federation — not a DKG roster — signs the movement's
    // key path. Loaded unconditionally because WHICH phase the bridge is in is
    // chain state the machine reads per epoch, not something to decide here: a
    // node can start in Phase 1 and still be running when the first Update-Y
    // makes it a Phase-2 node.
    config.phase1_signer = match phase1_signer(&cfg) {
        Ok(v) => v,
        Err(e) => {
            error!("[demo] federation share: {e}");
            std::process::exit(2);
        }
    };
    if let Some(fed) = config.phase1_signer.as_ref() {
        info!(
            "[demo] federation share loaded: {}-of-{} (signs treasury movements while the \
             bridge is in Phase 1)",
            fed.roster.min_signers, fed.roster.max_signers
        );
    }

    let t0 = Instant::now();
    // The epoch loop backs off and re-enters `Idle` on EVERY error, so it does
    // not return Err at all today — this arm is unreachable by construction and
    // kept only because the signature is still `EpochResult`. It must NOT go
    // back to parking on Ctrl-C: that is exactly what froze an honest node on a
    // stale roster (2026-07-22), because re-deriving the roster is something
    // only the loop does. If a future change reintroduces an error exit, say so
    // plainly and let the supervisor restart us.
    let tm = match run_epoch_loop(chain, pegin_source, peers, clock, rng, &config).await {
        Ok(tm) => tm,
        Err(e) => {
            error!("[demo] epoch loop returned unexpectedly: {e}");
            error!("[demo] this should not happen — the loop is meant to retry indefinitely.");
            std::process::exit(1);
        }
    };
    info!("Cycle complete ({:.2?})", t0.elapsed());

    // ── Bitcoin TM transaction summary ──────────────────────────────────────
    info!("── Bitcoin Treasury Movement ──");
    info!("  txid:    {}", tm.txid);
    info!("  inputs:  {}", tm.unsigned_tx.input.len());
    for (i, (inp, prevout)) in tm
        .unsigned_tx
        .input
        .iter()
        .zip(tm.prevouts.iter())
        .enumerate()
    {
        info!(
            "    [{}] {}:{} — {} sat  script={}",
            i,
            inp.previous_output.txid,
            inp.previous_output.vout,
            prevout.value.to_sat(),
            hex::encode(prevout.script_pubkey.as_bytes()),
        );
    }
    info!("  outputs: {}", tm.unsigned_tx.output.len());
    for (i, out) in tm.unsigned_tx.output.iter().enumerate() {
        info!(
            "    [{}] {} sat  script={}",
            i,
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes()),
        );
    }
    let signed_bytes = bitcoin::consensus::encode::serialize(&tm.unsigned_tx);
    info!("  size:    {} bytes", signed_bytes.len());
    info!("  hex:     {}", hex::encode(&signed_bytes));

    info!("=== SPO {spo_label} cycle complete ===");

    info!("Server still running on {bind_addr}:{port}; press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await.ok();
}

/// Build a `MockCardanoChain` from the fixture, wiring up the Bitcoin
/// RPC if `bitcoin.rpc_url` is set in the config.
fn mock_chain_with_rpc(
    cfg: &HeimdallConfig,
    fixture: heimdall::epoch::fixture::StaticFixture,
) -> MockCardanoChain {
    let mut chain = MockCardanoChain::new(fixture);
    if let Some(rpc_url) = &cfg.bitcoin.rpc_url {
        chain = chain.with_btc_rpc(
            rpc_url,
            cfg.bitcoin.rpc_user.clone(),
            cfg.bitcoin.rpc_pass.clone(),
        );
    }
    chain
}

/// The local HTTP bind port, from this node's OWN registered bifrost_url.
/// Parses the URL properly (a naive `rsplit(':')` mishandles paths, IPv6
/// hosts, and userinfo that the roster's URL validation accepts) and
/// requires an explicit `:<port>` — peers fetching FROM a URL can rely on
/// scheme defaults, but the node cannot guess which local port to serve on.
fn port_from_url(url: &str) -> Result<u16, String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.port())
        .ok_or_else(|| {
            format!(
                "this node's bifrost_url {url:?} has no explicit ':<port>' — the demo binds its \
                 local HTTP server to that port, so register a URL ending in ':<port>'"
            )
        })
}

/// Derive the bootstrap federation keypair from `bitcoin.y_fed_seed_hex`.
/// At bootstrap Y_51 = Y_fed, so the seed's secret key signs every TM input
/// and its x-only pubkey is both the treasury and peg-in internal key.
///
/// For the commands that SIGN with the federation key. Since WI-069 the seed is
/// optional in the config — a plain SPO reads the public key from the
/// `treasury_info` datum — so it is required here by name, and the published key
/// cannot stand in for it. Parsing lives in `cardano::federation` so this and
/// the depositor demo cannot drift apart over what a valid seed is.
fn y_fed_keypair(
    _secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    cfg: &HeimdallConfig,
) -> Result<
    (
        bitcoin::secp256k1::SecretKey,
        bitcoin::key::UntweakedPublicKey,
    ),
    String,
> {
    let seed_hex = configured_seed(cfg).ok_or_else(|| {
        // A ceremony federation gets a different answer, because the problem is
        // different: the key is not missing, it is SHARED, and no single node can
        // produce this signature at all.
        if federation_share(cfg).ok().flatten().is_some() {
            "this command signs with the federation key as a SINGLE key, and this node holds a \
             SHARE of a t-of-n federation key — no one node can produce that signature alone. \
             For Update-Y, run `heimdall federation-sign --message <the sign message printed \
             above>` together with the other members and pass the result back as --signature. \
             `treasury-self-send` has no distributed form: fund the genesis anchor directly at \
             the address `bootstrap-treasury` prints, instead of normalising a funding tx"
                .to_string()
        } else {
            "bitcoin.y_fed_seed_hex is unset — this command SIGNS with the federation key, so \
             the public key published in the Config datum cannot stand in for it"
                .to_string()
        }
    })?;
    let kp = heimdall::cardano::federation::keypair_from_seed_hex(seed_hex)
        .map_err(|e| e.to_string())?;
    Ok((kp.secret_key(), kp.x_only_public_key().0))
}

/// The operator's configured federation seed, treating blank as ABSENT — the
/// shape produced by uncommenting the packaged template's own `y_fed_seed_hex = ""`.
fn configured_seed(cfg: &HeimdallConfig) -> Option<&str> {
    cfg.bitcoin
        .y_fed_seed_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Parse a `<txid>:<vout>` outpoint.
fn parse_outpoint(s: &str) -> Result<bitcoin::OutPoint, String> {
    use std::str::FromStr;
    bitcoin::OutPoint::from_str(s)
        .map_err(|e| format!("outpoint must be <txid>:<vout>, got '{s}': {e}"))
}

/// The LOCALLY configured federation CSV timelock.
///
/// For the federation-ops and genesis commands only — the ones run by whoever
/// holds the seed, and (in `bootstrap-treasury`'s case) before any chain state
/// exists to read. Every other path takes the delay from the `treasury_info`
/// datum via [`resolve_federation`]. There is no default (WI-069): a guessed
/// delay builds a different Taproot tree, so the leaf is not in it and the spend
/// simply does not validate.
fn csv_blocks_u16(cfg: &HeimdallConfig) -> Result<u16, String> {
    let blocks = cfg.bitcoin.federation_csv_blocks.ok_or(
        "bitcoin.federation_csv_blocks is unset — it is an input to the treasury address, so \
         there is no safe default. Set it to the delay this treasury was locked with",
    )?;
    u16::try_from(blocks).map_err(|_| {
        format!(
            "federation_csv_blocks ({blocks}) exceeds u16::MAX ({})",
            u16::MAX
        )
    })
}

/// TM parameters for the SINGLE-SIGNER admin spends (`treasury-self-send`,
/// `federation-spend`): the local `bitcoin.fee_rate_sat_per_vb`, no selection
/// floors.
///
/// Legitimate here precisely because these transactions have no co-signers — one
/// operator's key spends, so there is no cross-SPO agreement for a local value to
/// break. Every path that FROST-signs reads the Config UTxO instead
/// ([`batch_params`], `heimdall::cardano::config_params`).
///
/// The per-peg-out PROTOCOL fee is not here: since rev 5.1 each request pins its
/// own fee in its datum, and `peg-out.ak` binds the completed-peg-outs trie value
/// against that value. `bitcoin.per_pegout_fee_sat` survives only as the fee this
/// node's own `pegout-request` CLI writes into a new request.
fn dev_tm_params_from_cfg(cfg: &HeimdallConfig) -> heimdall::bitcoin::tm_builder::TmParams {
    heimdall::bitcoin::tm_builder::TmParams::fee_rate_only(cfg.bitcoin.fee_rate_sat_per_vb)
}

/// Freeze the batch's parameters for the CLI sweep path (`sweep-pegins` /
/// `run-mover`), the mirror of `CardanoChain::query_batch_snapshot`.
///
/// Returns the TM parameters and the snapshot's chain time (POSIX ms, the
/// peg-out freshness filter's "now"; `None` when there is no Config UTxO to
/// snapshot, leaving the caller to source its own). With a Config
/// UTxO configured every value is the chain's and this node's `bitcoin.*fee*`
/// keys are ignored — which is what lets two operators with different TOMLs
/// co-sign the same TM. Without one it falls back to those keys and says so.
/// What one batch opportunity is built against: the parameters, the chain "now",
/// the tip the creation-slot resolver measures against, and the grid opportunity
/// itself.
struct SweepBatch {
    params: heimdall::bitcoin::tm_builder::TmParams,
    /// Chain tip time (POSIX ms); `None` when there is no Config UTxO to snapshot.
    now_ms: Option<i64>,
    /// `(slot, time_ms)` of the snapshot, for resolving request creation slots on a
    /// backend that omits `slot` from `/txs`.
    tip: Option<(u64, i64)>,
    /// The batch opportunity in force, when this deployment has a grid.
    batch: heimdall::epoch::batch::BatchWindow,
}

fn batch_params(
    rt: &tokio::runtime::Runtime,
    cfg: &HeimdallConfig,
    verbose: bool,
) -> Result<SweepBatch, String> {
    use heimdall::cardano::config_params::{ParamSource, fetch_param_snapshot, resolve_tm_params};

    let local = cfg.bitcoin.fee_rate_sat_per_vb;
    let Some(loc) = config_locator(cfg) else {
        let (p, _) = resolve_tm_params(None, local);
        return Ok(SweepBatch {
            params: p,
            now_ms: None,
            tip: None,
            batch: heimdall::epoch::batch::BatchWindow::NoGrid,
        });
    };
    let snapshot = rt.block_on(fetch_param_snapshot(
        &loc.base_url,
        &loc.project_id,
        &loc.address,
        &loc.nft_unit,
    ))?;
    if verbose {
        let t = &snapshot.config.params.tunables;
        info!(
            "  operational params (Config {} @ slot {}): fee_rate={} sat/vB, \
             per_pegout_fee floor={} sat, min_peg_out_fbtc={} sat",
            snapshot.config.utxo,
            snapshot.slot,
            t.fee_rate_sat_per_vb,
            t.per_pegout_fee_floor,
            t.min_peg_out_fbtc,
        );
    }
    let time_ms = snapshot.time_ms;
    let (p, src) = resolve_tm_params(Some(&snapshot), local);
    if let ParamSource::LocalOverride(why) = &src {
        warn!(
            "[params] building on the LOCAL bitcoin.fee_rate_sat_per_vb ({local} \
             sat/vB) — {why}. Co-signers reading a different value build different TM bytes."
        );
    }
    let batch = rt.block_on(heimdall::cardano::config_params::batch_at(
        &loc.base_url,
        &loc.project_id,
        &snapshot,
    ));
    if let (true, Some(b)) = (verbose, batch.open()) {
        info!(
            "  batch B_{} at slot {} (membership cutoff: created at or before slot {})",
            b.index, b.slot, b.cutoff_slot
        );
    }
    Ok(SweepBatch {
        params: p,
        now_ms: Some(time_ms),
        tip: Some((snapshot.slot, time_ms)),
        batch,
    })
}

/// Everything needed to fetch the bridge Config UTxO: the Blockfrost endpoint and
/// the (address, NFT unit) pair that identifies the singleton.
struct ConfigLocator {
    project_id: String,
    base_url: String,
    address: String,
    nft_unit: String,
}

/// The Config locator, when this node is configured to locate it
/// (`cardano.config_address` + `cardano.config_nft_policy_id` + Blockfrost).
fn config_locator(cfg: &HeimdallConfig) -> Option<ConfigLocator> {
    let (pid, addr, policy) = (
        cfg.cardano.blockfrost_project_id.as_deref()?,
        cfg.cardano.config_address.as_deref()?,
        cfg.cardano.config_nft_policy_id.as_deref()?,
    );
    Some(ConfigLocator {
        project_id: pid.to_string(),
        base_url: heimdall::cardano::bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref()),
        address: addr.to_string(),
        nft_unit: format!(
            "{policy}{}",
            cfg.cardano.config_nft_asset_name.as_deref().unwrap_or("")
        ),
    })
}

/// Read the bridge Config UTxO, when this node is pointed at one.
///
/// `Ok(None)` means no Config is configured at all — not that the read failed.
/// Callers that resolve a published identity fall back to their local keys on
/// `None` and propagate a genuine read error.
fn config_view(
    rt: &tokio::runtime::Runtime,
    cfg: &HeimdallConfig,
) -> Result<Option<heimdall::cardano::config_params::ConfigView>, String> {
    rt.block_on(config_view_async(cfg))
}

/// [`config_view`] for callers already inside the runtime.
async fn config_view_async(
    cfg: &HeimdallConfig,
) -> Result<Option<heimdall::cardano::config_params::ConfigView>, String> {
    let Some(loc) = config_locator(cfg) else {
        return Ok(None);
    };
    heimdall::cardano::config_params::fetch_config(
        &loc.base_url,
        &loc.project_id,
        &loc.address,
        &loc.nft_unit,
    )
    .await
    .map(Some)
}

/// Resolve the treasury's federation identity (WI-069).
///
/// Walks the whole chain from the one Config NFT: Config #9/#10 name the
/// `treasury_info` policy and state-NFT, its script hash gives the address, and
/// that UTxO's datum carries `y_federation` (#2) and `federation_csv_blocks`
/// (#3). No new field and no extra query — this is the same snapshot the roster
/// is read from.
///
/// A read failure is NOT swallowed into the local fallback. "The bridge publishes
/// nothing" and "we could not ask" have different right answers, and taking the
/// local value on the second reintroduces exactly the per-operator divergence
/// this replaces. `Ok(None)` from either resolve step means genuinely no on-chain
/// registry — the fixture-roster demo — and only then do the local keys apply.
async fn resolve_federation(
    cfg: &HeimdallConfig,
) -> Result<heimdall::cardano::federation::FederationIdentity, String> {
    use heimdall::cardano::roster::RegistryRosterSource;

    // Rev 5.5: both values are Config fields (#11 and params[7]), so this needs
    // the Config read every command already performs and no treasury_info fetch
    // at all ([CFG-6]). RegistryRosterSource::resolve stays as the check that the
    // Config names a locatable roster — a Config that does not is not a bridge
    // this node can join, federation identity or no.
    let config = config_view_async(cfg).await?;
    let _source = RegistryRosterSource::resolve(&cfg.cardano, config.as_ref().map(|v| &v.params))
        .map_err(|e| format!("cannot locate the treasury_info state: {e}"))?;

    // Since WI-087 the key this node may hold locally is either the single seed or
    // a share of a ceremony key. Reading it here means the published value is
    // cross-checked against what this node actually signs with, whichever of the
    // two that is.
    let share = federation_share(cfg)?
        .map(|s| s.federation_setup_y().map_err(|e| e.to_string()))
        .transpose()?;
    heimdall::cardano::federation::resolve(&cfg.bitcoin, share, config.as_ref().map(|v| &v.params))
        .map_err(|e| format!("{e}\n{}", e.fix()))
}

/// Freeze the scanned peg-outs against `batch` — the CLI sweep's half of the rule
/// the epoch machine applies in `freeze_pegouts` (spec §TM batches; plan N19).
///
/// Both drivers must reach the same set from the same chain state, so the rule lives
/// in `epoch::batch` and each driver only supplies its own request type. Without a
/// grid (no Config schedule, or an unreadable epoch anchor) the cutoff is skipped and
/// only the FIFO order and the capacity cap apply — the pre-N19 behaviour, minus the
/// dependence on whatever order the chain query answered in.
fn freeze_sweep_pegouts(
    requests: Vec<heimdall::cardano::pegout_datum::PegOutRequestData>,
    batch: Option<heimdall::epoch::batch::BatchSlot>,
) -> Vec<heimdall::cardano::pegout_datum::PegOutRequestData> {
    use heimdall::epoch::batch::{Caps, FifoKey, SpendVariant, freeze};

    let cap = Caps::for_variant(SpendVariant::KeyPath).max_pegouts;
    let key = |r: &heimdall::cardano::pegout_datum::PegOutRequestData| FifoKey {
        // Unresolved sorts last and is deferred under a real cutoff: a request whose
        // place in time we cannot establish must not be signed into a batch our
        // co-signers would place differently.
        created_slot: r.created_slot.unwrap_or(u64::MAX),
        tx_hash: r.outpoint[..32].try_into().unwrap_or([0u8; 32]),
        output_index: u32::from_le_bytes(r.outpoint[32..].try_into().unwrap_or([0u8; 4])),
    };

    let Some(batch) = batch else {
        let mut ordered = requests;
        ordered.sort_by_key(&key);
        ordered.truncate(cap);
        return ordered;
    };

    let frozen = freeze(requests, batch, cap, key);
    if frozen.deferred() > 0 {
        info!(
            "  batch freeze: {} peg-out(s) in, {} created after the cutoff (slot {}), {} over \
             the {cap}-peg-out capacity — deferred to a later batch",
            frozen.selected.len(),
            frozen.too_new.len(),
            batch.cutoff_slot,
            frozen.over_cap.len(),
        );
    }
    frozen.selected
}

/// Load this node's completed-peg-outs trie from `protocol.state_dir`.
///
/// No `state_dir`, or no file yet, means the genesis (empty) trie — correct on a
/// bridge that has completed no peg-out, and loud everywhere else: every root this
/// node then proposes is refused by peers whose trie is populated.
fn cpo_trie_from_cfg(cfg: &HeimdallConfig) -> Result<heimdall::cardano::cpo_trie::CpoTrie, String> {
    use heimdall::cardano::cpo_trie::CpoTrie;
    let Some(dir) = cfg.protocol.state_dir.as_deref() else {
        warn!("[cpo] no protocol.state_dir — using the empty (genesis) completed-peg-outs trie");
        return Ok(CpoTrie::empty());
    };
    let dir = std::path::Path::new(dir);
    match CpoTrie::load(dir).map_err(|e| e.to_string())? {
        Some(t) => {
            info!(
                "[cpo] completed-peg-outs trie: {} entr(y|ies), root {}",
                t.len(),
                hex::encode(t.root())
            );
            Ok(t)
        }
        None => {
            warn!(
                "[cpo] no completed-peg-outs trie at {} — using the empty (genesis) trie; run \
                 `reconstruct-cpo-trie` if this bridge already has history",
                dir.display()
            );
            Ok(CpoTrie::empty())
        }
    }
}

/// Load this node's swept peg-ins trie from `protocol.state_dir`.
///
/// No `state_dir`, or no file yet, means the genesis (empty) trie — correct on a
/// bridge whose treasury has swept no deposit, and loud everywhere else: the
/// spi_root this node then commits is refused by peers whose trie is populated.
fn spi_trie_from_cfg(cfg: &HeimdallConfig) -> Result<heimdall::cardano::spi_trie::SpiTrie, String> {
    use heimdall::cardano::spi_trie::SpiTrie;
    let Some(dir) = cfg.protocol.state_dir.as_deref() else {
        eprintln!("[spi] no protocol.state_dir — using the empty (genesis) swept peg-ins trie");
        return Ok(SpiTrie::empty());
    };
    let dir = std::path::Path::new(dir);
    match SpiTrie::load(dir).map_err(|e| e.to_string())? {
        Some(t) => {
            eprintln!(
                "[spi] swept peg-ins trie: {} entr(y|ies), root {}",
                t.len(),
                hex::encode(t.root())
            );
            Ok(t)
        }
        None => {
            eprintln!(
                "[spi] no swept peg-ins trie at {} — using the empty (genesis) trie",
                dir.display()
            );
            Ok(SpiTrie::empty())
        }
    }
}

/// Refuse to build a TM off a trie the chain does not hold — the CLI mirror of
/// `epoch::machine::cross_check_cpo_root`.
///
/// [`cpo_trie_from_cfg`] trusts `cpo-trie.json` verbatim, so a re-bootstrap that
/// mints a FRESH zero-root bridge state singleton while this box still holds the previous
/// deployment's trie leaves `sweep-pegins` / `run-mover` ready to commit a root
/// the chain no longer has. Confirm then copies that root into the singleton's
/// datum, and every membership proof built against the real payment history is
/// refused by `peg-out.ak`.
///
/// Since WI-070 the singleton's policy is Config #4, so the check can no longer
/// be switched off by leaving a key unset — [`CpoTrust::Unverified`] survives
/// only for the deployments with no Config at all.
fn cross_check_cpo_trie_from_cfg(
    rt: &tokio::runtime::Runtime,
    cfg: &HeimdallConfig,
    trie: &heimdall::cardano::cpo_trie::CpoTrie,
) -> Result<CpoTrust, String> {
    use heimdall::cardano::cpo_history::{BlockfrostHistory, CpoHistorySource, KupoHistory};

    let Some(view) = config_view(rt, cfg)? else {
        warn!(
            "[cpo] no bridge Config configured — the local root was NOT cross-checked \
             against the on-chain bridge state singleton. Set cardano.config_address and \
             cardano.config_nft_policy_id before signing a TM on a live bridge."
        );
        return Ok(CpoTrust::Unverified);
    };
    let policy = hex::encode(view.params.bridge_state_policy);
    let policy = policy.as_str();
    // Same backend selection as `reconstruct-cpo-trie`, so both reads see the same index.
    let source: Box<dyn CpoHistorySource> = match cfg.cardano.kupo_url.as_deref() {
        Some(url) => Box::new(KupoHistory::new(url)),
        None => {
            let project_id = cfg.cardano.blockfrost_project_id.as_deref().ok_or(
                "set cardano.kupo_url or cardano.blockfrost_project_id — the bridge state \
                 singleton must be readable to cross-check the local trie",
            )?;
            Box::new(BlockfrostHistory::new(
                project_id,
                cfg.cardano.blockfrost_url.as_deref(),
            ))
        }
    };
    // `cpo_root` BY NAME, per [LIB-1]: field 0 of the singleton is `spi_root`.
    let on_chain = rt
        .block_on(heimdall::cardano::bridge_state::fetch_bridge_state(
            source.as_ref(),
            policy.trim(),
        ))
        .map_err(|e| format!("read the bridge state singleton: {e}"))?
        .cpo_root;
    if on_chain != trie.root() {
        return Err(format!(
            "completed-peg-outs trie is out of sync with the chain: local root {} ({} entries) \
             != the bridge state singleton's cpo_root {}. Refusing to build — a TM built on a \
             stale trie commits a root the chain does not hold. Rebuild with \
             `reconstruct-cpo-trie` (and \
             delete the stale {}/cpo-trie.json if the bridge was re-bootstrapped).",
            hex::encode(trie.root()),
            trie.len(),
            hex::encode(on_chain),
            cfg.protocol
                .state_dir
                .as_deref()
                .unwrap_or("<protocol.state_dir>"),
        ));
    }
    info!(
        "[cpo] local root matches the bridge state singleton's cpo_root ({})",
        hex::encode(on_chain)
    );
    Ok(CpoTrust::Verified)
}

/// Whether the local completed-peg-outs trie may be trusted to decide which peg-outs an
/// earlier movement already paid. Mirrors the epoch machine's own gate — since WI-031 the
/// trie is the sole already-paid record, so "not cross-checked" has to be actionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpoTrust {
    /// Cross-checked against the on-chain bridge state singleton's `cpo_root`.
    Verified,
    /// No `cardano.cpo_policy_id` — the local root was never checked against the chain.
    Unverified,
}

/// Build the Bitcoin RPC config; errors if `bitcoin.rpc_url` is unset.
fn btc_rpc_config(
    cfg: &HeimdallConfig,
) -> Result<heimdall::cardano::btc_rpc::BtcRpcConfig, String> {
    let url = cfg
        .bitcoin
        .rpc_url
        .clone()
        .ok_or_else(|| "bitcoin.rpc_url not set in config".to_string())?;
    Ok(heimdall::cardano::btc_rpc::BtcRpcConfig {
        url,
        user: cfg.bitcoin.rpc_user.clone(),
        pass: cfg.bitcoin.rpc_pass.clone(),
    })
}

/// Build (and optionally broadcast) a self-send of the bootstrap treasury UTXO
/// to a tx whose output[0] is the treasury — so `query_treasury` (which reads
/// vout 0) sees it. Key-path spend with the single `y_fed` key.
fn run_treasury_self_send(
    cfg: &HeimdallConfig,
    outpoint: &str,
    amount_sat: u64,
) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::{Amount, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::bitcoin::tm_builder::{TreasuryInput, build_tm, sign_tm_single_key};

    let secp = Secp256k1::new();
    let outpoint = parse_outpoint(outpoint)?;
    let (sk, y_fed) = y_fed_keypair(&secp, cfg)?;
    let csv = csv_blocks_u16(cfg)?;

    let spend_info = treasury_spend_info(&secp, y_fed, y_fed, csv);
    let treasury_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    // Only the treasury input, no peg-ins/peg-outs => single output[0] = treasury.
    let unsigned = build_tm(
        TreasuryInput {
            outpoint,
            value: Amount::from_sat(amount_sat),
            spend_info,
        },
        vec![],
        vec![],
        treasury_spk,
        &dev_tm_params_from_cfg(cfg),
        // No peg-outs, so there is nothing for the window to filter.
        &heimdall::bitcoin::tm_builder::Freshness::inert(),
        // A self-send fulfils nothing, so it re-commits the trie's current root.
        &cpo_trie_from_cfg(cfg)?,
        // …and sweeps nothing, so the spi_root is unchanged too.
        &spi_trie_from_cfg(cfg)?,
    )
    .map_err(|e| format!("build self-send: {e}"))?;

    let signed =
        sign_tm_single_key(&secp, &unsigned, &sk).map_err(|e| format!("sign self-send: {e}"))?;
    let raw = bitcoin::consensus::encode::serialize(&signed);

    println!("self-send txid : {}", signed.compute_txid());
    println!(
        "output[0]      : {} sat (treasury)",
        signed.output[0].value.to_sat()
    );
    println!("raw tx         : {}", hex::encode(&raw));

    // heimdall does not send this. Signing needs the federation seed; SENDING needs
    // a Bitcoin node, and heimdall has no business holding one (WI-086) — so the
    // signed bytes above are the deliverable.
    println!("(send it with: bitcoin-cli sendrawtransaction <raw tx>)");
    Ok(())
}

// ── Federation key ceremony and signing (WI-087) ────────────────────────

/// The typed-in `[federation]` roster.
fn federation_roster(cfg: &HeimdallConfig) -> Result<FederationRoster, String> {
    FederationRoster::from_config(&cfg.federation).map_err(|e| e.to_string())
}

/// Where the federation share is kept. Required for the ceremony, and by name:
/// a share generated with nowhere to write it dies with the process, and this
/// key — unlike an epoch key — has no next boundary to be regenerated at.
fn federation_state_dir(cfg: &HeimdallConfig) -> Result<std::path::PathBuf, String> {
    cfg.protocol
        .state_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            "protocol.state_dir is unset, so there is nowhere to persist the federation share. \
             Unlike an epoch share this one never regenerates: the ceremony cannot reproduce \
             the same key, so a share that exists only in this process is a recovery path lost \
             when the process exits. Set protocol.state_dir before running the ceremony"
                .to_string()
        })
}

/// This node's persisted federation share, if it has one — cross-checked against
/// the configured roster whenever one is configured.
fn federation_share(cfg: &HeimdallConfig) -> Result<Option<FederationKeyState>, String> {
    let Some(dir) = cfg.protocol.state_dir.as_deref() else {
        return Ok(None);
    };
    let Some(state) =
        federation_persist::read(std::path::Path::new(dir)).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    // A share is only meaningful against the membership + threshold that made it.
    // With no `[federation]` section there is nothing to check it against — which
    // is legitimate for a node that only READS the key (`bootstrap-treasury`), so
    // the check applies exactly when a roster is configured.
    if !cfg.federation.members.is_empty() {
        state
            .check_roster(&federation_roster(cfg)?)
            .map_err(|e| e.to_string())?;
    }
    Ok(Some(state))
}

/// This node's federation signing material for the epoch machine (WI-095), or
/// `None` if it is not a federation member.
///
/// The machine needs both halves together: the share to sign with, and the
/// membership to address peers by. `federation_share` already refuses a share
/// that does not match the configured roster; what is left is the case where
/// there is no roster to match against.
fn phase1_signer(
    cfg: &HeimdallConfig,
) -> Result<Option<heimdall::epoch::state::Phase1Signer>, String> {
    let Some(state) = federation_share(cfg)? else {
        return Ok(None);
    };
    if cfg.federation.members.is_empty() {
        // A share with nobody to sign alongside. Refused rather than downgraded
        // to "not a member": this node CAN sign, and on a Phase-1 bridge its
        // silence stalls every treasury movement — a failure whose only symptom
        // would be co-signers timing out on a peer that looks healthy.
        return Err(format!(
            "a federation share is persisted in {} but [federation].members is empty, so this \
             node cannot tell who its co-signers are or where to reach them. The roster is \
             typed in — Y_federation precedes the bridge, so there is nothing to read it from. \
             Restore the member list the ceremony ran with",
            cfg.protocol.state_dir.as_deref().unwrap_or("<state_dir>")
        ));
    }
    let roster = federation_roster(cfg)?.to_roster();
    let group_keys = state.to_group_keys().map_err(|e| e.to_string())?;
    Ok(Some(heimdall::epoch::state::Phase1Signer {
        roster,
        group_keys,
    }))
}

/// Start this node's ceremony endpoint and return the transport peers fetch from.
///
/// Same server, same routes and same authenticated wire as the epoch DKG — only
/// the roster behind it is different. The listen port follows the same rule too:
/// `http.listen_port` when the advertised URL is not where this process binds,
/// otherwise the port inside this member's own `bifrost_url`.
async fn serve_federation(
    cfg: &HeimdallConfig,
    me: &FederationMember,
    keypair: bitcoin::secp256k1::Keypair,
) -> Result<Arc<HttpPeerNetwork>, String> {
    let port = match cfg.http.listen_port {
        Some(p) => p,
        None => port_from_url(&me.bifrost_url)?,
    };
    let net = Arc::new(HttpPeerNetwork::new(
        bitcoin::secp256k1::Secp256k1::new(),
        keypair,
        me.address(),
    ));
    let app = router(net.shared_state());
    let bind = format!("{}:{port}", cfg.http.bind_address);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    info!(
        "[federation] listening on {bind}; peers fetch from {}",
        me.bifrost_url
    );
    Ok(net)
}

/// Locate this node in the federation and load the identity key it publishes
/// under. Both halves fail loudly: a node that cannot prove which member it is
/// has no business contributing material to a key that decides where the
/// treasury lives.
fn federation_identity(
    cfg: &HeimdallConfig,
    roster: &FederationRoster,
) -> Result<(FederationMember, bitcoin::secp256k1::Keypair), String> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = cfg
        .load_bifrost_keypair(&secp)
        .map_err(|e| format!("[bifrost].skey_path: {e}"))?;
    let my_pk = keypair.x_only_public_key().0.serialize();
    let me = roster.own(&my_pk).ok_or_else(|| {
        format!(
            "this node's bifrost identity key ({}) is not in [federation].members. Every \
             member's config lists the WHOLE federation, this node included",
            hex::encode(my_pk)
        )
    })?;
    Ok((me.clone(), keypair))
}

fn federation_limits(cfg: &HeimdallConfig, timeout_secs: Option<u64>) -> CeremonyLimits {
    let poll = std::time::Duration::from_millis(cfg.protocol.poll_interval_ms);
    match timeout_secs {
        Some(s) => CeremonyLimits::bounded(poll, std::time::Duration::from_secs(s)),
        None => CeremonyLimits::unbounded(poll),
    }
}

/// Print this node's bifrost identity key and where it sits in the configured
/// federation.
///
/// The public half has to be typed into other people's config files, so it needs
/// to come out of the same file the daemon signs with — not be re-derived by
/// whatever tool the operator has to hand. Reporting the federation position
/// alongside it turns "my key is not in the list" into a line of output rather
/// than a ceremony that waits for a member nobody else can see.
fn print_bifrost_id(cfg: &HeimdallConfig) -> Result<(), String> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = cfg
        .load_bifrost_keypair(&secp)
        .map_err(|e| format!("[bifrost].skey_path: {e}"))?;
    let pk = keypair.x_only_public_key().0.serialize();
    println!("bifrost_id_pk: {}", hex::encode(pk));

    if cfg.federation.members.is_empty() {
        println!("federation:    none configured ([federation].members is empty)");
        return Ok(());
    }
    let roster = federation_roster(cfg)?;
    print!("{}", roster.table());
    match roster.own(&pk) {
        Some(me) => println!("this node:     {}", me.label()),
        None => println!(
            "this node:     NOT a member — this key is not in [federation].members, so a \
             ceremony run here would refuse to start"
        ),
    }
    Ok(())
}

/// Run the federation key ceremony (WI-087) and persist this node's share.
///
/// Idempotent by design: a share already on disk for the configured roster is
/// printed rather than replaced. Re-running the ceremony would produce a
/// DIFFERENT key — hence a different treasury address — so "run it again" is
/// never the answer once one exists, and a command that quietly did so would
/// strand whatever the old address holds.
async fn run_federation_dkg(
    cfg: &HeimdallConfig,
    timeout_secs: Option<u64>,
    serve_after_secs: u64,
) -> Result<(), String> {
    let roster = federation_roster(cfg)?;
    let dir = federation_state_dir(cfg)?;
    let (me, keypair) = federation_identity(cfg, &roster)?;
    print!("{}", roster.table());
    println!("this node: {}", me.label());

    if let Some(existing) = federation_share(cfg)? {
        let y = existing.federation_setup_y().map_err(|e| e.to_string())?;
        println!("\nthe federation key already exists — nothing to do.");
        println!("federation_setup_Y: {}", hex::encode(y.serialize()));
        println!(
            "(share: {})",
            federation_persist::state_path(&dir).display()
        );
        // Said here because this is where a half-finished ceremony is discovered:
        // the member that failed re-runs, finds everyone else already done, and
        // waits for peers that will never publish again. The round payloads are
        // per-process, so a completed member cannot re-serve them.
        println!(
            "\nIf another member did NOT complete, this cannot be fixed by re-running there: \
             a ceremony only forms a key when every member is in it, and the payloads are not \
             kept after it ends. Every member deletes its federation-key.json and the whole \
             federation runs the ceremony again — which produces a DIFFERENT y_federation, so \
             do it before any BTC is sent to an address derived from this one."
        );
        return Ok(());
    }

    let peers: Arc<dyn PeerNetwork> = serve_federation(cfg, &me, keypair).await?;
    let mut rng = OsRngSource.rng(b"federation-dkg");
    let keys = ceremony::run_dkg(
        &peers,
        &roster,
        me.identifier,
        &mut rng,
        &federation_limits(cfg, timeout_secs),
    )
    .await
    .map_err(|e| {
        format!(
            "{e}\n\nIf other members DID complete, they now hold shares of a key this node has \
             none of. That cannot be repaired here alone: every member must delete its \
             federation-key.json and the federation must run the ceremony again."
        )
    })?;

    let state = FederationKeyState::from_output(&roster, &keys).map_err(|e| e.to_string())?;
    // Fatal, unlike the epoch ceremony's best-effort persist: there is no next
    // boundary to regenerate at, so an unpersisted share is a recovery path that
    // ends when this process does.
    federation_persist::write(&dir, &state).map_err(|e| {
        format!(
            "the ceremony completed but the share could NOT be persisted: {e}. The key exists \
             only in this process — fix the state dir and run the ceremony again (all members \
             must, since a re-run produces a different key)"
        )
    })?;

    let y = state.federation_setup_y().map_err(|e| e.to_string())?;
    println!("\nfederation key formed.");
    println!("federation_setup_Y: {}", hex::encode(y.serialize()));
    println!(
        "                    ↳ genesis publishes this as Config #11 y_federation \
         (binocular bridge.y-federation-hex)"
    );
    println!(
        "share:              {} (0600 — losing every copy loses the recovery path)",
        federation_persist::state_path(&dir).display()
    );
    println!(
        "next:               `heimdall bootstrap-treasury` prints the genesis treasury address"
    );

    // Keep answering for a while. This node is done, but a slower member may
    // still be fetching the payloads only this process holds — and to that member
    // an endpoint that has exited looks exactly like one that published nothing.
    if serve_after_secs > 0 {
        info!(
            "[federation] serving for another {serve_after_secs}s so members still collecting \
             can fetch from this node (--serve-after-secs 0 to exit at once)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(serve_after_secs)).await;
    }
    Ok(())
}

/// Which federation key this node holds, and therefore how it signs.
enum FederationSigner {
    /// The single seed of the pre-WI-087 federation.
    Seed(bitcoin::secp256k1::Keypair),
    /// A share of a ceremony key: signing means a FROST session.
    Share(Box<FederationKeyState>),
}

impl FederationSigner {
    /// The public half — `federation_setup_Y` before genesis publishes it, and
    /// `y_federation` after. Same 32 bytes; what changes is who else can read
    /// them.
    fn public_key(&self) -> Result<bitcoin::key::UntweakedPublicKey, String> {
        match self {
            Self::Seed(kp) => Ok(kp.x_only_public_key().0),
            Self::Share(state) => state.federation_setup_y().map_err(|e| e.to_string()),
        }
    }

    /// How this node came by the key, for the operator reading the output.
    fn label(&self) -> String {
        match self {
            Self::Seed(_) => "derived from bitcoin.y_fed_seed_hex — one seed, one holder".into(),
            Self::Share(state) => format!(
                "the {}-of-{} federation ceremony key",
                state.min_signers, state.max_signers
            ),
        }
    }
}

/// Resolve the federation key this node signs with, refusing both and neither.
///
/// Both is the interesting case: the seed and a ceremony key are different keys
/// locking different treasuries, so a preference order would silently pick one,
/// and picking wrong produces a perfectly well-formed transaction for an address
/// that holds nothing.
fn federation_signer(cfg: &HeimdallConfig) -> Result<FederationSigner, String> {
    let share = federation_share(cfg)?;
    let seed = configured_seed(cfg).map(str::to_string);
    match (share, seed) {
        (Some(_), Some(_)) => Err(
            "this node holds two federation keys: bitcoin.y_fed_seed_hex and a persisted \
             federation-dkg share. They lock different treasuries, so exactly one belongs to \
             this bridge and nothing here can tell which — remove the other"
                .to_string(),
        ),
        (Some(state), None) => Ok(FederationSigner::Share(Box::new(state))),
        (None, Some(seed_hex)) => Ok(FederationSigner::Seed(
            heimdall::cardano::federation::keypair_from_seed_hex(&seed_hex)
                .map_err(|e| e.to_string())?,
        )),
        (None, None) => Err(
            "this node holds no federation key: no federation-dkg share under \
             protocol.state_dir, and no bitcoin.y_fed_seed_hex. Run `heimdall federation-dkg` \
             to take part in the ceremony that generates one, or set the seed if this bridge \
             uses the single-key federation that ceremony replaces. The key published on chain \
             cannot stand in — it is the public half"
                .to_string(),
        ),
    }
}

/// Sign one 32-byte message as the federation and print the signature.
///
/// The generic form of what `federation-spend` does to a sighash, for the
/// authorizations that are not Bitcoin transactions — today, Update-Y as the
/// federation ([UY-5]), which already accepts an externally produced signature
/// via `--signature`.
fn run_federation_sign(
    cfg: &HeimdallConfig,
    message_hex: &str,
    signers: &[u16],
    timeout_secs: Option<u64>,
    serve_after_secs: u64,
) -> Result<(), String> {
    let message = parse_hex_n::<32>(message_hex, "--message")?;
    let signer = federation_signer(cfg)?;
    let (signature, session) = match &signer {
        // A single-key federation is a one-party session; the same command works
        // so a caller does not have to know which shape this bridge uses.
        FederationSigner::Seed(kp) => {
            println!("signing with the single federation seed (no co-signers)");
            let secp = bitcoin::secp256k1::Secp256k1::new();
            (
                secp.sign_schnorr_no_aux_rand(
                    &bitcoin::secp256k1::Message::from_digest(message),
                    kp,
                )
                .serialize(),
                None,
            )
        }
        FederationSigner::Share(state) => {
            let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
            let (sig, held) = frost_federation_signature(
                cfg,
                rt,
                state,
                message,
                signers,
                timeout_secs,
                serve_after_secs,
            )?;
            (sig, Some(held))
        }
    };

    println!("message:      {}", hex::encode(message));
    println!(
        "y_federation: {}",
        hex::encode(signer.public_key()?.serialize())
    );
    println!("signature:    {}", hex::encode(signature));
    println!(
        "(pass it to the command that asked for it, e.g. `update-y --federation --signature <signature>`)"
    );

    if let Some(session) = session {
        session.hold();
    }
    Ok(())
}

/// Build (and print) the FEDERATION emergency spend of the treasury (scenario 3,
/// N23): a Taproot SCRIPT-PATH spend via the `y_fed` CSV leaf, the fallback for
/// when the FROST group is dark. The treasury UTxO must already be
/// `federation_csv_blocks` deep on Bitcoin. Change returns to the same treasury
/// address (federation self-send); the on-chain rotation to y_federation is a
/// separate step (N10b). `y51_hex` is the treasury's current internal key (its
/// FROST group key) — needed only to rebuild the treasury tree / leaf control
/// block.
///
/// `y_fed` and the CSV delay come from the **Config datum** wherever the bridge
/// has one (#11 and `params[7]`, via [`resolve_federation`]) — what this node
/// holds locally is the SECRET half and a cross-check, never the source of the
/// address. That mattered less when one operator signed alone; with a threshold
/// federation several operators must build byte-identical transactions, so a
/// per-operator `federation_csv_blocks` would be exactly the silent divergence
/// [`heimdall::cardano::federation`] exists to prevent — each member would hash a
/// different tree, and the session would stall with every member waiting for the
/// others. Local values are the source only before genesis, when there is
/// genuinely no Config to read.
fn run_federation_spend(
    cfg: &HeimdallConfig,
    outpoint: &str,
    amount_sat: u64,
    y51_hex: Option<&str>,
    signers: &[u16],
    timeout_secs: Option<u64>,
    serve_after_secs: u64,
) -> Result<(), String> {
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::{Amount, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::bitcoin::tm_builder::{TreasuryInput, build_tm, federation_leaf_spend};

    let secp = Secp256k1::new();
    let outpoint = parse_outpoint(outpoint)?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    // Published-wins, and a local key that disagrees with the published one is
    // fatal here rather than quietly preferred — this node would otherwise sign
    // for an address the other members are not using.
    let federation = rt.block_on(resolve_federation(cfg))?;
    let signer = federation_signer(cfg)?;
    let y_fed = federation.y_fed;
    let csv = federation.csv_blocks;
    println!(
        "y_federation: {} ({})",
        hex::encode(y_fed.serialize()),
        federation.origin
    );
    // Omitted => the bootstrap treasury, whose internal key is y_fed itself.
    let y51 = match y51_hex {
        Some(h) => {
            let b = hex::decode(h.trim()).map_err(|e| format!("--y51 hex: {e}"))?;
            UntweakedPublicKey::from_slice(&b)
                .map_err(|e| format!("--y51 is not a 32-byte x-only key: {e}"))?
        }
        None => y_fed,
    };

    // Real treasury tree: Y_51 internal (key-path = 51%), y_fed CSV leaf (federation).
    let spend_info = treasury_spend_info(&secp, y51, y_fed, csv);
    let treasury_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let treasury_addr =
        bitcoin::Address::p2tr_tweaked(spend_info.output_key(), cfg.bitcoin.parsed_network());

    // Treasury-only, no peg-ins/peg-outs => single output[0] = treasury.
    let unsigned = build_tm(
        TreasuryInput {
            outpoint,
            value: Amount::from_sat(amount_sat),
            spend_info,
        },
        vec![],
        vec![],
        treasury_spk,
        &dev_tm_params_from_cfg(cfg),
        &heimdall::bitcoin::tm_builder::Freshness::inert(),
        &cpo_trie_from_cfg(cfg)?,
        &spi_trie_from_cfg(cfg)?,
    )
    .map_err(|e| format!("build federation spend: {e}"))?;

    // One leaf spend, two ways to sign the SAME 32 bytes: the single seed signs
    // locally, a ceremony share runs a FROST session with its co-signers. Sharing
    // the construction is what makes the two produce the same transaction —
    // anything built differently would be a different sighash.
    let spend = federation_leaf_spend(&unsigned, y_fed, csv)
        .map_err(|e| format!("federation leaf: {e}"))?;
    let (signature, session) = match &signer {
        FederationSigner::Seed(kp) => {
            println!("signing with the single federation seed (no co-signers)");
            let sig = secp.sign_schnorr_no_aux_rand(
                &bitcoin::secp256k1::Message::from_digest(spend.sighash),
                kp,
            );
            (sig.serialize(), None)
        }
        FederationSigner::Share(state) => {
            let (sig, held) = frost_federation_signature(
                cfg,
                rt,
                state,
                spend.sighash,
                signers,
                timeout_secs,
                serve_after_secs,
            )?;
            (sig, Some(held))
        }
    };
    let signed = spend
        .finish(signature)
        .map_err(|e| format!("sign federation spend: {e}"))?;
    let raw = bitcoin::consensus::encode::serialize(&signed);

    println!("federation-spend txid : {}", signed.compute_txid());
    println!("  treasury address     : {treasury_addr}  (fund this / the input's scriptPubKey)");
    println!(
        "  script-path via y_fed CSV leaf (csv={csv}); output[0] = {} sat (treasury)",
        signed.output[0].value.to_sat()
    );
    println!(
        "  witness items: {} (expect 3: sig, leaf, control block)",
        signed.input[0].witness.len()
    );
    println!("  raw tx : {}", hex::encode(&raw));

    // heimdall does not send this (WI-086). The recovery case makes that the right
    // shape rather than a limitation: whoever holds the federation key is not
    // necessarily running a node beside heimdall, and handing them signed bytes is a
    // smaller ask than handing them an RPC to configure.
    println!(
        "(send it with: bitcoin-cli sendrawtransaction <raw tx>; the treasury UTxO must \
         be >= {csv} blocks deep)"
    );

    // The transaction is out; only now does this node stop answering its
    // co-signers. See `HeldSession`.
    if let Some(session) = session {
        session.hold();
    }
    Ok(())
}

/// Run the FROST session that signs one 32-byte message with the federation key.
///
/// Every participating member runs `federation-spend` with the SAME arguments —
/// same outpoint, same amount, same `--y51`, same `--signers` — because each
/// builds the transaction itself and they must arrive at one sighash. The
/// session then binds to that sighash, so two members that built different
/// transactions never mix their material: they just wait for each other.
/// A finished FROST session whose endpoint is deliberately still up.
///
/// The tokio runtime owns the axum server this node served its payloads from, so
/// dropping it stops answering — and to a co-signer one poll behind, an endpoint
/// that has finished is indistinguishable from one that published nothing. So the
/// runtime outlives the signature, and [`Self::hold`] keeps it serving for the
/// grace window after the transaction has been printed.
struct HeldSession {
    rt: tokio::runtime::Runtime,
    grace: std::time::Duration,
}

impl HeldSession {
    fn hold(self) {
        if self.grace.is_zero() {
            return;
        }
        info!(
            "[federation] serving for another {}s so co-signers can still fetch this node's \
             share (--serve-after-secs 0 to exit at once)",
            self.grace.as_secs()
        );
        // The sleep is CREATED inside `block_on`, not passed into it: a
        // `tokio::time::Sleep` registers with the reactor when it is constructed,
        // and constructing one outside the runtime panics with "there is no
        // reactor running".
        let grace = self.grace;
        self.rt
            .block_on(async move { tokio::time::sleep(grace).await });
    }
}

fn frost_federation_signature(
    cfg: &HeimdallConfig,
    rt: tokio::runtime::Runtime,
    state: &FederationKeyState,
    sighash: [u8; 32],
    signers: &[u16],
    timeout_secs: Option<u64>,
    serve_after_secs: u64,
) -> Result<([u8; 64], HeldSession), String> {
    let roster = federation_roster(cfg)?;
    let (me, keypair) = federation_identity(cfg, &roster)?;
    let keys = state.to_group_keys().map_err(|e| e.to_string())?;
    // The share must be THIS member's. A share file copied from another member
    // carries their index, so the node would publish material under an identity
    // its peers address to somebody else — and the aggregate would fail with
    // nothing pointing at a misplaced file.
    if me.identifier != *keys.key_package.identifier() {
        return Err(format!(
            "the persisted share is member #{}'s, but this node's bifrost key makes it member \
             #{}. A share belongs to the member that generated it — check that \
             protocol.state_dir and [bifrost].skey_path belong to the same member",
            heimdall::frost::identifier_u16(*keys.key_package.identifier()),
            heimdall::frost::identifier_u16(me.identifier),
        ));
    }
    let set = if signers.is_empty() {
        roster.ids()
    } else {
        roster.signers_from_indices(signers)?
    };
    print!("{}", roster.table());

    let signature = rt.block_on(async {
        let peers: Arc<dyn PeerNetwork> = serve_federation(cfg, &me, keypair).await?;
        let mut rng = OsRngSource.rng(b"federation-spend");
        federation_spend::frost_sign(
            &peers,
            &roster,
            &keys,
            sighash,
            &set,
            &mut rng,
            // Bounded by default here, unlike the ceremony: a spend is a
            // coordinated moment among people already talking to each other, and
            // a command that sits for ever tells them nothing about who is late.
            &federation_limits(cfg, Some(timeout_secs.unwrap_or(300))),
        )
        .await
        .map_err(|e| e.to_string())
    })?;
    Ok((
        signature,
        HeldSession {
            rt,
            grace: std::time::Duration::from_secs(serve_after_secs),
        },
    ))
}

/// The Cardano wallet mnemonic: `cardano.mnemonic` from config, else
/// `$HEIMDALL_MNEMONIC`.
fn resolve_mnemonic(cfg: &HeimdallConfig) -> Result<String, String> {
    cfg.cardano
        .mnemonic
        .clone()
        .or_else(|| {
            std::env::var("HEIMDALL_MNEMONIC")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .ok_or_else(|| "no mnemonic (set cardano.mnemonic or $HEIMDALL_MNEMONIC)".to_string())
}

/// Parse `<cardano_tx_hash>:<index>` into a 32-byte tx id + output index.
/// The index is bounded to `u32` (the ledger's output-index width) so a typo
/// can never silently wrap into a negative Plutus Int downstream.
fn parse_cardano_outref(s: &str) -> Result<([u8; 32], u32), String> {
    let (h, i) = s
        .split_once(':')
        .ok_or_else(|| format!("expected <tx_hash>:<index>, got '{s}'"))?;
    let tx_id: [u8; 32] = hex::decode(h)
        .map_err(|e| format!("tx hash hex: {e}"))?
        .try_into()
        .map_err(|_| "tx hash must be 32 bytes".to_string())?;
    let index: u32 = i.parse().map_err(|e| format!("output index: {e}"))?;
    Ok((tx_id, index))
}

/// Build (and with `submit`, broadcast) the K1 `treasury_info` bootstrap mint.
/// See `heimdall::cardano::treasury_bootstrap` for the on-chain contract.
#[allow(clippy::too_many_arguments)]
fn run_bootstrap_treasury_info(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    frost_key: &str,
    identity_root: Option<&str>,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spos_registry_script, treasury_info_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::treasury_bootstrap::{bootstrap_datum, build_treasury_bootstrap_tx};
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    // Rev 5.5 derivation order: Config → treasury → registry ([PRE-3], [PRE-4]).
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    let treasury = treasury_info_script(
        &blueprint_json,
        &tsy_tx_id,
        u64::from(tsy_index),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize treasury_info: {e}"))?;
    let registry = spos_registry_script(
        &blueprint_json,
        &reg_tx_id,
        u64::from(reg_index),
        &treasury.hash,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    println!("registry policy id:   {}", registry.hash_hex());
    println!("treasury_info policy: {}", treasury.hash_hex());

    let frost = hex::decode(frost_key).map_err(|e| format!("--frost-key: {e}"))?;
    bitcoin::XOnlyPublicKey::from_slice(&frost)
        .map_err(|e| format!("--frost-key is not a valid x-only secp256k1 point: {e}"))?;
    // Rev 5.5: y_federation and federation_csv_blocks are CONFIG fields (#11 and
    // params[7]), written by the Config bootstrap rather than this one ([CFG-6]).
    // They are no longer arguments here.
    let mut datum = bootstrap_datum(frost, heimdall::cardano::mpf::NULL_HASH);
    // spec [PRE-2]: the operator may seed a non-empty identity root (e.g. a
    // replacement deployment carrying registered SPOs forward). Rev 5.5
    // implements it on-chain, so this no longer warns.
    if let Some(root_hex) = identity_root {
        datum.bifrost_identity_root = hex::decode(root_hex)
            .map_err(|e| format!("--identity-root: {e}"))?
            .try_into()
            .map_err(|_| "--identity-root must be 32 bytes".to_string())?;
    }

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    // Never let coin selection consume the registry one-shot outref: spending
    // it would make the spos_registry bootstrap impossible, and treasury.ak's
    // spend path requires a registry-policy mint — the state UTxO created here
    // would be frozen at bootstrap forever.
    let reg_tx_hash_hex = hex::encode(reg_tx_id);
    let wallet_utxos: Vec<WalletUtxo> = raw
        .iter()
        .map(WalletUtxo::from_bf)
        .filter(|u| !(u.tx_hash == reg_tx_hash_hex && u.output_index == reg_index))
        .collect();
    if wallet_utxos.is_empty() {
        return Err(format!(
            "wallet has no spendable UTxOs besides the registry bootstrap outref — \
             fund it first (address: {wallet_addr})"
        ));
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_treasury_bootstrap_tx(
        &treasury,
        &wallet_addr,
        &wallet_utxos,
        &datum,
        &key,
        (&hex::encode(tsy_tx_id), tsy_index),
        Some(cost_models),
    )
    .map_err(|e| format!("build bootstrap tx: {e}"))?;

    println!(
        "one-shot input_ref:   {}#{}",
        built.input_ref.0, built.input_ref.1
    );
    println!(
        "treasury NFT:         {}.{}",
        built.policy_id_hex, built.asset_name_hex
    );
    println!("state UTxO address:   {}", built.script_address);
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let cbor = hex::decode(&built.signed_tx_hex).map_err(|e| e.to_string())?;
    let mut settings = blockfrost::BlockFrostSettings::new();
    if let Some(url) = cfg.cardano.blockfrost_url.as_deref() {
        settings.base_url = Some(url.to_string());
    }
    let api = blockfrost::BlockfrostAPI::new(pid, settings);
    let tx_hash = rt
        .block_on(api.transactions_submit(cbor))
        .map_err(|e| format!("blockfrost submit: {e}"))?;
    println!("submitted: tx_hash={tx_hash}");
    Ok(())
}

/// Submit a signed tx (hex) via Blockfrost; returns the tx hash.
fn submit_tx_blockfrost(
    cfg: &HeimdallConfig,
    project_id: &str,
    signed_tx_hex: &str,
    rt: &tokio::runtime::Runtime,
) -> Result<String, String> {
    let cbor = hex::decode(signed_tx_hex).map_err(|e| e.to_string())?;
    let mut settings = blockfrost::BlockFrostSettings::new();
    if let Some(url) = cfg.cardano.blockfrost_url.as_deref() {
        settings.base_url = Some(url.to_string());
    }
    let api = blockfrost::BlockfrostAPI::new(project_id, settings);
    rt.block_on(api.transactions_submit(cbor))
        .map_err(|e| format!("blockfrost submit: {e}"))
}

/// The Cardano network of a bech32 address — testnet iff the `addr_test` HRP.
/// Thin alias over the shared [`crate::cardano::tx_common::network_from_address`]
/// (the single source of truth) for the on-chain command handlers.
fn network_of(addr: &str) -> pallas_addresses::Network {
    heimdall::cardano::tx_common::network_from_address(addr)
}

/// Byte size of a reference script attached to a one-shot bootstrap outref, if
/// any. The outref can't be swapped (it parameterizes the policy), so the Conway
/// per-byte ref-script fee on spending it must be priced in explicitly (whisky's
/// estimate can't see it). Shared by the registry and ban-list bootstrap
/// commands; `label` tags the operator-facing note.
fn fetch_one_shot_ref_script_size(
    rt: &tokio::runtime::Runtime,
    base_url: &str,
    pid: &str,
    raw: &[heimdall::cardano::bf_http::BfUtxo],
    tx_hash_hex: &str,
    index: u32,
    label: &str,
) -> Result<Option<u64>, String> {
    use heimdall::cardano::bf_http;
    let Some(h) = raw
        .iter()
        .find(|u| u.tx_hash == tx_hash_hex && u.output_index == index)
        .and_then(|u| u.reference_script_hash.as_deref())
    else {
        return Ok(None);
    };
    let size = rt
        .block_on(bf_http::fetch_script_size(base_url, pid, h))
        .map_err(|e| format!("one-shot ref script size: {e}"))?;
    info!(
        "[{label}] note: the one-shot outref carries reference script {h} ({size} bytes) — \
         adding the Conway ref-script fee"
    );
    Ok(Some(size))
}

/// The shared dry-run / `--submit` tail of the on-chain tx commands: on a dry
/// run print the notice and stop; otherwise broadcast via Blockfrost and print
/// the tx hash. Centralizes the user-facing wording so the copies can't drift.
fn finish_tx(
    cfg: &HeimdallConfig,
    project_id: &str,
    rt: &tokio::runtime::Runtime,
    submit: bool,
    signed_tx_hex: &str,
) -> Result<(), String> {
    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let tx_hash = submit_tx_blockfrost(cfg, project_id, signed_tx_hex, rt)?;
    println!("submitted: tx_hash={tx_hash}");
    Ok(())
}

/// Build (and with `submit`, broadcast) the registry-list bootstrap: the
/// one-shot `Bootstrap` mint creating the `"reg-root"` anchor element.
/// See `heimdall::cardano::register_spo`.
fn run_bootstrap_registry(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::spos_registry_script;
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_registry_bootstrap_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    // The one-shot outref cannot be swapped (it parameterizes the policy). If
    // it carries a reference script, the ledger charges the per-byte
    // ref-script fee on spending it — fetch the size so the builder prices it
    // in explicitly (whisky's estimate cannot see it).
    let reg_tx_hash_hex = hex::encode(reg_tx_id);
    let one_shot_ref_script_size = fetch_one_shot_ref_script_size(
        &rt,
        &base_url,
        pid,
        &raw,
        &reg_tx_hash_hex,
        reg_index,
        "bootstrap-registry",
    )?;

    let built = build_registry_bootstrap_tx(
        &registry,
        &reg_tx_hash_hex,
        reg_index,
        &wallet_addr,
        &wallet_utxos,
        &key,
        one_shot_ref_script_size,
        Some(cost_models),
    )
    .map_err(|e| format!("build registry bootstrap tx: {e}"))?;

    println!("registry policy id:   {}", built.policy_id_hex);
    println!("registry address:     {}", built.script_address);
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, submit, &built.signed_tx_hex)
}

/// Build (and with `submit`, broadcast) the ban-list bootstrap: the one-shot
/// `Bootstrap` mint creating the `"ban-root"` anchor element (WI-015). The ban
/// policy's fault-policy set + ban-schedule come from [cardano] config; the
/// `--ban-bootstrap` outref should match `cardano.ban_bootstrap` (the value
/// apply-ban reads). This must confirm before any apply-ban can be built.
/// See `heimdall::cardano::apply_ban`.
fn run_bootstrap_ban_list(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    ban_bootstrap: &str,
    schedule_flags: (Option<i64>, Option<i64>, Option<i64>),
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::apply_ban::build_ban_bootstrap_tx;
    use heimdall::cardano::ban_list::BanPolicyParams;
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spo_bans_script, spos_registry_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;

    // The ban policy is parameterized by the registry hash + the fault-policy
    // set + ban schedule + its own one-shot outref. Everything but the outref is
    // config-pinned (shared with apply-ban) so the derived policy id matches.
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let (ban_tx_id, ban_index) = parse_cardano_outref(ban_bootstrap)?;
    // apply-ban derives the ban policy id from the one-shot the Config publishes
    // at #12. If a different outref is bootstrapped here, `ban-root` is minted
    // under a policy apply-ban never queries — fail loudly instead of silently
    // bootstrapping an unreachable list.
    if let Some(cfg_ban) = cfg.cardano.federation_one_shot.as_deref() {
        let (cfg_tx_id, cfg_index) = parse_cardano_outref(cfg_ban)?;
        if (cfg_tx_id, cfg_index) != (ban_tx_id, ban_index) {
            return Err(format!(
                "--ban-bootstrap ({ban_bootstrap}) does not match the bridge Config's \
                 federation one-shot ({cfg_ban}); apply-ban derives the ban policy from the \
                 published value, so bootstrapping a different outref would mint ban-root \
                 under an unreachable policy"
            ));
        }
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    // The ban schedule is a property of the deployment, not of this operator, so
    // take it from the bridge Config whenever there IS one (params[4..6]).
    //
    // At genesis there is not: the ban root is minted in the transaction BEFORE
    // the Config NFT that names it, which is precisely when this command runs.
    // With the local schedule keys retired, `resolve` then has nothing to read
    // and no fallback — so without these flags the command could not bootstrap
    // the very bridge it exists to bootstrap.
    let bridge_config = config_view(&rt, cfg)?;
    let (flag_base, flag_faults, flag_window) = schedule_flags;
    let params = match bridge_config.as_ref().map(|v| &v.params) {
        Some(published) => {
            // A readable Config is authoritative; a second copy on the command
            // line could only disagree with it, silently deriving a different
            // ban policy id. Refuse rather than pick a winner.
            if flag_base.is_some() || flag_faults.is_some() || flag_window.is_some() {
                return Err("--base-ban-duration-ms / --max-faults-before-permanent / \
                     --max-validity-window-ms are genesis-only flags, but this node can read \
                     the bridge Config, which already publishes the schedule (params[4..6]). \
                     Drop them: two copies could differ, and the difference would silently \
                     derive a ban policy id no deployment has"
                    .to_string());
            }
            BanPolicyParams::resolve(&cfg.cardano, Some(published)).map_err(|e| e.to_string())?
        }
        None => {
            let (Some(base), Some(faults), Some(window)) = (flag_base, flag_faults, flag_window)
            else {
                return Err(
                    "no bridge Config is readable, so the ban schedule must be given \
                     explicitly: pass --base-ban-duration-ms, --max-faults-before-permanent \
                     and --max-validity-window-ms. This is the genesis case — the ban root is \
                     minted before the Config NFT that names it exists, so there is nothing \
                     on chain to read the schedule from yet. Use the same three values the \
                     Config will publish, or the ban list lands at an address no node reads"
                        .to_string(),
                );
            };
            BanPolicyParams::from_genesis_flags(&cfg.cardano, base, faults, window)
                .map_err(|e| e.to_string())?
        }
    };
    let spo_bans = spo_bans_script(
        &blueprint_json,
        &registry.hash,
        &params.fault_proof_policies,
        params.base_ban_duration_ms,
        params.max_faults_before_permanent,
        params.max_validity_window_ms,
        &ban_tx_id,
        u64::from(ban_index),
    )
    .map_err(|e| format!("parameterize spo_bans: {e}"))?;
    // A bridge whose Config already names a ban policy already HAS a ban list.
    // Minting ban-root under a different policy would create a second list at an
    // address no SPO reads, so refuse rather than produce it.
    if let Some(published) = bridge_config.as_ref().map(|v| &v.params.bans)
        && published.spo_bans_policy_id != spo_bans.hash
    {
        return Err(format!(
            "these parameters derive ban policy {} but the bridge Config publishes {} \
             (field #8) — that bridge's ban list is already bootstrapped, and a root minted \
             here would sit at an address no SPO reads",
            spo_bans.hash_hex(),
            hex::encode(published.spo_bans_policy_id),
        ));
    }

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let ban_tx_hash_hex = hex::encode(ban_tx_id);
    let one_shot_ref_script_size = fetch_one_shot_ref_script_size(
        &rt,
        &base_url,
        pid,
        &raw,
        &ban_tx_hash_hex,
        ban_index,
        "bootstrap-ban-list",
    )?;

    let built = build_ban_bootstrap_tx(
        &spo_bans,
        &ban_tx_hash_hex,
        ban_index,
        &wallet_addr,
        &wallet_utxos,
        &key,
        one_shot_ref_script_size,
        Some(cost_models),
    )
    .map_err(|e| format!("build ban bootstrap tx: {e}"))?;

    println!("ban policy id:   {}", built.policy_id_hex);
    println!("ban address:     {}", built.script_address);
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, submit, &built.signed_tx_hex)
}

/// Build (and with `submit`, broadcast) the registry reference-script deploy.
fn run_deploy_registry_ref(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    submit: bool,
    force: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::spos_registry_script;
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_ref_script_deploy_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    if ref_script_already_deployed(&raw, &registry.hash_hex(), "registry", force) {
        return Ok(());
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_ref_script_deploy_tx(
        &registry,
        &wallet_addr,
        &wallet_utxos,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build ref-script deploy tx: {e}"))?;

    println!("registry script hash: {}", built.script_hash_hex);
    println!(
        "locked with the ref:  {} lovelace (reclaimable: key-locked at the wallet)",
        built.lovelace
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let tx_hash = submit_tx_blockfrost(cfg, pid, &built.signed_tx_hex, &rt)?;
    println!("submitted: tx_hash={tx_hash}");
    println!("registry ref UTxO:    {tx_hash}#0");
    println!(
        "                      register-spo finds this on its own — it is key-locked here, at \
         this wallet. Nothing to copy."
    );
    Ok(())
}

/// Deploy a DKG fault verifier as a CIP-33 reference script (M2 of the cheat→ban
/// scenario), and print its policy id (hash) for `fault_proof_policies`. The
/// verifier is parameterized by the spos_registry policy hash (derived from the
/// blueprint + bootstrap outref), exactly as `DkgFaultBanFlow::from_config` does,
/// so the deployed hash matches what the ban flow recomputes. Dry-run prints only
/// the hash — enough for round1/round2 on the equivocation path (their ref UTxOs
/// are never consumed and their SRS is never opened).
fn run_deploy_fault_ref(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    kind: &str,
    submit: bool,
    force: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{
        fault_verifier_equivocation_script, fault_verifier_round1_script,
        fault_verifier_round2_script, spos_registry_script,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_ref_script_deploy_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let verifier = match kind {
        "round1" => fault_verifier_round1_script(&blueprint_json, &registry.hash),
        "round2" => fault_verifier_round2_script(&blueprint_json, &registry.hash),
        "equivocation" => fault_verifier_equivocation_script(&blueprint_json, &registry.hash),
        other => {
            return Err(format!(
                "unknown --kind '{other}' (expected: round1 | round2 | equivocation)"
            ));
        }
    }
    .map_err(|e| format!("parameterize fault_verifier_{kind}: {e}"))?;

    println!("fault_verifier_{kind} policy id: {}", verifier.hash_hex());
    println!(
        "  → add to `fault_proof_policies` in [cardano] (order: round1, round2, equivocation)"
    );

    if !submit {
        println!("(dry run — hash only, no wallet needed; pass --submit to deploy the ref UTxO)");
        return Ok(());
    }

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;
    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    if ref_script_already_deployed(&raw, &verifier.hash_hex(), "fault_verifier", force) {
        return Ok(());
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_ref_script_deploy_tx(
        &verifier,
        &wallet_addr,
        &wallet_utxos,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build ref-script deploy tx: {e}"))?;
    let tx_hash = submit_tx_blockfrost(cfg, pid, &built.signed_tx_hex, &rt)?;
    println!("submitted: tx_hash={tx_hash}");
    println!(
        "fault-verifier ref UTxO: {tx_hash}:0  (→ fault_verifier_{kind}_ref in the SPO config)"
    );
    Ok(())
}

/// Deploy `spo_bans` as a CIP-33 reference script (M2). Parameterizes it exactly
/// as `DkgFaultBanFlow::from_config`: registry hash + the 3 fault-verifier policy
/// hashes (round1, round2, equivocation — order matters) + ban-schedule params +
/// the ban-list bootstrap outref. Prints the ban-list policy id; --submit deploys.
#[allow(clippy::too_many_arguments)]
fn run_deploy_spo_bans_ref(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    ban_bootstrap: &str,
    base_ban_duration_ms: i64,
    max_faults_before_permanent: i64,
    max_validity_window_ms: i64,
    submit: bool,
    force: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{
        fault_verifier_equivocation_script, fault_verifier_round1_script,
        fault_verifier_round2_script, spo_bans_script, spos_registry_script,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_ref_script_deploy_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let r1 = fault_verifier_round1_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_round1: {e}"))?;
    let r2 = fault_verifier_round2_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_round2: {e}"))?;
    let eq = fault_verifier_equivocation_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_equivocation: {e}"))?;
    let policies = [r1.hash, r2.hash, eq.hash];
    let (ban_tx_id, ban_index) = parse_cardano_outref(ban_bootstrap)?;
    let spo_bans = spo_bans_script(
        &blueprint_json,
        &registry.hash,
        &policies,
        base_ban_duration_ms,
        max_faults_before_permanent,
        max_validity_window_ms,
        &ban_tx_id,
        u64::from(ban_index),
    )
    .map_err(|e| format!("parameterize spo_bans: {e}"))?;

    println!(
        "spo_bans policy id (ban-list policy): {}",
        spo_bans.hash_hex()
    );
    println!("fault_proof_policies (round1, round2, equivocation):");
    println!("  {}", r1.hash_hex());
    println!("  {}", r2.hash_hex());
    println!("  {}", eq.hash_hex());

    if !submit {
        println!(
            "(dry run — hashes only, no wallet needed; pass --submit to deploy the spo_bans ref UTxO)"
        );
        return Ok(());
    }

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;
    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    if ref_script_already_deployed(&raw, &spo_bans.hash_hex(), "spo_bans", force) {
        return Ok(());
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_ref_script_deploy_tx(
        &spo_bans,
        &wallet_addr,
        &wallet_utxos,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build ref-script deploy tx: {e}"))?;

    let tx_hash = submit_tx_blockfrost(cfg, pid, &built.signed_tx_hex, &rt)?;
    println!("submitted: tx_hash={tx_hash}");
    println!("spo_bans ref UTxO: {tx_hash}:0  (→ spo_bans_ref in the SPO config)");
    Ok(())
}

/// Register the stake credentials of heimdall's withdraw-using scripts.
///
/// The table is deliberately a table: today it holds `spo_bans` alone, and a
/// future heimdall-deployed withdraw script is one more row rather than another
/// command. `peg_in`/`peg_out` are *not* here — binocular's `deploy-bridge`
/// registers them in its bootstrap tx, and re-registering is a ledger error.
#[allow(clippy::too_many_arguments)]
fn run_init_scripts(
    cfg: &HeimdallConfig,
    blueprint_path: Option<&str>,
    registry_bootstrap: Option<&str>,
    ban_bootstrap: &str,
    base_ban_duration_ms: i64,
    max_faults_before_permanent: i64,
    max_validity_window_ms: i64,
    key_deposit_override: Option<u64>,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http::{self, RegistrationState};
    use heimdall::cardano::blueprint::{
        fault_verifier_equivocation_script, fault_verifier_round1_script,
        fault_verifier_round2_script, spo_bans_script, spos_registry_script,
    };
    use heimdall::cardano::init_scripts::{
        WithdrawScript, build_init_scripts_tx, is_already_registered_error,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::tx_common::is_testnet_address;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    // Derive spo_bans exactly as deploy-spo-bans-ref and
    // DkgFaultBanFlow::from_config do — recomputing the fault-verifier policy
    // ids from the blueprint rather than reading cfg.fault_proof_policies, so
    // the credential we register cannot drift from the one ApplyBan withdraws.
    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(blueprint_path)?;
    let registry_bootstrap = &resolve_one_shot(cfg, registry_bootstrap)?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let r1 = fault_verifier_round1_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_round1: {e}"))?;
    let r2 = fault_verifier_round2_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_round2: {e}"))?;
    let eq = fault_verifier_equivocation_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("fault_verifier_equivocation: {e}"))?;
    let (ban_tx_id, ban_index) = parse_cardano_outref(ban_bootstrap)?;
    let spo_bans = spo_bans_script(
        &blueprint_json,
        &registry.hash,
        &[r1.hash, r2.hash, eq.hash],
        base_ban_duration_ms,
        max_faults_before_permanent,
        max_validity_window_ms,
        &ban_tx_id,
        u64::from(ban_index),
    )
    .map_err(|e| format!("parameterize spo_bans: {e}"))?;

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;
    let mainnet = !is_testnet_address(&wallet_addr);

    let scripts = vec![WithdrawScript {
        name: "spo_bans",
        hash_hex: spo_bans.hash_hex(),
        reward_address: spo_bans.reward_address(mainnet),
    }];

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // Filter per credential, not per transaction: one already-registered script
    // must not block the rest, or a partially-applied init could never converge.
    println!("withdraw-using scripts deployed by heimdall:");
    let mut pending: Vec<WithdrawScript> = Vec::new();
    for s in scripts {
        let state = rt
            .block_on(bf_http::fetch_account_registered(
                &base_url,
                pid,
                &s.reward_address,
            ))
            .map_err(|e| format!("registration state of {}: {e}", s.name))?;
        let label = match state {
            RegistrationState::Registered => "registered".to_string(),
            RegistrationState::NotRegistered => "NOT registered".to_string(),
            // A 404 here is ambiguous — never-registered and route-not-served
            // are indistinguishable — so say so rather than guessing, and let
            // the submission arbitrate.
            RegistrationState::Unknown { http_status } => {
                format!("unknown (http {http_status}) — will attempt")
            }
        };
        println!("  {:<10} hash={}", s.name, s.hash_hex);
        println!("             reward={}  [{label}]", s.reward_address);
        if state != RegistrationState::Registered {
            pending.push(s);
        }
    }

    if pending.is_empty() {
        println!("all credentials already registered — nothing to do");
        return Ok(());
    }
    if !submit {
        println!(
            "(dry run — {} credential(s) to register; pass --submit)",
            pending.len()
        );
        return Ok(());
    }

    let key_deposit = match key_deposit_override {
        Some(d) => d,
        None => rt
            .block_on(bf_http::fetch_key_deposit(&base_url, pid))
            .map_err(|e| format!("fetch key_deposit: {e}"))?,
    };
    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    // Never let coin selection consume either one-shot bootstrap outref. Both
    // parameterize script hashes — the registry's, and (through the ban list)
    // the very `spo_bans` credential this command registers. Ordering puts this
    // command after both bootstraps, so normally they are already spent; but the
    // ordering is documentation, not an interlock, and spending the ban outref
    // early would register a credential for a `spo_bans` that can now never be
    // bootstrapped at that hash — silently. `run_bootstrap_registry` guards the
    // registry outref for the same reason.
    let reg_outref = (hex::encode(reg_tx_id), reg_index);
    let ban_outref = (hex::encode(ban_tx_id), ban_index);
    let wallet_utxos: Vec<WalletUtxo> = raw
        .iter()
        .map(WalletUtxo::from_bf)
        .filter(|u| {
            let this = (u.tx_hash.clone(), u.output_index);
            this != reg_outref && this != ban_outref
        })
        .collect();
    if wallet_utxos.is_empty() {
        return Err(format!(
            "wallet has no spendable UTxOs besides the bootstrap one-shot outrefs — \
             fund it first (address: {wallet_addr})"
        ));
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_init_scripts_tx(
        &pending,
        key_deposit,
        &wallet_addr,
        &wallet_utxos,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build init-scripts tx: {e}"))?;
    println!(
        "registering {} credential(s), locking {} lovelace of deposits ({key_deposit} each)",
        pending.len(),
        built.deposit_total
    );

    match submit_tx_blockfrost(cfg, pid, &built.signed_tx_hex, &rt) {
        Ok(tx_hash) => {
            println!("submitted init-scripts: tx_hash={tx_hash}");
            Ok(())
        }
        // Idempotency backstop for backends whose /accounts route we cannot
        // trust: a phase-1 "already registered" rejection is the state we
        // wanted, at no cost.
        Err(e) if is_already_registered_error(&e) => {
            println!("credentials already registered on chain (submission rejected: {e})");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// register-spo CLI inputs, bundled (clap hands us a dozen options).
struct RegisterSpoArgs {
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
    cold_skey: Option<String>,
    cold_vkey: Option<String>,
    cold_sig: Option<String>,
    bifrost_skey: Option<String>,
    bifrost_id_pk: Option<String>,
    bifrost_sig: Option<String>,
    bifrost_url: Option<String>,
    registry_ref: Option<String>,
    submit: bool,
}

/// apply-ban CLI inputs.
struct ApplyBanArgs {
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
    accused_pool_id: String,
    evidence_hash: String,
    fault_kind: String,
    spo_bans_ref: String,
    submit: bool,
}

/// fault-proof-mint CLI inputs.
struct FaultProofMintArgs {
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
    evidence_file: String,
    submit: bool,
}

/// Parse a 32-byte secret-key argument: inline hex, a file containing hex, or
/// a cardano-cli TextEnvelope file (`cborHex` = `"5820" || 32 bytes`).
fn parse_key32(arg: &str, what: &str) -> Result<[u8; 32], String> {
    let content = if std::path::Path::new(arg).is_file() {
        std::fs::read_to_string(arg).map_err(|e| format!("{what}: read {arg}: {e}"))?
    } else {
        arg.to_string()
    };
    let trimmed = content.trim();
    let hex_str = if trimmed.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("{what}: TextEnvelope JSON: {e}"))?;
        v.get("cborHex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("{what}: TextEnvelope has no cborHex"))?
            .strip_prefix("5820")
            .ok_or_else(|| format!("{what}: cborHex is not a 32-byte key (5820…)"))?
            .to_string()
    } else {
        trimmed.to_string()
    };
    parse_hex_n(&hex_str, what)
}

/// Parse an inline hex argument of exactly `N` bytes.
fn parse_hex_n<const N: usize>(arg: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(arg.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{what}: expected {N} bytes of hex"))
}

fn parse_fault_verifier_kind(
    value: &str,
) -> Result<heimdall::cardano::blueprint::FaultVerifierKind, String> {
    use heimdall::cardano::blueprint::FaultVerifierKind;
    match value {
        "round1" | "invalid-payload-round1" => Ok(FaultVerifierKind::Round1),
        "round2" | "invalid-payload-round2" => Ok(FaultVerifierKind::Round2),
        "equivocation" => Ok(FaultVerifierKind::Equivocation),
        other => Err(format!(
            "fault kind must be round1, round2, or equivocation; got `{other}`"
        )),
    }
}

fn parse_points(hexes: &[String]) -> Result<Vec<[u8; 33]>, String> {
    hexes
        .iter()
        .enumerate()
        .map(|(i, h)| parse_hex_n::<33>(h, &format!("commitment[{i}]")))
        .collect()
}

/// Captured DKG misbehavior, the input to WI-019 `evidence_hash` derivation.
/// Each shape carries the **authentication envelope** the spec requires (§9.2):
/// the accused's x-only `bifrost_id_pk` and their BIP-340 `payload_signature`
/// over `SHA256(canonical_bytes)`. `derive` verifies that signature before
/// deriving anything — heimdall never forges a FaultProof against a payload the
/// accused did not author.
///
/// One of three shapes selected by `kind`:
/// - `"invalid-payload-round1"`: `identifier`, `commitments[]`, `sigma_i`,
///   `payload_signature`, `halo2_proof`
/// - `"invalid-payload-round2"`: `recipient_index`, `round2_entry_index`,
///   `sender_commitments[]`, `canonical_round1_bytes`, `round1_signature`,
///   `share`, `pad`, `round2_canonical_bytes`, `round2_signature`,
///   `halo2_proof`
/// - `"equivocation"`: `round` (`"round1"|"round2"`), `payload_a`/`signature_a`,
///   `payload_b`/`signature_b` (payloads are the canonical signed bytes)
///
/// Shared header: `accused_pool_id` (28-byte hex), `bifrost_id_pk` (32-byte hex),
/// `epoch`, `threshold`, `attempt`. All byte fields are hex.
#[derive(serde::Deserialize)]
struct EvidenceFile {
    kind: String,
    accused_pool_id: String,
    bifrost_id_pk: String,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    #[serde(default)]
    identifier: Option<u16>,
    #[serde(default)]
    commitments: Option<Vec<String>>,
    #[serde(default)]
    sigma_i: Option<String>,
    #[serde(default)]
    recipient_index: Option<u16>,
    #[serde(default)]
    sender_commitments: Option<Vec<String>>,
    #[serde(default)]
    canonical_round1_bytes: Option<String>,
    #[serde(default)]
    round1_signature: Option<String>,
    #[serde(default)]
    round2_entry_index: Option<u32>,
    #[serde(default)]
    share: Option<String>,
    #[serde(default)]
    pad: Option<String>,
    #[serde(default)]
    round2_canonical_bytes: Option<String>,
    #[serde(default)]
    round2_signature: Option<String>,
    #[serde(default)]
    halo2_proof: Option<String>,
    #[serde(default)]
    payload_signature: Option<String>,
    #[serde(default)]
    round: Option<String>,
    #[serde(default)]
    payload_a: Option<String>,
    #[serde(default)]
    signature_a: Option<String>,
    #[serde(default)]
    payload_b: Option<String>,
    #[serde(default)]
    signature_b: Option<String>,
}

/// The evidence fields `build_fault_proof_mint_tx` needs, derived from captured
/// evidence.
#[derive(Debug)]
struct DerivedFault {
    kind: heimdall::cardano::blueprint::FaultVerifierKind,
    accused_pool_id: [u8; 28],
    namespace_hash: [u8; 32],
    evidence_hash: [u8; 32],
    round1_invalid: Option<DerivedRound1Invalid>,
    round2_invalid: Option<DerivedRound2Invalid>,
    equivocation: Option<DerivedEquivocation>,
}

#[derive(Debug)]
struct DerivedRound1Invalid {
    canonical_round1_bytes: Vec<u8>,
    payload_signature: [u8; 64],
    halo2_proof: Vec<u8>,
}

#[derive(Debug)]
struct DerivedRound2Invalid {
    canonical_round1_bytes: Vec<u8>,
    round1_signature: [u8; 64],
    canonical_round2_bytes: Vec<u8>,
    round2_signature: [u8; 64],
    round2_entry_index: u32,
    pad: [u8; 32],
    opened_share: [u8; 32],
    halo2_proof: Vec<u8>,
}

#[derive(Debug)]
struct DerivedEquivocation {
    payload_a: Vec<u8>,
    signature_a: [u8; 64],
    payload_b: Vec<u8>,
    signature_b: [u8; 64],
}

fn req_field<'a>(v: &'a Option<String>, what: &str) -> Result<&'a str, String> {
    v.as_deref().ok_or(format!("evidence: missing `{what}`"))
}

fn decode_var(v: &Option<String>, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(req_field(v, what)?.trim()).map_err(|_| format!("{what}: bad hex"))
}

fn decode_optional_var(v: &Option<String>) -> Result<Vec<u8>, String> {
    match v {
        Some(value) => hex::decode(value.trim()).map_err(|_| "halo2_proof: bad hex".to_string()),
        None => Ok(Vec::new()),
    }
}

fn round2_signature_field(file: &EvidenceFile) -> Result<[u8; 64], String> {
    let raw = file
        .round2_signature
        .as_ref()
        .or(file.payload_signature.as_ref())
        .ok_or("evidence: missing `round2_signature`")?;
    parse_hex_n::<64>(raw, "round2_signature")
}

impl EvidenceFile {
    /// Derive `(kind, accused_pool_id, namespace_hash, evidence_hash)` from the
    /// captured evidence. Verifies the accused's payload signature and that the
    /// evidence actually encodes a fault before deriving.
    fn derive(&self) -> Result<DerivedFault, String> {
        use heimdall::cardano::blueprint::FaultVerifierKind;
        use heimdall::circuits::fault_evidence as fe;

        let accused_pool_id: [u8; 28] =
            parse_hex_n(self.accused_pool_id.trim(), "accused_pool_id")?;
        let bifrost_id_pk: [u8; 32] = parse_hex_n(self.bifrost_id_pk.trim(), "bifrost_id_pk")?;
        let to_err = |e: fe::FaultEvidenceError| e.to_string();

        match self.kind.as_str() {
            "invalid-payload-round1" => {
                let ev = fe::Round1PokFaultEvidence {
                    epoch: self.epoch,
                    threshold: self.threshold,
                    attempt: self.attempt,
                    accused_pool_id,
                    bifrost_id_pk,
                    identifier: self
                        .identifier
                        .ok_or("round1 evidence: missing `identifier`")?,
                    commitments: parse_points(
                        self.commitments
                            .as_deref()
                            .ok_or("round1 evidence: missing `commitments`")?,
                    )?,
                    sigma_i: parse_hex_n::<64>(req_field(&self.sigma_i, "sigma_i")?, "sigma_i")?,
                    payload_signature: parse_hex_n::<64>(
                        req_field(&self.payload_signature, "payload_signature")?,
                        "payload_signature",
                    )?,
                };
                ev.verify_payload_signature().map_err(to_err)?;
                if !ev.is_fault().map_err(to_err)? {
                    return Err("round1 evidence does not encode a fault (PoK verifies)".into());
                }
                Ok(DerivedFault {
                    kind: FaultVerifierKind::Round1,
                    accused_pool_id,
                    namespace_hash: ev.namespace_hash(),
                    evidence_hash: ev.evidence_hash().map_err(to_err)?,
                    round1_invalid: Some(DerivedRound1Invalid {
                        canonical_round1_bytes: ev.canonical_bytes().map_err(to_err)?,
                        payload_signature: ev.payload_signature,
                        halo2_proof: decode_optional_var(&self.halo2_proof)?,
                    }),
                    round2_invalid: None,
                    equivocation: None,
                })
            }
            "invalid-payload-round2" => {
                let ev = fe::Round2ShareFaultEvidence {
                    epoch: self.epoch,
                    threshold: self.threshold,
                    attempt: self.attempt,
                    accused_pool_id,
                    bifrost_id_pk,
                    recipient_index: self
                        .recipient_index
                        .ok_or("round2 evidence: missing `recipient_index`")?,
                    round2_entry_index: self
                        .round2_entry_index
                        .ok_or("round2 evidence: missing `round2_entry_index`")?,
                    sender_commitments: parse_points(
                        self.sender_commitments
                            .as_deref()
                            .ok_or("round2 evidence: missing `sender_commitments`")?,
                    )?,
                    canonical_round1_bytes: decode_var(
                        &self.canonical_round1_bytes,
                        "canonical_round1_bytes",
                    )?,
                    round1_signature: parse_hex_n::<64>(
                        req_field(&self.round1_signature, "round1_signature")?,
                        "round1_signature",
                    )?,
                    share: parse_hex_n::<32>(req_field(&self.share, "share")?, "share")?,
                    pad: parse_hex_n::<32>(req_field(&self.pad, "pad")?, "pad")?,
                    round2_canonical_bytes: decode_var(
                        &self.round2_canonical_bytes,
                        "round2_canonical_bytes",
                    )?,
                    round2_signature: round2_signature_field(self)?,
                };
                ev.verify_payload_signature().map_err(to_err)?;
                if !ev.is_fault().map_err(to_err)? {
                    return Err("round2 evidence does not encode a fault (share verifies)".into());
                }
                Ok(DerivedFault {
                    kind: FaultVerifierKind::Round2,
                    accused_pool_id,
                    namespace_hash: ev.namespace_hash(),
                    evidence_hash: fe::round2_evidence_hash_dyn(&ev).map_err(to_err)?,
                    round1_invalid: None,
                    round2_invalid: Some(DerivedRound2Invalid {
                        canonical_round1_bytes: ev.canonical_round1_bytes,
                        round1_signature: ev.round1_signature,
                        canonical_round2_bytes: ev.round2_canonical_bytes,
                        round2_signature: ev.round2_signature,
                        round2_entry_index: ev.round2_entry_index,
                        pad: ev.pad,
                        opened_share: ev.share,
                        halo2_proof: decode_optional_var(&self.halo2_proof)?,
                    }),
                    equivocation: None,
                })
            }
            "equivocation" => {
                let phase = match self.round.as_deref() {
                    Some("round1") => fe::NamespacePhase::Round1,
                    Some("round2") => fe::NamespacePhase::Round2,
                    other => {
                        return Err(format!(
                            "equivocation evidence: `round` must be round1|round2, got {other:?}"
                        ));
                    }
                };
                let ev = fe::EquivocationEvidence {
                    epoch: self.epoch,
                    threshold: self.threshold,
                    attempt: self.attempt,
                    phase,
                    accused_pool_id,
                    bifrost_id_pk,
                    payload_a: decode_var(&self.payload_a, "payload_a")?,
                    signature_a: parse_hex_n::<64>(
                        req_field(&self.signature_a, "signature_a")?,
                        "signature_a",
                    )?,
                    payload_b: decode_var(&self.payload_b, "payload_b")?,
                    signature_b: parse_hex_n::<64>(
                        req_field(&self.signature_b, "signature_b")?,
                        "signature_b",
                    )?,
                };
                ev.verify().map_err(to_err)?;
                Ok(DerivedFault {
                    kind: FaultVerifierKind::Equivocation,
                    accused_pool_id,
                    namespace_hash: ev.namespace_hash(),
                    evidence_hash: ev.evidence_hash(),
                    round1_invalid: None,
                    round2_invalid: None,
                    equivocation: Some(DerivedEquivocation {
                        payload_a: ev.payload_a,
                        signature_a: ev.signature_a,
                        payload_b: ev.payload_b,
                        signature_b: ev.signature_b,
                    }),
                })
            }
            other => Err(format!(
                "evidence `kind` must be invalid-payload-round1|invalid-payload-round2|\
                 equivocation, got `{other}`"
            )),
        }
    }
}

/// Bech32 (`pool1…`) form of the 28-byte pool key hash, as Blockfrost expects.
use heimdall::cardano::hash::pool_id_bech32;

/// Build (and with `--submit`, broadcast) the register_spo tx. Identities come
/// from local secret keys or from the air-gapped (vkey + signature) flow; the
/// R2 min-stake gate must pass before anything is submitted.
fn run_register_spo(cfg: &HeimdallConfig, args: &RegisterSpoArgs) -> Result<(), String> {
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::{Keypair, Message};
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spos_registry_script, treasury_info_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::ref_script::find_ref_script;
    use heimdall::cardano::ref_script::{RefScriptOrigin, find_ref_script_anywhere};
    use heimdall::cardano::register_spo::{
        RegisterSpoRequest, RegistrationSignatures, build_register_spo_tx, pool_id_from_cold_vkey,
        registration_message, verify_registration,
    };
    use heimdall::cardano::registry::REGISTRATION_ROOT_KEY;
    use heimdall::cardano::stake::{StakeSource, check_min_stake, fetch_pool_stake_src};
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
    use pallas_crypto::key::ed25519;

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(args.blueprint.as_deref())?;
    let registry_bootstrap = resolve_one_shot(cfg, args.registry_bootstrap.as_deref())?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(&registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let treasury = treasury_info_script(
        &blueprint_json,
        &tsy_tx_id,
        u64::from(tsy_index),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize treasury_info: {e}"))?;
    let registry = spos_registry_script(
        &blueprint_json,
        &reg_tx_id,
        u64::from(reg_index),
        &treasury.hash,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;

    // ── identities: local secret keys, or the air-gapped halves ──
    //
    // `--cold-skey` falls back to `cardano.cold_skey_path`. There is no default
    // location behind that: unset means the cold key is not on this machine,
    // which is a legitimate state — the air-gapped halves below cover it — and
    // not a setting someone forgot.
    let cold_skey_src = args
        .cold_skey
        .as_deref()
        .or(cfg.cardano.cold_skey_path.as_deref());
    let cold_skey: Option<ed25519::SecretKey> = cold_skey_src
        .map(|arg| parse_key32(arg, "--cold-skey").map(ed25519::SecretKey::from))
        .transpose()?;
    let cold_vkey_src = args
        .cold_vkey
        .as_deref()
        .or(cfg.cardano.cold_vkey_path.as_deref());
    let cold_vkey: [u8; 32] = match (&cold_skey, cold_vkey_src) {
        (Some(sk), None) => sk.public_key().into(),
        // parse_key32, not raw hex: pool-cold.vkey is a Cardano TextEnvelope, so
        // requiring hex here made the operator slice `cborHex` past its 5820
        // prefix by hand — while --cold-skey accepted the file directly. A wrong
        // slice yields a wrong pool_id, i.e. a well-formed registration for a
        // pool that is not theirs.
        (None, Some(vk)) => parse_key32(vk, "--cold-vkey")?,
        (Some(sk), Some(vk)) => {
            let derived: [u8; 32] = sk.public_key().into();
            if parse_key32(vk, "--cold-vkey")? != derived {
                return Err("--cold-vkey does not match --cold-skey".into());
            }
            derived
        }
        (None, None) => {
            return Err(
                "provide --cold-skey, or --cold-vkey (+ --cold-sig) for the air-gapped flow".into(),
            );
        }
    };

    let secp = Secp256k1::new();
    // `[bifrost].skey_path` is the same key the daemon runs on, so a node that
    // signs its own registration need not name it twice. `None` still means the
    // air-gapped halves below, which is why this is not an error when unset.
    let bifrost_skey_src = args
        .bifrost_skey
        .as_deref()
        .or(cfg.bifrost.skey_path.as_deref());
    let bifrost_keypair: Option<Keypair> = match bifrost_skey_src {
        Some(arg) => Some(
            Keypair::from_seckey_slice(&secp, &parse_key32(arg, "--bifrost-skey")?)
                .map_err(|e| format!("--bifrost-skey: {e}"))?,
        ),
        None => None,
    };
    let bifrost_id_pk: [u8; 32] = match (&bifrost_keypair, args.bifrost_id_pk.as_deref()) {
        (Some(kp), None) => kp.x_only_public_key().0.serialize(),
        (None, Some(pk)) => parse_hex_n(pk, "--bifrost-id-pk")?,
        (Some(kp), Some(pk)) => {
            let derived = kp.x_only_public_key().0.serialize();
            if parse_hex_n::<32>(pk, "--bifrost-id-pk")? != derived {
                return Err("--bifrost-id-pk does not match --bifrost-skey".into());
            }
            derived
        }
        (None, None) => {
            return Err(
                "provide --bifrost-skey, or --bifrost-id-pk (+ --bifrost-sig) for the \
                 air-gapped flow"
                    .into(),
            );
        }
    };

    let pool_id = pool_id_from_cold_vkey(&cold_vkey);
    let bifrost_url = resolve_bifrost_url(cfg, args.bifrost_url.as_deref())?;
    let message = registration_message(&pool_id, &bifrost_id_pk, bifrost_url.as_bytes());
    let digest = sha256::Hash::hash(&message).to_byte_array();

    let cold_sig: [u8; 64] = match (&cold_skey, args.cold_sig.as_deref()) {
        (Some(sk), _) => sk
            .sign(&message)
            .as_ref()
            .try_into()
            .expect("ed25519 signature is 64 bytes"),
        (None, Some(sig)) => parse_hex_n(sig, "--cold-sig")?,
        (None, None) => {
            return Err(format!(
                "no --cold-skey/--cold-sig. Air-gapped: Ed25519-sign this message with the \
                 pool cold key and re-run with --cold-sig:\n  message (hex): {}",
                hex::encode(&message)
            ));
        }
    };
    let bifrost_sig: [u8; 64] = match (&bifrost_keypair, args.bifrost_sig.as_deref()) {
        (Some(kp), _) => secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), kp)
            .serialize(),
        (None, Some(sig)) => parse_hex_n(sig, "--bifrost-sig")?,
        (None, None) => {
            return Err(format!(
                "no --bifrost-skey/--bifrost-sig. Air-gapped: BIP340-sign this 32-byte digest \
                 with the bifrost identity key and re-run with --bifrost-sig:\n  \
                 sha2_256(message): {}",
                hex::encode(digest)
            ));
        }
    };
    let sigs = RegistrationSignatures {
        cold_vkey,
        cold_sig,
        bifrost_sig,
    };
    verify_registration(&sigs, &bifrost_id_pk, bifrost_url.as_bytes())
        .map_err(|e| format!("registration signatures: {e}"))?;

    println!(
        "pool id:           {} ({})",
        hex::encode(pool_id),
        pool_id_bech32(&pool_id)
    );
    println!("bifrost_id_pk:     {}", hex::encode(bifrost_id_pk));
    println!("bifrost_url:       {bifrost_url}");
    println!("registry policy:   {}", registry.hash_hex());
    println!("treasury policy:   {}", treasury.hash_hex());

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // ── R2 min-stake gate: gates submission; a dry run only warns ──
    //
    // The threshold is `cardano.min_stake_lovelace`. Rev 5.4 removed `min_stake` from
    // the Config datum (spec §Config datum: the table is exhaustive, and the field
    // never had an on-chain reader — it gated this registration off-chain only), so
    // the gate is a local operational policy again. `None` skips the gate.
    let stake_source = StakeSource::from_config(cfg.cardano.stake_source.as_deref())?;
    let min_stake = cfg.cardano.min_stake_lovelace;
    match min_stake {
        Some(threshold) => {
            // yaci-store reads stake per-epoch; Blockfrost ignores the epoch.
            let epoch = match stake_source {
                StakeSource::YaciStore => rt
                    .block_on(bf_http::fetch_current_epoch(&base_url, pid))
                    .map_err(|e| format!("min-stake gate (epoch): {e}"))?,
                StakeSource::Blockfrost => 0,
            };
            let stake = rt
                .block_on(fetch_pool_stake_src(
                    stake_source,
                    &base_url,
                    pid,
                    epoch,
                    &pool_id_bech32(&pool_id),
                ))
                .map_err(|e| format!("min-stake gate: {e}"))?;
            let chk = check_min_stake(&stake, threshold);
            println!(
                "min-stake gate:    active_stake={} threshold={} → {}",
                chk.active_stake,
                chk.threshold,
                if chk.meets { "PASS" } else { "FAIL" }
            );
            if !chk.meets {
                if args.submit {
                    return Err(
                        "min-stake gate failed (R2) — refusing to submit register_spo".into(),
                    );
                }
                warn!(
                    "[register-spo] min-stake gate failed; printing the dry-run tx, \
                     but submission would be refused"
                );
            }
        }
        None => {
            if args.submit {
                return Err("no min_stake threshold — the R2 gate cannot run. Set \
                     cardano.min_stake_lovelace before submitting. It is a LOCAL operational \
                     policy, not a published one: rev 5.4 removed min_stake from the Config \
                     datum, so no chain read can supply it"
                    .into());
            }
            warn!(
                "[register-spo] no min_stake threshold (no Config UTxO configured and \
                 no cardano.min_stake_lovelace); dry run only — submission would be refused"
            );
        }
    }

    // ── chain state ──
    let network = network_of(&wallet_addr);
    let registry_addr = registry.enterprise_address(network);
    let treasury_addr = treasury.enterprise_address(network);
    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let registry_utxos = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &registry_addr))
        .map_err(|e| format!("registry UTxO query: {e}"))?;
    let treasury_utxos = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &treasury_addr))
        .map_err(|e| format!("treasury UTxO query: {e}"))?;
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;
    // Epoch-boundary validity window: the tx may not land in a later epoch
    // than the one it was built (and its candidate snapshot computed) in.
    let window = rt
        .block_on(bf_http::fetch_epoch_window(&base_url, pid))
        .map_err(|e| format!("epoch window: {e}"))?;
    println!(
        "validity window:   [{}, {}) — current epoch only",
        window.current_slot, window.epoch_end_slot
    );

    // The registry script is needed for both the spend and the mint; at ~12 KB,
    // embedding it twice does not fit in a 16 KB transaction, so it must be
    // referenced. `deploy-registry-ref` key-locks it at this very wallet, whose
    // UTxOs we just fetched — so the outpoint no longer has to be copied by hand
    // between the two commands (WI-056). `--registry-ref` overrides, for a
    // reference script held anywhere else: another SPO's, or one at an address
    // that is not this wallet. Blockfrost has no by-script-hash query, so those
    // cannot be discovered.
    let registry_ref = match args.registry_ref.as_deref() {
        Some(s) => {
            let (tx_id, index) =
                parse_cardano_outref(s).map_err(|e| format!("--registry-ref: {e}"))?;
            let outref = (hex::encode(tx_id), index);
            println!(
                "registry ref:      {}#{} (--registry-ref)",
                outref.0, outref.1
            );
            Some(outref)
        }
        None => {
            let hash = registry.hash_hex();
            // Look at this wallet first, then at the wallet the bridge was
            // deployed from (WI-091). `deploy-script-refs` already published this
            // script there for the whole bridge, so an SPO who finds it needs no
            // deploy step and locks no ADA. The deployer's address is derived
            // from the Config-published one-shot, not handed over by anyone.
            let found = rt
                .block_on(find_ref_script_anywhere(
                    &base_url,
                    pid,
                    &wallet_addr,
                    Some(&registry_bootstrap),
                    &hash,
                ))
                .map_err(|e| format!("reference-script lookup: {e}"))?;
            let (found, origin) = found.ok_or_else(|| {
                format!(
                    "no reference script for the registry ({hash}), at {wallet_addr} or at the \
                     wallet this bridge was deployed from.\n\
                     The ~12 KB registry script is needed for both the spend and the mint of \
                     this transaction, and embedding it twice exceeds the 16 KB limit, so it \
                     must be on chain first:\n\
                     \x20 heimdall deploy-registry-ref --config <file> --submit\n\
                     (~55 ADA, reclaimable — it stays key-locked at this wallet, and this \
                     command then finds it on its own).\n\
                     If one is already deployed elsewhere, pass it as --registry-ref <txid:ix>.",
                )
            })?;
            match &origin {
                RefScriptOrigin::OwnWallet => {
                    println!("registry ref:      {found} (discovered at this wallet)");
                }
                RefScriptOrigin::Deployer(addr) => {
                    // Say whose it is. It is kept SPENDABLE on purpose, so the
                    // deployer can reclaim it and break this path for everyone
                    // relying on it — an operator should know they depend on it
                    // rather than discover it when a registration stops building.
                    println!("registry ref:      {found} (the bridge deployer's, at {addr})");
                    println!(
                        "                   nothing to deploy — but that UTxO is theirs to spend"
                    );
                }
            }
            Some(found.outref())
        }
    };

    // Rev 5.5: treasury.ak's RegistryUpdate branch reads the registry policy from
    // the Config datum ([TSY-12]), so the tx must reference the Config UTxO.
    let config_view = rt
        .block_on(config_view_async(cfg))?
        .ok_or("register-spo needs the Config UTxO (treasury.ak reads the registry policy from it); set cardano.config_address and cardano.config_nft_policy_id")?;

    let req = RegisterSpoRequest {
        registry_script: &registry,
        treasury_script: &treasury,
        // [CFG-4]: the state NFT's name is a protocol constant, not a per-bridge
        // value. It used to be `--treasury-nft-name`, which is how an operator
        // could name a token no deployment mints and find no treasury state.
        treasury_asset_name_hex: &hex::encode(
            heimdall::cardano::config_params::TREASURY_INFO_ASSET_NAME,
        ),
        config_ref: (config_view.utxo.tx_hash.clone(), config_view.utxo.index),
        registry_utxos: &registry_utxos,
        treasury_utxos: &treasury_utxos,
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        sigs: &sigs,
        bifrost_id_pk,
        bifrost_url: bifrost_url.as_bytes().to_vec(),
        invalid_before: Some(window.current_slot),
        invalid_hereafter: Some(window.epoch_end_slot),
        registry_ref,
        cost_models: Some(cost_models),
    };
    let built = build_register_spo_tx(&req).map_err(|e| format!("build register_spo tx: {e}"))?;

    let anchor = if built.anchor_asset_name == REGISTRATION_ROOT_KEY {
        "reg-root (registry root)".to_string()
    } else {
        hex::encode(&built.anchor_asset_name)
    };
    println!("anchor element:    {anchor}");
    println!(
        "new identity root: {}",
        hex::encode(built.new_bifrost_identity_root)
    );
    println!(
        "membership token:  {}.{}",
        registry.hash_hex(),
        hex::encode(built.pool_id)
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

struct UpdateYArgs {
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
    new_key: String,
    epoch: u64,
    signer_skey: Option<String>,
    signature: Option<String>,
    /// spec [UY-5]: authorize as the federation – the signature is made (and
    /// checked) under the spent datum's `y_federation`.
    federation: bool,
    submit: bool,
}

/// Build (and with `--submit`, broadcast) the Update-Y key-rotation tx: spend the
/// treasury_info state UTxO with the `UpdateY` redeemer, rotating
/// `current_spos_frost_key` to `--new-key`. The OUTGOING key signs the
/// domain-tagged message – or, with `--federation`, the FEDERATION key signs it
/// (spec [UY-5]; same tx, same message, different datum key). Phase 1 default
/// signer: the y_fed seed; else `--signer-skey`, or an air-gapped
/// `--signature`. Submission is permissionless.
fn run_update_y(cfg: &HeimdallConfig, args: &UpdateYArgs) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::{Keypair, Message};
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spos_registry_script, treasury_info_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::treasury_info::update_y_sig_msg;
    use heimdall::cardano::treasury_spend::find_treasury_state;
    use heimdall::cardano::update_y::{UpdateYAuthorizer, UpdateYRequest, build_update_y_tx};
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(args.blueprint.as_deref())?;
    let registry_bootstrap = resolve_one_shot(cfg, args.registry_bootstrap.as_deref())?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(&registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let treasury = treasury_info_script(
        &blueprint_json,
        &tsy_tx_id,
        u64::from(tsy_index),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize treasury_info: {e}"))?;
    let registry = spos_registry_script(
        &blueprint_json,
        &reg_tx_id,
        u64::from(reg_index),
        &treasury.hash,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;

    let new_key = parse_hex_n::<32>(&args.new_key, "--new-key")?;
    let epoch_i64 =
        i64::try_from(args.epoch).map_err(|_| "epoch too large for Plutus Int".to_string())?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let network = network_of(&wallet_addr);
    let treasury_addr = treasury.enterprise_address(network);
    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let treasury_utxos = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &treasury_addr))
        .map_err(|e| format!("treasury UTxO query: {e}"))?;
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;
    let window = rt
        .block_on(bf_http::fetch_epoch_window(&base_url, pid))
        .map_err(|e| format!("epoch window: {e}"))?;

    let state = find_treasury_state(
        &treasury_utxos,
        &treasury.hash_hex(),
        // [CFG-4] constant, not a flag — see run_register_spo.
        &hex::encode(heimdall::cardano::config_params::TREASURY_INFO_ASSET_NAME),
    )
    .map_err(|e| format!("locate treasury state: {e}"))?;

    let spent_txid: [u8; 32] = hex::decode(&state.tx_hash)
        .map_err(|e| format!("state txid hex: {e}"))?
        .try_into()
        .map_err(|_| "state txid must be 32 bytes".to_string())?;
    let sig_msg = update_y_sig_msg(&spent_txid, state.output_index, args.epoch, &new_key);

    // spec [UY-5]: with --federation the signature is made under the spent
    // datum's y_federation; otherwise under its current_spos_frost_key. The
    // built tx is identical either way.
    let authorizer = if args.federation {
        UpdateYAuthorizer::Federation
    } else {
        UpdateYAuthorizer::Roster
    };
    // Rev 5.5 [UY-5]: the federation key is Config #11, not a datum field, and
    // the tx must reference the Config UTxO so treasury.ak can read it
    // ([TSY-12]). This CLI parameterizes its scripts from the blueprint, so it
    // did not previously need a Config read at all.
    let config = rt
        .block_on(config_view_async(cfg))?
        .ok_or("update-y needs the Config UTxO (y_federation is #11); set cardano.config_address and cardano.config_nft_policy_id")?;
    let y_federation = config.params.y_federation;
    let (expected_signer, signer_role) = authorizer.signing_key(&state.datum, &y_federation);

    println!("treasury policy:   {}", treasury.hash_hex());
    println!(
        "state UTxO:        {}:{}",
        state.tx_hash, state.output_index
    );
    println!(
        "current key:       {}",
        hex::encode(&state.datum.current_spos_frost_key)
    );
    if args.federation {
        println!("y_federation:      {}", hex::encode(y_federation));
    }
    println!("new key:           {}", hex::encode(new_key));
    println!("epoch:             {}", args.epoch);
    println!("sign message:      {}", hex::encode(sig_msg));

    // Resolve the 64-byte BIP340 signature under the authorizing key.
    let secp = Secp256k1::new();
    let signature: [u8; 64] = if let Some(sig_hex) = args.signature.as_deref() {
        parse_hex_n::<64>(sig_hex, "--signature")?
    } else {
        let sk = match args.signer_skey.as_deref() {
            Some(hex_sk) => {
                bitcoin::secp256k1::SecretKey::from_slice(&parse_key32(hex_sk, "--signer-skey")?)
                    .map_err(|e| format!("--signer-skey: {e}"))?
            }
            // Phase 1 default: both the outgoing key and the federation key
            // are the config y_fed seed.
            None => y_fed_keypair(&secp, cfg)?.0,
        };
        let kp = Keypair::from_secret_key(&secp, &sk);
        let signer_xonly = kp.x_only_public_key().0.serialize();
        if signer_xonly.as_slice() != expected_signer {
            return Err(format!(
                "signer key {} does not match the treasury's {signer_role} {} – that key must \
                 sign Update-Y (Phase 1: y_fed; else pass --signer-skey, or BIP340-sign the \
                 printed message and pass --signature)",
                hex::encode(signer_xonly),
                hex::encode(expected_signer)
            ));
        }
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sig_msg), &kp)
            .serialize()
    };

    let req = UpdateYRequest {
        treasury_script: &treasury,
        state: &state,
        new_spos_frost_key: &new_key,
        epoch: epoch_i64,
        signature: &signature,
        authorizer,
        y_federation: &y_federation,
        config_ref: (&config.utxo.tx_hash, config.utxo.index),
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        invalid_before: Some(window.current_slot),
        invalid_hereafter: Some(window.epoch_end_slot),
        cost_models: Some(cost_models),
    };
    let built = build_update_y_tx(&req).map_err(|e| format!("build update-y tx: {e}"))?;
    println!(
        "rotated key ->:    {}",
        hex::encode(&built.new_datum.current_spos_frost_key)
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Build (and with `--submit`, broadcast) the `spo_bans.ApplyBan` tx: consume a
/// published FaultProof and write the ban-list node (WI-018 pt4b). The
/// fault-policy set + ban-schedule params come from `[cardano]` config (they
/// are baked into the ban policy id).
fn run_apply_ban(cfg: &HeimdallConfig, args: &ApplyBanArgs) -> Result<(), String> {
    use heimdall::cardano::apply_ban::{ApplyBanRequest, FaultProofUtxo, build_apply_ban_tx};
    use heimdall::cardano::ban_list::{BanPolicyParams, fault_token_name};
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{
        fault_verifier_script, spo_bans_script, spos_registry_script,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(args.blueprint.as_deref())?;
    let registry_bootstrap = resolve_one_shot(cfg, args.registry_bootstrap.as_deref())?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(&registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let fault_kind = parse_fault_verifier_kind(&args.fault_kind)?;
    let fault = fault_verifier_script(&blueprint_json, fault_kind, &registry.hash)
        .map_err(|e| format!("parameterize fault_verifier: {e}"))?;

    // The ban policy is chain-pinned: the one-shot from Config #12, plus the
    // fault-policy set and the schedule the Config also publishes.
    let ban_bootstrap = cfg
        .cardano
        .federation_one_shot
        .as_deref()
        .ok_or("the federation one-shot (Config #12) has not been resolved from the chain")?;
    let (ban_tx_id, ban_index) = parse_cardano_outref(ban_bootstrap)?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    // The ban a tx applies is computed from the SCHEDULE — its end time from
    // params[4]/params[5] and the validity interval from params[6] — so those
    // numbers must be the deployment's, not this operator's. Read them from the
    // Config where the bridge publishes them; the derived policy is then checked
    // against #8.
    let bridge_config = config_view(&rt, cfg)?;
    let params = BanPolicyParams::resolve(&cfg.cardano, bridge_config.as_ref().map(|v| &v.params))
        .map_err(|e| e.to_string())?;
    let spo_bans = spo_bans_script(
        &blueprint_json,
        &registry.hash,
        &params.fault_proof_policies,
        params.base_ban_duration_ms,
        params.max_faults_before_permanent,
        params.max_validity_window_ms,
        &ban_tx_id,
        u64::from(ban_index),
    )
    .map_err(|e| format!("parameterize spo_bans: {e}"))?;
    if let Some(published) = bridge_config.as_ref().map(|v| &v.params.bans)
        && published.spo_bans_policy_id != spo_bans.hash
    {
        return Err(format!(
            "this ban would be applied to policy {} but the bridge Config publishes {} \
             (field #8) — it would confirm into a ban list no other SPO reads. Check \
             cardano.ban_bootstrap and cardano.fault_proof_policies against this bridge",
            spo_bans.hash_hex(),
            hex::encode(published.spo_bans_policy_id),
        ));
    }

    let accused_pool_id: [u8; 28] = parse_hex_n(&args.accused_pool_id, "--accused-pool-id")?;
    let evidence_hash: [u8; 32] = parse_hex_n(&args.evidence_hash, "--evidence-hash")?;
    let (sb_tx, sb_ix) = parse_cardano_outref(&args.spo_bans_ref)?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());

    let network = network_of(&wallet_addr);
    let mainnet = matches!(network, pallas_addresses::Network::Mainnet);
    let ban_addr = spo_bans.enterprise_address(network);
    let registry_addr = registry.enterprise_address(network);

    println!("ban policy:        {}", spo_bans.hash_hex());
    println!("ban address:       {ban_addr}");
    println!(
        "accused pool:      {} ({})",
        hex::encode(accused_pool_id),
        pool_id_bech32(&accused_pool_id)
    );

    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let registry_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &registry_addr))
        .map_err(|e| format!("registry UTxO query: {e}"))?;
    let ban_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &ban_addr))
        .map_err(|e| format!("ban UTxO query: {e}"))?;
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;
    let window = rt
        .block_on(bf_http::fetch_epoch_window(&base_url, pid))
        .map_err(|e| format!("epoch window: {e}"))?;

    // Locate the parked FaultProof UTxO at the wallet (Part 3b output).
    let token_name = fault_token_name(&accused_pool_id, &evidence_hash);
    let fault_unit = format!("{}{}", fault.hash_hex(), hex::encode(token_name));
    let lovelace_of = |u: &bf_http::BfUtxo| -> u64 {
        u.amount
            .iter()
            .find(|a| a.unit == "lovelace")
            .and_then(|a| a.quantity.parse().ok())
            .unwrap_or(0)
    };
    let fault_bf = wallet_raw
        .iter()
        .find(|u| u.amount.iter().any(|a| a.unit == fault_unit))
        .ok_or_else(|| {
            format!(
                "no FaultProof UTxO for this (pool, evidence) at the wallet — publish it first \
                 (token {})",
                hex::encode(token_name)
            )
        })?;
    let fault_utxo = FaultProofUtxo {
        tx_hash: fault_bf.tx_hash.clone(),
        output_index: fault_bf.output_index,
        lovelace: lovelace_of(fault_bf),
    };

    // Locate the accused pool's registry node — the read-only reference input.
    let reg_unit = format!("{}{}", registry.hash_hex(), hex::encode(accused_pool_id));
    let reg_node = registry_raw
        .iter()
        .find(|u| u.amount.iter().any(|a| a.unit == reg_unit))
        .ok_or_else(|| {
            format!(
                "accused pool {} is not in the on-chain registry — cannot reference it",
                hex::encode(accused_pool_id)
            )
        })?;

    // Validity interval: [current_slot, current_slot + W), W*1s within both the
    // ban validator's max_validity_window_ms and the epoch horizon. Plutus
    // exposes finite upper bounds as exclusive, so spo_bans resolves the
    // POSIX-ms upper bound as `slot_to_posix(invalid_hereafter) - 1`.
    let max_window_slots = (params.max_validity_window_ms / 1000).max(1) as u64;
    let avail = window.epoch_end_slot.saturating_sub(window.current_slot);
    let w = max_window_slots.min(avail);
    let invalid_before = window.current_slot;
    let invalid_hereafter = window.current_slot + w;
    let start_time_ms = window.block_time_ms + (w as i64) * 1000 - 1;

    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let req = ApplyBanRequest {
        spo_bans_script: &spo_bans,
        fault_verifier_script: &fault,
        fault_verifier_ref: None,
        ban_params: &params,
        accused_pool_id,
        evidence_hash,
        ban_utxos: &ban_raw,
        fault_utxo: &fault_utxo,
        registration_ref: (reg_node.tx_hash.clone(), reg_node.output_index),
        spo_bans_ref: (hex::encode(sb_tx), sb_ix),
        mainnet,
        start_time_ms,
        invalid_before,
        invalid_hereafter,
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        cost_models: Some(cost_models),
    };
    let built = build_apply_ban_tx(&req).map_err(|e| format!("build apply_ban tx: {e}"))?;

    println!(
        "action:            {}",
        if built.first_ban {
            "first ban (mint + insert)"
        } else {
            "reban (in-place update)"
        }
    );
    println!(
        "ban node:          {}.{} (counter {}, until {})",
        spo_bans.hash_hex(),
        hex::encode(&built.ban_node_asset_name),
        built.ban_node.ban_counter,
        built.ban_node.ban_until_time
    );
    println!(
        "burned FaultProof: {}.{}",
        fault.hash_hex(),
        hex::encode(built.burned_fault_token)
    );
    println!(
        "validity:          slots [{invalid_before}, {invalid_hereafter}), start_time_ms {start_time_ms}"
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Build (and with `--submit`, broadcast) the `fault_verifier.PublishProof` tx:
/// mint the FaultProof token `blake2b_256(accused_pool_id || evidence_hash)` and
/// park it at the wallet. A later `apply-ban` consumes + burns it.
fn run_fault_proof_mint(cfg: &HeimdallConfig, args: &FaultProofMintArgs) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{fault_verifier_script, spos_registry_script};
    use heimdall::cardano::fault_proof::{
        EquivocationEvidence as OnchainEquivocationEvidence, FaultProofEvidence,
        FaultProofMintRequest, Round1InvalidPayloadEvidence, Round2InvalidPayloadEvidence,
        build_fault_proof_mint_tx,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = heimdall::cardano::blueprint::load_blueprint(args.blueprint.as_deref())?;
    let registry_bootstrap = resolve_one_shot(cfg, args.registry_bootstrap.as_deref())?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&registry_bootstrap)?;
    let (treasury_bootstrap, config_policy_id) =
        heimdall::cardano::roster::treasury_derivation_inputs(
            &cfg.cardano.with_one_shot(&registry_bootstrap),
        )?;
    let (tsy_tx_id, tsy_index) = parse_cardano_outref(&treasury_bootstrap)?;
    // Rev 5.5: Config → treasury → registry ([PRE-3], [PRE-4]).
    let registry = heimdall::cardano::blueprint::registry_policy_from_bootstraps(
        &blueprint_json,
        (&reg_tx_id, u64::from(reg_index)),
        (&tsy_tx_id, u64::from(tsy_index)),
        &config_policy_id,
    )
    .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let json = std::fs::read_to_string(&args.evidence_file)
        .map_err(|e| format!("read evidence file {}: {e}", args.evidence_file))?;
    let ev: EvidenceFile = serde_json::from_str(&json)
        .map_err(|e| format!("parse evidence file {}: {e}", args.evidence_file))?;
    let derived = ev.derive()?;
    println!("derived from evidence ({}):", ev.kind);
    println!("  evidence_hash:   {}", hex::encode(derived.evidence_hash));
    println!("  namespace_hash:  {}", hex::encode(derived.namespace_hash));
    let fault_vscript = fault_verifier_script(&blueprint_json, derived.kind, &registry.hash)
        .map_err(|e| format!("parameterize fault_verifier: {e}"))?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let registry_addr = registry.enterprise_address(network_of(&wallet_addr));
    let registry_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &registry_addr))
        .map_err(|e| format!("registry UTxO query: {e}"))?;
    let reg_unit = format!(
        "{}{}",
        registry.hash_hex(),
        hex::encode(derived.accused_pool_id)
    );
    let node = registry_raw
        .iter()
        .find(|u| u.amount.iter().any(|a| a.unit == reg_unit))
        .ok_or_else(|| {
            format!(
                "accused pool {} is not in the on-chain registry — cannot reference it",
                hex::encode(derived.accused_pool_id)
            )
        })?;
    let registration_ref = (node.tx_hash.clone(), node.output_index);

    let public_inputs = vec![
        derived.evidence_hash.to_vec(),
        derived.accused_pool_id.to_vec(),
    ];
    let evidence = match derived.kind {
        heimdall::cardano::blueprint::FaultVerifierKind::Round1 => {
            let Some(round1) = derived.round1_invalid.as_ref() else {
                return Err("round1 fault evidence missing".into());
            };
            if round1.halo2_proof.is_empty() {
                return Err("round1 invalid-payload evidence requires `halo2_proof`".into());
            }
            FaultProofEvidence::Round1InvalidPayload(Round1InvalidPayloadEvidence {
                accused_pool_id: &derived.accused_pool_id,
                canonical_round1_bytes: &round1.canonical_round1_bytes,
                payload_signature: &round1.payload_signature,
                halo2_proof: &round1.halo2_proof,
                halo2_public_inputs: &public_inputs,
            })
        }
        heimdall::cardano::blueprint::FaultVerifierKind::Round2 => {
            let Some(round2) = derived.round2_invalid.as_ref() else {
                return Err("round2 fault evidence missing".into());
            };
            if round2.halo2_proof.is_empty() {
                return Err("round2 invalid-payload evidence requires `halo2_proof`".into());
            }
            FaultProofEvidence::Round2InvalidPayload(Round2InvalidPayloadEvidence {
                accused_pool_id: &derived.accused_pool_id,
                canonical_round1_bytes: &round2.canonical_round1_bytes,
                round1_signature: &round2.round1_signature,
                canonical_round2_bytes: &round2.canonical_round2_bytes,
                round2_signature: &round2.round2_signature,
                round2_entry_index: round2.round2_entry_index,
                pad: &round2.pad,
                opened_share: &round2.opened_share,
                halo2_proof: &round2.halo2_proof,
                halo2_public_inputs: &public_inputs,
            })
        }
        heimdall::cardano::blueprint::FaultVerifierKind::Equivocation => {
            let Some(eq) = derived.equivocation.as_ref() else {
                return Err("equivocation evidence missing".into());
            };
            FaultProofEvidence::Equivocation(OnchainEquivocationEvidence {
                accused_pool_id: &derived.accused_pool_id,
                payload_a: &eq.payload_a,
                signature_a: &eq.signature_a,
                payload_b: &eq.payload_b,
                signature_b: &eq.signature_b,
                evidence_hash: &derived.evidence_hash,
            })
        }
    };

    let req = FaultProofMintRequest {
        fault_verifier_script: &fault_vscript,
        fault_verifier_ref_script: None,
        evidence,
        registration_ref: (&registration_ref.0, registration_ref.1),
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        cost_models: Some(cost_models),
    };
    let built =
        build_fault_proof_mint_tx(&req).map_err(|e| format!("build fault-proof mint tx: {e}"))?;

    println!("fault policy:      {}", built.policy_id_hex);
    println!(
        "FaultProof token:  {}.{}",
        built.policy_id_hex,
        hex::encode(built.token_name)
    );
    println!(
        "parked at:         {} ({} lovelace) — spend with `apply-ban`",
        built.proof_address, built.lovelace
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Read + verify the on-chain SPO registry and print the DKG roster (WI-010).
fn run_show_roster(
    cfg: &HeimdallConfig,
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::roster::RegistryRosterSource;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // Resolve the registry the way the daemon does — published identity (#9-#10)
    // first, local keys only otherwise. This report is what the operator guide
    // sends people to in order to check their own registration, so it has to work
    // on a bridge where the guide has already told them to delete those keys.
    // The CLI flags stay as overrides, layered onto `[cardano]` before resolving
    // so both halves of the report describe ONE deployment.
    let bridge_config = config_view(&rt, cfg)?;
    let cardano = heimdall::config::CardanoConfig {
        registry_blueprint: blueprint.or_else(|| cfg.cardano.registry_blueprint.clone()),
        federation_one_shot: registry_bootstrap.or_else(|| cfg.cardano.federation_one_shot.clone()),
        ..cfg.cardano.clone()
    };
    let source = RegistryRosterSource::resolve(&cardano, bridge_config.as_ref().map(|v| &v.params))
        .map_err(|e| e.to_string())?
        .ok_or(
            "no registry to show: this bridge's Config publishes no registry identity \
             (#9-#10), and cardano.registry_blueprint / registry_bootstrap / \
             treasury_info_asset_name are unset. Pass --blueprint, --registry-bootstrap and \
             --treasury-nft-name, or point cardano.config_address at a bridge that \
             publishes them",
        )?;
    println!("registry policy:   {}", source.registry_policy_hex);
    println!("registry address:  {}", source.registry_address);
    println!("treasury_info:     {}", source.treasury_info_address);
    println!(
        "registry source:   {}",
        if bridge_config.is_some() {
            "bridge Config #9-#10"
        } else {
            "LOCAL heimdall.toml registry keys"
        }
    );

    let epoch = rt.block_on(bf_http::fetch_current_epoch(&base_url, pid))?;
    let snapshot = rt
        .block_on(source.fetch_snapshot(&base_url, pid))
        .map_err(|e| e.to_string())?;

    println!("current epoch:     {epoch}");
    println!(
        "identity root:     {} (verified against treasury_info)",
        hex::encode(snapshot.identity_root)
    );
    println!("registered SPOs:   {}", snapshot.spos.len());
    for spo in &snapshot.spos {
        let pool: [u8; 28] = spo
            .pool_id
            .as_slice()
            .try_into()
            .map_err(|_| format!("pool_id not 28 bytes: {}", hex::encode(&spo.pool_id)))?;
        println!("  pool {} ({})", hex::encode(pool), pool_id_bech32(&pool));
        println!("    bifrost_id_pk: {}", hex::encode(&spo.bifrost_id_pk));
        println!(
            "    bifrost_url:   {}",
            String::from_utf8_lossy(&spo.bifrost_url)
        );
        println!("    element UTxO:  {}:{}", spo.tx_hash, spo.output_index);
    }

    // ── ban list (WI-011) ── list entries AND capture the active-ban set the
    // Round-0 derivation below subtracts. Resolved through the SAME call the
    // daemon uses, over the same CLI-overridden `[cardano]` the registry half
    // resolved from — so a --blueprint/--registry-bootstrap override cannot make
    // the two sections describe different deployments, and this report cannot
    // disagree with what the running node filters.
    use heimdall::cardano::ban_list::{BanListError, BanListSource};
    let mut active_bans: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    match BanListSource::resolve(&cardano, bridge_config.as_ref().map(|v| &v.params)) {
        Ok(None) => println!(
            "ban list:          (not configured — this bridge's Config publishes no ban \
             policy, and cardano.ban_bootstrap is unset)"
        ),
        // A report, so a bad ban configuration is printed rather than aborting
        // the registry half above it — which is the half an operator ran this for.
        Err(e) => println!("ban list:          UNRESOLVABLE — {e}"),
        Ok(Some(source)) => {
            println!("ban policy source: {}", source.origin);
            println!("ban policy:        {}", source.ban_policy_hex);
            println!("ban address:       {}", source.ban_address);
            // Ban activity is evaluated at the epoch boundary (chain-derived),
            // the same deterministic time the live roster path uses.
            let epoch_start_ms =
                rt.block_on(bf_http::fetch_epoch_start_ms(&base_url, pid, epoch))?;
            let read = rt.block_on(source.fetch_ban_list(&base_url, pid));
            // Report the entries from the raw read, but take the ACTIVE SET
            // through the same interpretation the daemon uses: an
            // unbootstrapped list is "no bans" only where that reading is
            // legitimate. Otherwise the eligible roster printed below would be
            // the unfiltered one, presented as if it were the real one.
            match &read {
                Ok(bans) => {
                    println!(
                        "ban entries:       {} ({} active at epoch {epoch} boundary)",
                        bans.len(),
                        bans.active_bans(epoch_start_ms).len()
                    );
                    for (pool_id, data) in bans.iter() {
                        let state = if data.active_at(epoch_start_ms) {
                            "ACTIVE"
                        } else {
                            "expired"
                        };
                        println!(
                            "  pool {}  counter={} until_time={} permanent={} [{state}]",
                            hex::encode(pool_id),
                            data.ban_counter,
                            data.ban_until_time,
                            data.permanent
                        );
                    }
                }
                // Expected on a bridge predating the ban infrastructure, and
                // absorbed just below into "no bans". Where it is NOT expected
                // `active_bans_from` re-raises it and this report stops.
                Err(e @ BanListError::NotBootstrapped) => println!("ban list:          {e}"),
                Err(_) => {}
            }
            active_bans = source
                .active_bans_from(read, epoch_start_ms)
                .map_err(|e| format!("ban list: {e}"))?;
        }
    }

    // ── DKG Round 0 (WI-012): eligible roster (registry − active bans −
    // unusable/duplicate URLs) + stake-weighted FROST threshold ──
    use heimdall::cardano::dkg_roster::{
        derive_dkg_context, eligible_pool_ids, fetch_eligible_stakes,
    };
    let eligible = eligible_pool_ids(&snapshot, &active_bans);
    let stake_source =
        heimdall::cardano::stake::StakeSource::from_config(cfg.cardano.stake_source.as_deref())
            .unwrap_or_else(|e| panic!("cardano.stake_source: {e}"));
    let exclude_unstaked = cfg.cardano.demo_exclude_unstaked;
    match rt.block_on(fetch_eligible_stakes(
        &base_url,
        pid,
        &eligible,
        stake_source,
        epoch,
        exclude_unstaked,
    )) {
        Ok(stakes) => {
            // DEMO-ONLY: drop pools whose stake was skipped (mirrors the demo
            // path) so the threshold below reflects only resolvable-stake pools.
            let mut bans = active_bans.clone();
            if exclude_unstaked {
                for pid2 in &eligible {
                    if !stakes.contains_key(pid2) {
                        bans.insert(pid2.clone());
                    }
                }
            }
            match derive_dkg_context(&snapshot, &bans, &stakes, epoch, 0) {
                Ok(ctx) => {
                    println!(
                        "DKG roster (epoch {epoch}; threshold {} of {}, total stake {}):",
                        ctx.threshold,
                        ctx.participants.len(),
                        ctx.total_stake
                    );
                    for p in &ctx.participants {
                        println!(
                            "  #{:<3} pk {}  stake={} {}",
                            p.index,
                            hex::encode(&p.bifrost_id_pk),
                            p.active_stake,
                            p.bifrost_url
                        );
                    }
                    for ex in &ctx.excluded {
                        // `demo_exclude_unstaked` excludes no-stake pools by adding them to the
                        // ban set, so `ex.reason` would read "banned" — relabel those accurately
                        // (they were NOT banned/slashed, just have no resolvable Cardano stake).
                        let reason = if exclude_unstaked && !active_bans.contains(&ex.pool_id) {
                            "no active stake (excluded via demo_exclude_unstaked)".to_string()
                        } else {
                            ex.reason.to_string()
                        };
                        println!("  excluded pool {}: {}", hex::encode(&ex.pool_id), reason);
                    }
                }
                Err(e) => println!("DKG roster:        cannot derive ({e})"),
            }
        }
        // A stake query failure is fatal for a real ceremony (the threshold
        // can't be computed), but tolerated in this read-only diagnostic so
        // the registry + ban sections above still print — synthetic preprod
        // pools aren't registered Cardano SPOs, so /pools/{id} returns 404.
        Err(e) => println!(
            "DKG roster:        stake unavailable ({e}) — {} eligible pool(s) before threshold",
            eligible.len()
        ),
    }
    Ok(())
}

/// Background auto-mover loop (WI-028): periodically chain-source the treasury and
/// post the next Treasury Movement when there is work AND the treasury is free.
/// Reuses `run_sweep_pegins` in `auto_mode` (busy / idle → skip, not error) so a
/// transient failure never kills the loop; pacing is implicit — a just-posted
/// movement shows up as in-flight on the next tick and is skipped until binocular
/// `confirm-tmtx` advances the tip. No leader election (WI-027): run ONE instance.
#[allow(clippy::too_many_arguments)]
fn run_mover(
    cfg: &HeimdallConfig,
    cardano_socket: &str,
    cardano_magic: u64,
    pegin_script_address: &str,
    pegin_policy_id: &str,
    pegout_script_address: &str,
    bridged_token_unit: &str,
    interval_secs: u64,
    once: bool,
    broadcast: bool,
    exclude_pegin: &[String],
) -> Result<(), String> {
    use std::time::Duration;

    // N19: the mover follows the protocol's BATCH GRID, not a wall-clock interval.
    // B_i = epoch_start + i * tm_batch_interval, and at each opportunity every SPO
    // evaluates the same gate against the same frozen set — which is what makes two
    // independently-run movers agree on the TM bytes. A wall-clock tick cannot: two
    // nodes ticking 30 s apart scan different chain states.
    //
    // `--interval-secs` survives in two roles: the cadence when there is no grid to
    // follow (no Config schedule, or no Config UTxO at all), and the ceiling on how
    // long this loop sleeps before re-checking the chain.
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let poll_ceiling = Duration::from_secs(interval_secs.clamp(1, 300));

    // The batch this process has already built for. The grid says an opportunity is
    // open for the whole interval, so without this the mover would rebuild the same
    // batch every poll — burning a fee per poll on a treasury self-move.
    let mut built_batch: Option<u64> = None;
    let mut tick: u64 = 0;
    loop {
        // Where are we on the grid? A quiet probe: the sweep itself re-reads and
        // reports the snapshot it actually builds against.
        let probe = match batch_params(&rt, cfg, false) {
            Ok(p) => Some(p),
            Err(e) => {
                warn!("[mover] grid probe failed ({e}) — retrying after the poll interval");
                None
            }
        };

        use heimdall::epoch::batch::BatchWindow;
        match probe.as_ref().map_or(BatchWindow::NoGrid, |p| p.batch) {
            // An opportunity is open and this process has not built for it yet.
            BatchWindow::Open(b) if built_batch != Some(b.index) => {
                built_batch = Some(b.index);
                tick += 1;
                info!(
                    "═══ batch B_{} @ slot {} (cutoff {}), tick #{tick}, broadcast={broadcast} ═══",
                    b.index, b.slot, b.cutoff_slot
                );
            }
            // Already built for this opportunity: the grid says wait for the next one.
            BatchWindow::Open(b) => {
                if once {
                    info!("[mover] batch B_{} already built — nothing to do", b.index);
                    return Ok(());
                }
                std::thread::sleep(poll_ceiling);
                continue;
            }
            // A grid exists but no opportunity is open — before B_1, or past
            // final_tm_cutoff. The spec is explicit that the opportunity passes UNUSED:
            // building here would post a movement outside the schedule every SPO agreed
            // on, which no co-signer would reproduce.
            BatchWindow::Closed { .. } => {
                if once {
                    info!("[mover] no batch opportunity is open — nothing to do");
                    return Ok(());
                }
                std::thread::sleep(poll_ceiling);
                continue;
            }
            // No grid (or the probe failed): fall back to the interval cadence.
            BatchWindow::NoGrid => {
                tick += 1;
                info!(
                    "═══ auto-mover tick #{tick} (no batch grid; interval {interval_secs}s, \
                     broadcast={broadcast}) ═══"
                );
            }
        }
        let result = run_sweep_pegins(
            cfg,
            cardano_socket,
            cardano_magic,
            pegin_script_address,
            pegin_policy_id,
            None, // chain-source the treasury (WI-028)
            None,
            pegout_script_address,
            bridged_token_unit,
            broadcast,
            None, // no existing-tm override
            exclude_pegin,
            true, // auto_mode → busy/idle skips instead of erroring
        );
        // In --once mode (documented "for testing") propagate the tick result so the
        // process exit code reflects success/failure. In the continuous loop a tick
        // error is logged and the loop keeps going.
        if once {
            return result;
        }
        if let Err(e) = result {
            error!("[mover] tick #{tick} error (continuing): {e}");
            // A failed build must not consume its opportunity: clear the marker so the
            // next poll retries the same batch rather than waiting for the next one.
            built_batch = None;
        }
        std::thread::sleep(poll_ceiling);
    }
}

/// `reconstruct-cpo-trie`: rebuild the completed-peg-outs trie from Cardano
/// history, then persist it to `protocol.state_dir`.
///
/// The history read runs on EITHER backend — Kupo when `cardano.kupo_url` is set
/// (the production recommendation), else the Blockfrost-compatible API already
/// configured for steady-state operation. Both run the same algorithm and the same
/// checks; see `cardano::cpo_history`.
///
/// Writes only on success, and only the whole trie: a partial rebuild is worse
/// than no rebuild, because the node would sign roots derived from a set it
/// believes is complete. Every TM's running root is checked against the root that
/// TM attested, so an unexplainable movement aborts the run and names itself.
fn run_reconstruct_cpo_trie(cfg: &HeimdallConfig, dry_run: bool) -> Result<(), String> {
    use heimdall::cardano::cpo_history::{BlockfrostHistory, CpoHistorySource, KupoHistory};
    use heimdall::cardano::cpo_trie::{ReconstructConfig, reconstruct};

    // Every identifier this walk needs is Config #2/#4/#5/#7 (WI-070) — one
    // authenticated read instead of four keys, which matters here more than
    // anywhere: a wrong TM address or peg-out address yields a SHORT trie, and a
    // short trie is indistinguishable from a bridge with less history.
    let bridge = resolve_bridge_contracts(cfg)?;
    let tm_address = bridge.tm_address.as_str();
    let pegout_address = bridge.pegout_script_address.as_str();
    let unit = bridge.bridged_token_unit.to_ascii_lowercase();
    let (fbtc_policy_id, fbtc_asset_name_hex) = unit.split_at(56);

    // The cross-check is not optional and can no longer be turned off. Every
    // per-movement assertion is relative to the previous movement, so a replay
    // that stops one TM short of the tip passes every one of them and still
    // yields a short trie. Only the on-chain singleton catches that.
    let cpo_policy_id = bridge.bridge_state_policy_id.to_ascii_lowercase();

    // Backend selection: Kupo when configured, else the Blockfrost-compatible API.
    //
    // Kupo is what a production SPO should run — it answers a whole address
    // history in one request, and it is self-hosted, which the spec requires of
    // every consensus-relevant read. The Blockfrost path is for test
    // environments, demos, and non-SPO tooling: it reconstructs the same trie
    // with the same checks, but it walks the address's transaction history and
    // costs roughly one request per transaction.
    let source: Box<dyn CpoHistorySource> = match cfg.cardano.kupo_url.as_deref() {
        Some(url) => Box::new(KupoHistory::new(url)),
        None => {
            let project_id = cfg.cardano.blockfrost_project_id.as_deref().ok_or(
                "set cardano.kupo_url (recommended for SPOs) or cardano.blockfrost_project_id \
                 — reconstruction reads the datums of SPENT outputs, which needs either a Kupo \
                 index or a Blockfrost-compatible transaction-history API",
            )?;
            Box::new(BlockfrostHistory::new(
                project_id,
                cfg.cardano.blockfrost_url.as_deref(),
            ))
        }
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let recon = ReconstructConfig {
        tm_address: tm_address.to_string(),
        pegout_address: pegout_address.to_string(),
        fbtc_policy_id: fbtc_policy_id.to_string(),
        fbtc_asset_name_hex: fbtc_asset_name_hex.to_string(),
        cpo_policy_id,
    };
    // `reconstruct` itself logs the active backend and its endpoint before its
    // first read, so every caller reports it identically and this command does not
    // repeat the line.
    println!("reconstructing the completed-peg-outs trie");
    let trie = rt
        .block_on(reconstruct(source.as_ref(), &recon))
        .map_err(|e| e.to_string())?;

    println!(
        "  reconstructed root : {} ({} entr(y|ies))",
        hex::encode(trie.root()),
        trie.len()
    );
    for (por_id, value) in trie.entries() {
        println!("    {} -> {}", hex::encode(por_id), hex::encode(value));
    }

    if dry_run {
        println!("  --dry-run: not written");
        return Ok(());
    }
    let dir = cfg
        .protocol
        .state_dir
        .as_deref()
        .ok_or("set protocol.state_dir to persist the trie (or pass --dry-run)")?;
    let dir = std::path::Path::new(dir);
    trie.save(dir).map_err(|e| e.to_string())?;
    println!(
        "  written            : {}",
        heimdall::cardano::cpo_trie::CpoTrie::state_path(dir).display()
    );
    Ok(())
}

/// `reconstruct-spi-trie`: rebuild the swept peg-ins trie from Cardano history,
/// then persist it to `protocol.state_dir` — the recovery `BuildTm`'s spi_root
/// cross-check points an operator at.
///
/// Same backend selection and the same harvest/walk as `reconstruct-cpo-trie`;
/// the entries are each confirmed TM's inputs per [SPI-1]/[SPI-3], and the
/// finished root must equal the singleton's attested `spi_root`.
fn run_reconstruct_spi_trie(cfg: &HeimdallConfig, dry_run: bool) -> Result<(), String> {
    use heimdall::cardano::cpo_history::{BlockfrostHistory, CpoHistorySource, KupoHistory};
    use heimdall::cardano::cpo_trie::reconstruct_spi;

    // Config #5 and #4 (WI-070): the TM validator address the walk reads, and the
    // singleton that supplies its head and the attested spi_root.
    let bridge = resolve_bridge_contracts(cfg)?;
    let tm_address = bridge.tm_address.as_str();
    let policy = bridge.bridge_state_policy_id.to_ascii_lowercase();

    let source: Box<dyn CpoHistorySource> = match cfg.cardano.kupo_url.as_deref() {
        Some(url) => Box::new(KupoHistory::new(url)),
        None => {
            let project_id = cfg.cardano.blockfrost_project_id.as_deref().ok_or(
                "set cardano.kupo_url (recommended for SPOs) or cardano.blockfrost_project_id \
                 — reconstruction reads the datums of SPENT outputs, which needs either a Kupo \
                 index or a Blockfrost-compatible transaction-history API",
            )?;
            Box::new(BlockfrostHistory::new(
                project_id,
                cfg.cardano.blockfrost_url.as_deref(),
            ))
        }
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    println!("reconstructing the swept peg-ins trie");
    let trie = rt
        .block_on(reconstruct_spi(source.as_ref(), tm_address, &policy))
        .map_err(|e| e.to_string())?;

    println!(
        "  reconstructed root : {} ({} entr(y|ies))",
        hex::encode(trie.root()),
        trie.len()
    );
    for (peg_in, value) in trie.entries() {
        println!("    {} -> {}", hex::encode(peg_in), hex::encode(value));
    }

    if dry_run {
        println!("  --dry-run: not written");
        return Ok(());
    }
    let dir = cfg
        .protocol
        .state_dir
        .as_deref()
        .ok_or("set protocol.state_dir to persist the trie (or pass --dry-run)")?;
    let dir = std::path::Path::new(dir);
    trie.save(dir).map_err(|e| e.to_string())?;
    println!(
        "  written            : {}",
        heimdall::cardano::spi_trie::SpiTrie::state_path(dir).display()
    );
    Ok(())
}

/// Read-only `show-config-params`: print the Config UTxO's operational parameters
/// as of the current tip — the snapshot a TM batch built now would use (WI-040).
///
/// Operationally this is the "do we all agree?" check: run it on every SPO and the
/// output must be identical, because these values decide TM bytes. A node
/// reporting a LOCAL source here cannot co-sign with one reporting the Config.
fn run_show_config_params(cfg: &HeimdallConfig) -> Result<(), String> {
    use heimdall::cardano::config_params::{ParamSource, fetch_param_snapshot, resolve_tm_params};

    let loc = config_locator(cfg).ok_or(
        "set cardano.config_address, cardano.config_nft_policy_id and \
         cardano.blockfrost_project_id to read the bridge Config UTxO",
    )?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let snapshot = rt.block_on(fetch_param_snapshot(
        &loc.base_url,
        &loc.project_id,
        &loc.address,
        &loc.nft_unit,
    ))?;

    println!("config UTxO        : {}", snapshot.config.utxo);
    println!(
        "snapshot slot      : {} (tip time {} ms)",
        snapshot.slot, snapshot.time_ms
    );
    println!(
        "datum fields       : {}",
        snapshot.config.params.field_count
    );
    println!(
        "#3  bridge_state   : {}",
        hex::encode(snapshot.config.params.bridge_state_policy)
    );
    println!(
        "#4  tm_script_hash : {}",
        hex::encode(snapshot.config.params.tm_script_hash)
    );
    {
        let t = &snapshot.config.params.tunables;
        println!("#7  params:");
        println!("      fee_rate       : {} sat/vB", t.fee_rate_sat_per_vb);
        println!(
            "      per_pegout_fee : {} sat (floor)",
            t.per_pegout_fee_floor
        );
        println!("      min_peg_out    : {} sat", t.min_peg_out_fbtc);
        let s = &t.schedule;
        println!("      schedule (slots, E-relative):");
        println!(
            "        dkg_r1_deadline={} dkg_r2_deadline={} update_y_deadline={}",
            s.dkg_r1_deadline, s.dkg_r2_deadline, s.update_y_deadline
        );
        println!(
            "        tm_batch_interval={} sign_r1_window={} sign_r2_window={}",
            s.tm_batch_interval, s.sign_r1_window, s.sign_r2_window
        );
        println!(
            "        leader_slot_t={} tm_recovery_window={} final_tm_cutoff={} \
             stability_window={}",
            s.leader_slot_t, s.tm_recovery_window, s.final_tm_cutoff, s.stability_window
        );
    }
    {
        let b = &snapshot.config.params.bans;
        let mainnet = cfg.cardano.is_mainnet()?;
        let source = heimdall::cardano::ban_list::BanListSource::from_policy_id(
            &b.spo_bans_policy_id,
            mainnet,
        );
        let t = &snapshot.config.params.tunables;
        println!("#8  spo_bans policy: {}", source.ban_policy_hex);
        println!("      ban address  : {}", source.ban_address);
        println!(
            "    params[4] base_ban_duration_ms      : {}",
            t.base_ban_duration_ms
        );
        println!(
            "    params[5] max_faults_before_permanent: {}",
            t.max_faults_before_permanent
        );
        println!(
            "    params[6] max_validity_window_ms     : {}",
            t.max_validity_window_ms
        );
        println!(
            "      (the roster is filtered against this address; no ban keys are needed \
             in [cardano])"
        );
    }
    {
        let r = &snapshot.config.params.registry;
        let source = heimdall::cardano::roster::RegistryRosterSource::from_policy_ids(
            &r.spos_registry_policy_id,
            &r.treasury_info_policy_id,
            heimdall::cardano::config_params::TREASURY_INFO_ASSET_NAME,
            cfg.cardano.is_mainnet()?,
        );
        println!("#9  registry policy: {}", source.registry_policy_hex);
        println!("      registry addr: {}", source.registry_address);
        println!("#10 treasury_info  : {}", source.treasury_info_policy_hex);
        println!("      state addr   : {}", source.treasury_info_address);
        println!(
            "    treasury_info NFT name: {} ({}) — the [CFG-4] constant, not a Config field",
            source.treasury_info_asset_name_hex,
            String::from_utf8_lossy(heimdall::cardano::config_params::TREASURY_INFO_ASSET_NAME)
        );
        println!(
            "      (the roster is read from these; no registry keys are needed in \
             [cardano]. The Update-Y handoff additionally needs a blueprint to compile \
             treasury_info, checked against #10)"
        );
    }
    {
        let p = &snapshot.config.params;
        println!(
            "#11 y_federation : {} (params[7] federation_csv_blocks: {})",
            hex::encode(p.y_federation),
            p.tunables.federation_csv_blocks
        );
    }

    let (params, source) = resolve_tm_params(Some(&snapshot), cfg.bitcoin.fee_rate_sat_per_vb);
    println!("\nTM parameters in force: {source}");
    println!(
        "  fee_rate={} sat/vB, per_pegout_fee floor={} sat, min_peg_out_fbtc={} sat",
        params.fee_rate_sat_per_vb,
        params.per_pegout_fee_floor.to_sat(),
        params.min_peg_out_fbtc.to_sat(),
    );
    if matches!(source, ParamSource::LocalOverride(_)) {
        println!(
            "  local bitcoin.fee_rate_sat_per_vb = {} — a DEV override; co-signers reading a \
             different value build different TM bytes",
            cfg.bitcoin.fee_rate_sat_per_vb
        );
    } else {
        println!(
            "  (local bitcoin.fee_rate_sat_per_vb = {} is IGNORED — dev override only)",
            cfg.bitcoin.fee_rate_sat_per_vb
        );
    }
    Ok(())
}

/// Read-only `show-treasury`: chain-source the current treasury from Cardano and
/// print it. The safe way to test WI-028 against a live network — posts nothing.
fn run_show_treasury(cfg: &HeimdallConfig) -> Result<(), String> {
    use bitcoin::ScriptBuf;
    use bitcoin::key::Secp256k1;
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::cardano::blockfrost_chain::scan_tm_utxos;
    use heimdall::frost::dkg::run_demo_dkg;

    let bridge = resolve_bridge_contracts(cfg)?;
    let address = bridge.tm_address.as_str();
    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id not set")?;
    let base_url = heimdall::cardano::bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let asset_unit = bridge.tm_asset_unit();

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let scan = rt.block_on(scan_tm_utxos(
        &base_url,
        pid,
        address,
        &asset_unit,
        cfg.bitcoin.inflight_deadline_secs,
    ))?;

    println!("TM validator address: {address}");
    println!("marker unit:          {asset_unit}");
    println!("in-flight spends:     {}", scan.in_flight_spends.len());
    println!("parse failures:       {}", scan.parse_failures);
    println!("opaque unconfirmed:   {}", scan.opaque_unconfirmed);
    if scan.parse_failures > 0 {
        println!(
            "  ⚠ {} marker-token TM datum(s) failed to parse — chain-source would REFUSE \
             (mis-root risk)",
            scan.parse_failures
        );
    }

    // Our expected treasury keys: demo Y_51 (deterministic DKG) + the federation
    // identity. Read-only: this reports what the treasury SHOULD look like, so it
    // must use the same source the mover signs against — the treasury_info datum,
    // not this node's local seed (WI-069).
    let secp = Secp256k1::new();
    let federation = rt.block_on(resolve_federation(cfg))?;
    let y_fed = federation.y_fed;
    let dkg = run_demo_dkg(
        b"heimdall-demo-seed-v1-0123456789",
        cfg.demo.min_signers,
        cfg.demo.max_signers,
    );
    let y_51 = group_xonly(dkg.public_key_package.verifying_key())?.xonly;
    let csv = federation.csv_blocks;
    let expected_spk =
        ScriptBuf::new_p2tr_tweaked(treasury_spend_info(&secp, y_51, y_fed, csv).output_key());
    println!("our Y_51:             {}", hex::encode(y_51.serialize()));
    println!(
        "expected treasury spk: {}",
        hex::encode(expected_spk.as_bytes())
    );

    // The current treasury is the bridge-state singleton's head (rev 5.4: there
    // is no Confirmed chain to follow).
    let current = match singleton_chain_tip(&rt, cfg, Some(&scan)) {
        Ok(tip) => {
            println!(
                "\nCURRENT TREASURY (singleton head): {} — {} sat",
                tip.outpoint,
                tip.value.to_sat()
            );
            if tip.in_flight {
                println!(
                    "  a movement is already in flight against it (or an unreadable record might \
                     be) — NOT free to move (wait for confirm-tmtx)"
                );
            } else {
                println!(
                    "  free to move — the auto-mover / sweep-pegins would build the next TM off this"
                );
            }
            Some((tip.outpoint, tip.value.to_sat(), tip.in_flight))
        }
        Err(e) => {
            println!("\nno singleton head: {e}");
            None
        }
    };

    // Diagnose "why can't the mover advance": list the in-flight (Unconfirmed)
    // movements and flag the one(s) that spend the current tip — those block the
    // mover, and if any can never confirm (a spent/missing BTC input) it deadlocks.
    let tip_op = current.map(|(op, _, _)| op);
    if !scan.unconfirmed.is_empty() || scan.opaque_unconfirmed > 0 {
        println!(
            "\nin-flight (Unconfirmed) movements: {}",
            scan.unconfirmed.len()
        );
        for u in &scan.unconfirmed {
            // [CTM-18]: only a TM whose input 0 spends the CURRENT head can ever
            // confirm. Anything else is a dead post awaiting its creator's GC.
            let spends_tip = tip_op.is_some_and(|t| u.inputs.first() == Some(&t));
            let dead = tip_op.is_some() && !spends_tip;
            let tag = if spends_tip {
                "   ← SPENDS THE CURRENT HEAD (blocks the mover)"
            } else if dead {
                "   ← DEAD (input 0 is not the current head; can never confirm — [CTM-18])"
            } else {
                ""
            };
            println!(
                "  btc {} — {} input(s), {} output(s){}",
                u.btc_txid,
                u.inputs.len(),
                u.outputs.len(),
                tag,
            );
            for inp in &u.inputs {
                let mark = if tip_op == Some(*inp) {
                    "   (= current treasury head)"
                } else {
                    ""
                };
                println!("      in  {}:{}{}", inp.txid, inp.vout, mark);
            }
            for (val, spk) in &u.outputs {
                println!(
                    "      out {} sat  {}",
                    val.to_sat(),
                    hex::encode(spk.as_bytes())
                );
            }
        }
        if scan.opaque_unconfirmed > 0 {
            println!(
                "  + {} unreadable Unconfirmed TM(s) (BTC tx did not deserialize) — treated as \
                 blocking (fail-closed)",
                scan.opaque_unconfirmed
            );
        }
        if let Some(t) = tip_op {
            let viable_blockers = scan
                .unconfirmed
                .iter()
                .filter(|u| u.inputs.first() == Some(&t))
                .count();
            if viable_blockers > 0 || scan.opaque_unconfirmed > 0 {
                println!(
                    "\nBLOCKED: {viable_blockers} live in-flight movement(s) spend the current \
                     head {t} — the mover waits for one to confirm."
                );
            }
        }
    }
    Ok(())
}

/// The chain-sourced treasury tip: outpoint + value, and whether a movement is
/// already in flight against it (an Unconfirmed TM already spends it).
struct ChainTip {
    outpoint: bitcoin::OutPoint,
    value: bitcoin::Amount,
    in_flight: bool,
}

/// The current treasury for the CLI sweep: the bridge-state singleton's head.
///
/// Rev 5.4 removed the Confirmed TM chain — the head outpoint AND its satoshi
/// amount come straight from the singleton's `BridgeState` datum, located
/// through the Config's `bridge_state_policy` (field 3, [PAR-1]). The scan of
/// the TM address is still consulted for the in-flight guard: an `UnconfirmedTm`
/// record whose embedded BTC tx spends the head is a movement in flight, and a
/// record we could not read might be — either way the sweep must wait for
/// confirm-tmtx rather than double-spend the head.
///
/// Takes the scan by ref so the sweep path scans the validator address ONCE and
/// reuses it for both the peg-in guard and this tip selection.
fn singleton_chain_tip(
    rt: &tokio::runtime::Runtime,
    cfg: &HeimdallConfig,
    scan: Option<&heimdall::cardano::blockfrost_chain::TmScan>,
) -> Result<ChainTip, String> {
    use bitcoin::hashes::Hash;
    let loc = config_locator(cfg).ok_or(
        "chain-sourced treasury requires a Config locator (cardano.config_address + \
         config_nft_policy_id) — or pass --treasury-outpoint and --treasury-amount-sat",
    )?;
    let mainnet = cfg.cardano.is_mainnet()?;
    let (_config, singleton) =
        rt.block_on(heimdall::cardano::blockfrost_chain::fetch_config_singleton(
            &loc.base_url,
            &loc.project_id,
            &loc.address,
            &loc.nft_unit,
            mainnet,
        ))?;
    let state = &singleton.state;
    let txid_bytes: [u8; 32] = state.treasury_utxo_id[..32].try_into().unwrap();
    let outpoint = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_byte_array(txid_bytes),
        vout: u32::from_le_bytes(state.treasury_utxo_id[32..].try_into().unwrap()),
    };
    let in_flight = scan.is_some_and(|s| {
        s.in_flight_spends.contains(&outpoint) || s.opaque_unconfirmed > 0 || s.parse_failures > 0
    });
    Ok(ChainTip {
        outpoint,
        value: bitcoin::Amount::from_sat(state.treasury_amount),
        in_flight,
    })
}

/// Scan binocular's on-chain `PegInRequest` UTxOs over N2C, then build, sign and
/// (optionally) broadcast the Treasury Movement sweeping the current treasury +
/// all discovered deposits into a new treasury `output[0]`.
///
/// The deposits are *discovered* from Cardano (not hand-typed): each PIR is
/// validated by `parse_pegin_request`, which reconstructs the peg-in P2TR from
/// `(y_fed, depositor_xonly, refund_timeout)` and requires a matching output —
/// so a successful parse is itself proof the spend-info matches the on-chain
/// scriptPubKey. The treasury input is chain-sourced from the bridge-state
/// singleton's head unless overridden by `--treasury-outpoint`.
#[allow(clippy::too_many_arguments)]
fn run_sweep_pegins(
    cfg: &HeimdallConfig,
    cardano_socket: &str,
    cardano_magic: u64,
    pegin_script_address: &str,
    pegin_policy_id: &str,
    treasury_outpoint: Option<&str>,
    treasury_amount_sat: Option<u64>,
    pegout_script_address: &str,
    bridged_token_unit: &str,
    broadcast: bool,
    existing_tm_hex: Option<&str>,
    exclude_pegin: &[String],
    // Auto-mover mode (WI-028 background loop): a treasury movement already in
    // flight, or nothing pending to sweep, is a no-op skip (returns Ok) rather
    // than an error — so the loop just waits for the next tick. One-shot
    // `sweep-pegins` passes false (busy/idle stays an explicit outcome).
    auto_mode: bool,
) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::bitcoin::tm_builder::{
        PegInInput, PegOutRequest, TreasuryInput, build_tm, sign_tm_frost,
    };
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
    use heimdall::cardano::btc_rpc::broadcast_btc_tx;
    use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
    use heimdall::cardano::pegin_datum::parse_pegin_request;
    use heimdall::cardano::pegin_source::CardanoPegInSource;
    use heimdall::cardano::pegout_datum::fetch_pegout_requests;
    use heimdall::frost::dkg::run_demo_dkg;

    let secp = Secp256k1::new();
    // Peg-in internal key + treasury key-path = the FROST group key Y_51, NOT the fe-seed y_fed
    // (commit 6af7c67 wrongly switched these to y_fed for the demo). Reproduce the deterministic
    // demo DKG to recover Y_51 + every signing share, then FROST-sign the TM. y_fed survives only
    // as the treasury federation fallback leaf.
    // One runtime for the federation read, the peg-in scan and the (optional) broadcast.
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // The federation identity comes from the treasury_info datum, not this node's
    // local seed (WI-069): the mover runs on every SPO, and a per-operator value
    // here builds a treasury address the other signers are not using. Resolved
    // ONCE and up front — a node that cannot establish it must not sign, and must
    // not discover that only after the TM is assembled and signed.
    let federation = rt.block_on(resolve_federation(cfg))?;

    let dkg = run_demo_dkg(
        b"heimdall-demo-seed-v1-0123456789",
        cfg.demo.min_signers,
        cfg.demo.max_signers,
    );
    let y_51 = group_xonly(dkg.public_key_package.verifying_key())?.xonly;
    info!("  FROST group key Y_51: {}", hex::encode(y_51.serialize()));
    // Same tree, resolved from the federation identity because this path derives Y_51 from
    // the demo DKG above rather than reading it off the oracle. The other three values are
    // the bridge's, and the mapping lives in one place.
    let pegin_tree = federation.pegin_tree(y_51)?;

    let policy_id: [u8; 28] = hex::decode(pegin_policy_id)
        .map_err(|e| format!("pegin_policy_id: {e}"))?
        .try_into()
        .map_err(|_| "pegin_policy_id must be 28 bytes (56 hex chars)".to_string())?;

    // Scan PegInRequests: via Blockfrost (incl. yaci-devkit's blockfrost_url) when configured,
    // else via the N2C socket.
    let source: Box<dyn CardanoPegInSource> =
        if let Some(pid) = cfg.cardano.blockfrost_project_id.as_deref() {
            Box::new(BlockfrostPegInSource::new(
                pid,
                pegin_script_address,
                cfg.cardano.blockfrost_url.as_deref(),
            ))
        } else {
            Box::new(
                PallasPegInSource::from_bech32(
                    cardano_socket,
                    NetworkMagic(cardano_magic),
                    pegin_script_address,
                )
                .map_err(|e| format!("pallas source: {e}"))?,
            )
        };
    let reqs = rt
        .block_on(source.query_pegin_requests(&policy_id))
        .map_err(|e| format!("query_pegin_requests: {e}"))?;
    info!(
        "scanned {} peg-in request(s) at {pegin_script_address}",
        reqs.len()
    );

    // Operator-supplied drop list: BTC outpoints whose PIR lingers on Cardano but whose deposit
    // is already inside the current treasury (swept by an earlier TM, never minted). Re-including
    // them would spend a UTxO that no longer exists, so drop them before building.
    let excluded: std::collections::HashSet<bitcoin::OutPoint> = exclude_pegin
        .iter()
        .map(|s| parse_outpoint(s))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("--exclude-pegin: {e}"))?;

    // Scan the TM validator UTxOs ONCE (Cardano) — reused for the peg-in guard here
    // AND the chain-sourced treasury tip below, so a mover tick scans only once.
    let tm_scan: Option<heimdall::cardano::blockfrost_chain::TmScan> =
        match cfg.cardano.blockfrost_project_id.as_deref() {
            Some(pid) => {
                let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
                let bridge = resolve_bridge_contracts(cfg)?;
                let address = bridge.tm_address.clone();
                let asset_unit = bridge.tm_asset_unit();
                {
                    match rt.block_on(heimdall::cardano::blockfrost_chain::scan_tm_utxos(
                        &base_url,
                        pid,
                        &address,
                        &asset_unit,
                        cfg.bitcoin.inflight_deadline_secs,
                    )) {
                        Ok(scan) => Some(scan),
                        Err(e) => {
                            warn!("[sweep] could not scan TM UTxOs: {e}");
                            None
                        }
                    }
                }
            }
            None => None,
        };

    // The swept peg-ins trie: the source of "this deposit already reached the
    // treasury" (rev 5.4 — there are no Confirmed records to read it from), and
    // the state this TM's BTMR1 commitment advances.
    let spi_trie = spi_trie_from_cfg(cfg)?;

    // Auto-skip peg-ins Cardano already shows as handled — WITHOUT querying Bitcoin.
    // A peg-in already in the swept peg-ins trie, or committed to a viable
    // in-flight TM, would build an invalid/duplicate TM. Because `pegin-complete`
    // (fBTC mint) is the depositor's choice and may never happen, the on-chain PIR
    // can linger forever after its deposit is swept; we detect that from the SPI
    // trie and the Unconfirmed TM datums, not the open PIR.
    let mut auto_consumed: std::collections::HashSet<bitcoin::OutPoint> = tm_scan
        .as_ref()
        .map(|s| s.in_flight_spends.iter().copied().collect())
        .unwrap_or_default();
    for (key, _) in spi_trie.entries() {
        if let Some(op) = heimdall::cardano::treasury_datum::outpoint_from_swept_key(key) {
            auto_consumed.insert(op);
        }
    }

    // Each parse reconstructs and matches the peg-in P2TR, so the returned
    // `spend_info` is itself proof the spend info matches the on-chain
    // scriptPubKey — reuse it directly rather than re-deriving.
    let mut pegin_inputs = Vec::with_capacity(reqs.len());
    for req in &reqs {
        // Skip PIRs that don't reconstruct under Y_51 (other bridges' deposits, or encodings we
        // don't yet support) rather than aborting the whole sweep — a TM sweeps the valid peg-ins
        // and drops the rest. Mirrors the daemon's collect_pegins drop behaviour.
        let parsed = match parse_pegin_request(req, &pegin_tree) {
            Ok(p) => p,
            Err(e) => {
                warn!("  dropped peg-in {:?}: {e}", req.cardano_utxo);
                continue;
            }
        };
        let outpoint = OutPoint {
            txid: parsed.btc_txid,
            vout: parsed.btc_vout,
        };
        if excluded.contains(&outpoint) {
            info!(
                "  excluded peg-in {}:{} — {} sat (--exclude-pegin: already in treasury)",
                parsed.btc_txid,
                parsed.btc_vout,
                parsed.value.to_sat(),
            );
            continue;
        }
        if auto_consumed.contains(&outpoint) {
            println!(
                "  auto-skip peg-in {}:{} — {} sat (already in the swept peg-ins trie or \
                 committed to a live in-flight TM; its PIR just lingers unminted)",
                parsed.btc_txid,
                parsed.btc_vout,
                parsed.value.to_sat(),
            );
            continue;
        }
        info!(
            "  peg-in {}:{} — {} sat (depositor {})",
            parsed.btc_txid,
            parsed.btc_vout,
            parsed.value.to_sat(),
            hex::encode(parsed.depositor_outputkey.serialize()),
        );
        pegin_inputs.push(PegInInput {
            outpoint,
            value: parsed.value,
            spend_info: parsed.spend_info,
        });
    }

    // Collect every OPEN peg-out at the peg_out.ak address (the SPO's spec job — a TM pays the
    // pending peg-outs alongside sweeping every peg-in). Destination scriptPubKey, gross amount,
    // the datum-pinned per-peg-out fee, `created`, and the request identity all come from the
    // on-chain PegOut UTxO; the skip rules are applied below and inside `build_tm`.
    // Blockfrost-backed (the demo path); the pallas N2C path is peg-in only.
    // Peg-out collection is Blockfrost-only (the N2C path is peg-in only). When no Blockfrost is
    // configured, skip it with a loud warning rather than hard-failing — an N2C-only sweep that
    // previously worked must still build a TM (it just can't include peg-outs over N2C).
    let mut pegout_data = match cfg.cardano.blockfrost_project_id.as_deref() {
        Some(pid) => {
            let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
            rt.block_on(fetch_pegout_requests(
                &base_url,
                pid,
                pegout_script_address,
                bridged_token_unit,
            ))
            .map_err(|e| format!("fetch_pegout_requests: {e}"))?
        }
        None => {
            warn!(
                "[sweep] no cardano.blockfrost_project_id — peg-out collection is Blockfrost-only \
                 (N2C is peg-in only); building TM without peg-outs"
            );
            heimdall::cardano::pegout_datum::PegOutScan::default()
        }
    };
    // Report the undecodable UTxOs, not just the decodable ones: a request heimdall cannot
    // parse is payable by no TM and would otherwise vanish from this count with no signal
    // (WI-031 item 8).
    if pegout_data.malformed > 0 {
        warn!(
            "  {} UTxO(s) at {pegout_script_address} carry the bridged token but no \
             decodable PegOutDatum — no TM can pay them (their owners can still Cancel)",
            pegout_data.malformed
        );
    }
    info!(
        "scanned {} open peg-out request(s) at {pegout_script_address}",
        pegout_data.requests.len()
    );

    // Auto-mover: with nothing pending at all, don't post a treasury→treasury self-move
    // (it would just burn fee) — skip this tick. (Re-checked after the batch freeze below,
    // which can empty the peg-out set.)
    if auto_mode && pegin_inputs.is_empty() && pegout_data.requests.is_empty() {
        info!("[mover] nothing to sweep (0 peg-ins, 0 peg-outs) — skipping tick");
        return Ok(());
    }

    // The TREASURY tree, which keeps the federation key as its leaf and its own CSV.
    let treasury_spend_info =
        treasury_spend_info(&secp, y_51, federation.y_fed, federation.csv_blocks);
    let treasury_spk = ScriptBuf::new_p2tr_tweaked(treasury_spend_info.output_key());

    // Treasury input: an explicit --treasury-outpoint/--treasury-amount-sat pair
    // overrides; otherwise chain-source it from the Cardano tip Confirmed-TM
    // (WI-028) so no manual config edit is needed after each movement.
    let (treasury_outpoint, treasury_amount_sat) = match (treasury_outpoint, treasury_amount_sat) {
        (Some(o), Some(a)) => {
            info!("  treasury (CLI override): {o} — {a} sat");
            (parse_outpoint(o)?, a)
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(
                "pass BOTH --treasury-outpoint and --treasury-amount-sat, or NEITHER \
                        (to chain-source the treasury from the bridge-state singleton)"
                    .to_string(),
            );
        }
        (None, None) => {
            let tip = singleton_chain_tip(&rt, cfg, tm_scan.as_ref())?;
            if tip.in_flight {
                let msg = format!(
                    "a treasury movement is already in flight spending tip {} — wait for \
                     confirm-tmtx before sweeping again",
                    tip.outpoint
                );
                if auto_mode {
                    info!("[mover] {msg} (skipping tick)");
                    return Ok(());
                }
                return Err(format!("{msg} (or override with --treasury-outpoint)"));
            }
            println!(
                "  treasury (bridge-state singleton head): {} — {} sat",
                tip.outpoint,
                tip.value.to_sat()
            );
            (tip.outpoint, tip.value.to_sat())
        }
    };

    // The completed-peg-outs trie, loaded before peg-out selection: it decides both which
    // requests are still owed a payment (WI-031) and the root this TM commits, so a trie out
    // of sync with the chain must stop the sweep before anything is built or signed.
    let cpo_trie = cpo_trie_from_cfg(cfg)?;
    let cpo_trust = cross_check_cpo_trie_from_cfg(&rt, cfg, &cpo_trie)?;

    // ── Peg-out selection ──────────────────────────────────────────────────────────────────────
    // An open PegOut UTxO is NOT an unpaid one: it survives at the script address until someone
    // completes it (which needs this TM's Bitcoin confirmation plus a membership proof — hours
    // later, or never), so the scan above keeps returning withdrawals earlier TMs already paid.
    // The completed-peg-outs trie, keyed by `por_id`, is what filters them: `build_tm` skips a
    // request already in the trie (`AlreadyCompleted`).
    //
    // WI-031 deleted the `(destination scriptPubKey, net sat)` multiset that used to run here.
    // It could never be keyed by request identity — a `Confirmed` TM datum holds
    // `fulfilled_peg_outs: [{scriptPubKey, amount}]` and nothing more, and the
    // `fulfilled_por_outpoints` hint exists only on `Unconfirmed` and is explicitly unverified
    // — so a credit left by a long-completed withdrawal was indistinguishable from an unpaid
    // one and stranded a re-created identical request permanently. The double-pay window it
    // nominally covered is already closed by the in-flight refusal above (`tip.in_flight`),
    // which stops a second sweep before the previous TM confirms and folds into the trie.
    // Freeze this batch's consensus inputs at one chain point (WI-040/WI-041): the
    // operational parameters TM construction reads (Config `params[1..=3]`), the chain "now"
    // the freshness filter compares `created` against, and the batch opportunity whose
    // cutoff decides membership. Chain values, never this node's: each decides TM
    // bytes, and a divergent verdict means a divergent txid and a failed FROST round.
    let sweep_batch = batch_params(&rt, cfg, true)?;
    let tm_params = sweep_batch.params.clone();

    // Peg-out membership is a function of the batch, not of the instant this node
    // happened to scan: resolve each request's CREATION SLOT (a chain fact — the datum's
    // `created` is requester-set and backdatable), then take the cutoff-eligible ones in
    // the spec's FIFO order up to the per-TM capacity. Anything held back is a candidate
    // for a later batch; since rev 5.1 retired the outpoint pin, missing a batch costs a
    // peg-out only latency.
    rt.block_on(heimdall::cardano::pegout_datum::resolve_created_slots(
        &bf_http::base_url(
            cfg.cardano.blockfrost_project_id.as_deref().unwrap_or(""),
            cfg.cardano.blockfrost_url.as_deref(),
        ),
        cfg.cardano.blockfrost_project_id.as_deref().unwrap_or(""),
        &mut pegout_data.requests,
        sweep_batch.tip,
    ));
    pegout_data.requests = freeze_sweep_pegouts(
        std::mem::take(&mut pegout_data.requests),
        sweep_batch.batch.open(),
    );

    let mut pegout_requests: Vec<PegOutRequest> = Vec::new();
    if !pegout_data.requests.is_empty() && cpo_trust == CpoTrust::Unverified {
        // The trie is the only record of what an earlier TM already paid, so a trie this node
        // cannot vouch for means "pay no peg-out", never "pay unchecked" — unchecked, every
        // open request is re-paid on every sweep, draining the treasury irrecoverably.
        // Peg-ins still sweep.
        warn!(
            "[pegout] skipping ALL {} open peg-out(s): the completed-peg-outs trie was not \
             cross-checked against the chain (no cardano.cpo_policy_id), and it is the only \
             record of what an earlier TM already paid. Set cardano.cpo_policy_id (and \
             protocol.state_dir) to pay peg-outs.",
            pegout_data.requests.len(),
        );
    } else if !pegout_data.requests.is_empty() {
        for po in &pegout_data.requests {
            info!(
                "  peg-out → {} — {} sat ({}#{})",
                hex::encode(&po.destination_script_pubkey),
                po.amount_sat,
                po.cardano_utxo.0,
                po.cardano_utxo.1,
            );
            pegout_requests.push(PegOutRequest {
                script_pubkey: ScriptBuf::from_bytes(po.destination_script_pubkey.clone()),
                amount: Amount::from_sat(po.amount_sat),
                per_pegout_fee: Amount::from_sat(po.per_pegout_fee),
                por_id: po.por_id,
                outpoint: po.outpoint,
                created: po.created,
            });
        }
    }

    // Nothing left once the filters ran (every peg-out already paid): don't burn a fee on a
    // treasury→treasury self-move.
    if auto_mode && pegin_inputs.is_empty() && pegout_requests.is_empty() {
        info!("[mover] nothing to sweep (0 peg-ins, 0 unpaid peg-outs) — skipping tick");
        return Ok(());
    }

    // No Config UTxO to snapshot: fall back to the tip time alone. Without
    // Blockfrost there are no peg-outs to filter anyway, so 0 is inert.
    let snapshot_now_ms = sweep_batch.now_ms;
    let chain_now_ms = match (
        snapshot_now_ms,
        cfg.cardano.blockfrost_project_id.as_deref(),
    ) {
        (Some(ms), _) => ms,
        (None, Some(pid)) if !pegout_requests.is_empty() => {
            let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
            rt.block_on(bf_http::fetch_latest_block_time(&base_url, pid))
                .map_err(|e| format!("chain now: {e}"))?
                .saturating_mul(1000)
        }
        _ => 0,
    };

    // Treasury self-funds the fee; output[0] = new treasury = sum(inputs) − fee; outputs[1..m] = one
    // payment per peg-out (sorted by (scriptPubKey, net amount, por_id) inside build_tm); the LAST
    // output is the mandatory BTMR1 two-root commitment (spi_root ++ cpo_root).
    let unsigned = build_tm(
        TreasuryInput {
            outpoint: treasury_outpoint,
            value: Amount::from_sat(treasury_amount_sat),
            spend_info: treasury_spend_info,
        },
        pegin_inputs,
        pegout_requests,
        treasury_spk.clone(),
        &tm_params,
        &heimdall::bitcoin::tm_builder::Freshness::at(chain_now_ms),
        &cpo_trie,
        &spi_trie,
    )
    .map_err(|e| format!("build sweep: {e}"))?;

    info!(
        "  completed-peg-outs root committed: {} ({} fulfilled peg-out(s))",
        hex::encode(unsigned.cpo_root),
        unsigned.fulfilled.len(),
    );
    println!(
        "  swept peg-ins root committed: {} ({} swept input(s))",
        hex::encode(unsigned.spi_root),
        unsigned.tx.input.len().saturating_sub(1),
    );

    // Surface any peg-outs the TM dropped as unpayable (non-standard destination
    // or sub-dust after fee) so the operator sees them — the TM still pays the
    // rest rather than aborting.
    for s in &unsigned.skipped_pegouts {
        info!(
            "[sweep] skipped peg-out → {} ({} sat): {}",
            hex::encode(s.script_pubkey.as_bytes()),
            s.amount.to_sat(),
            s.reason
        );
    }

    // output[0] is the new treasury; if it doesn't carry the treasury
    // scriptPubKey the whole balance would move to the wrong address, so
    // refuse before signing rather than broadcast a misdirected sweep.
    if unsigned.tx.output[0].script_pubkey != treasury_spk {
        return Err(format!(
            "output[0] scriptPubKey {} does not match treasury spk {}",
            hex::encode(unsigned.tx.output[0].script_pubkey.as_bytes()),
            hex::encode(treasury_spk.as_bytes()),
        ));
    }

    let signed = sign_tm_frost(&unsigned, &dkg.key_packages, &dkg.public_key_package)
        .map_err(|e| format!("FROST sign sweep: {e}"))?;
    let local_raw = bitcoin::consensus::encode::serialize(&signed);
    // If an existing-on-Bitcoin TM is provided, the effective tx posted to Cardano is THAT one,
    // not the locally-built one. Deserialize it so every subsequent print (txid, inputs, outputs)
    // reflects the bytes Cardano will actually see — operators would otherwise copy-paste the
    // wrong txid from the locally-signed value.
    let (effective_tx, raw, override_in_effect): (Transaction, Vec<u8>, bool) =
        if let Some(hex_str) = existing_tm_hex {
            let trimmed = hex_str.trim();
            let bytes = hex::decode(trimmed).map_err(|e| format!("existing_tm_hex: {e}"))?;
            let tx: Transaction = bitcoin::consensus::deserialize(&bytes)
                .map_err(|e| format!("existing_tm_hex: not a valid Bitcoin transaction: {e}"))?;
            // Slice into `trimmed` (not the un-trimmed `hex_str`) — otherwise leading/trailing
            // whitespace makes `hex_str.len()` bigger than `trimmed.len()` and the slice panics.
            let preview_end = trimmed.len().min(20);
            info!(
                "  [override] using existing TM bytes ({} bytes hex={}…)",
                bytes.len(),
                &trimmed[..preview_end]
            );
            (tx, bytes, true)
        } else {
            (signed, local_raw, false)
        };

    // With an override, the bytes posted to Cardano are the supplied TM, NOT the locally-built
    // one (heimdall's real output is the Cardano post; the BTC broadcast path is debug/demo).
    // Warn about any peg-out the local build would pay that the supplied TM does NOT — typically
    // a peg-out created/scanned AFTER the supplied TM was built, which this movement cannot
    // fulfil (it rolls to the next TM). Surfacing it prevents silently recording a TM that skips
    // a pending withdrawal. (Compared by destination scriptPubKey: local peg-out outputs are
    // `unsigned.tx.output[1..]`; output[0] is the treasury change.)
    if override_in_effect {
        let override_out_spks: std::collections::HashSet<&[u8]> = effective_tx
            .output
            .iter()
            .map(|o| o.script_pubkey.as_bytes())
            .collect();
        for out in unsigned.tx.output.iter().skip(1) {
            if !override_out_spks.contains(out.script_pubkey.as_bytes()) {
                warn!(
                    "[override] supplied TM does not pay pending peg-out → {} ({} sat) \
                     — likely recorded after the supplied TM was built; it will NOT be fulfilled \
                     by this movement",
                    hex::encode(out.script_pubkey.as_bytes()),
                    out.value.to_sat(),
                );
            }
        }
    }

    info!("── Treasury Movement (sweep peg-ins) ──");
    info!("  txid:    {}", effective_tx.compute_txid());
    info!("  inputs:  {}", effective_tx.input.len());
    if override_in_effect {
        // The override is a different tx than the local build, so its inputs do NOT correspond
        // to the locally-computed `unsigned.prevouts` — print outpoints only (we don't have the
        // override's prevout values/scripts) rather than mispair them.
        for (i, inp) in effective_tx.input.iter().enumerate() {
            info!(
                "    [{}] {}:{}",
                i, inp.previous_output.txid, inp.previous_output.vout
            );
        }
    } else {
        for (i, (inp, prevout)) in effective_tx
            .input
            .iter()
            .zip(unsigned.prevouts.iter())
            .enumerate()
        {
            info!(
                "    [{}] {}:{} — {} sat  script={}",
                i,
                inp.previous_output.txid,
                inp.previous_output.vout,
                prevout.value.to_sat(),
                hex::encode(prevout.script_pubkey.as_bytes()),
            );
        }
    }
    info!("  outputs: {}", effective_tx.output.len());
    for (i, out) in effective_tx.output.iter().enumerate() {
        info!(
            "    [{}] {} sat  script={}",
            i,
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes()),
        );
    }
    info!(
        "  output[0] (new treasury): {} sat",
        effective_tx.output[0].value.to_sat()
    );
    info!("  size:    {} bytes", raw.len());
    info!("  hex:     {}", hex::encode(&raw));

    // `--broadcast` is the master "execute side effects" gate. Without it, sweep-pegins only
    // builds, signs, and prints the TM (no Cardano post, no Bitcoin broadcast) — a safe dry run.
    if !broadcast {
        info!("(not broadcast — pass --broadcast to post the TM / send)");
        return Ok(());
    }

    // Protocol path (technical_documentation.md §"Post signed TM as Unconfirmed TM tx"): when
    // Blockfrost is configured, hand the signed TM to the shared Cardano chain, which POSTS the
    // Unconfirmed TM UTxO to Cardano (Constr(0, [signed_btc_tx]) at treasury_address) when
    // `cardano.submit_oracle` is set. That post is the whole of heimdall's output: a watchtower
    // (binocular `relay`) carries the signed bytes to Bitcoin and then runs the validated
    // Confirm. Nothing on this path can reach Bitcoin itself (WI-086).
    if let Some(project_id) = cfg.cardano.blockfrost_project_id.as_deref() {
        let fixture = heimdall::epoch::fixture::demo_static_fixture_from_config(cfg, &federation);
        let bridge = resolve_bridge_contracts(cfg)?;
        let treasury_config = TreasuryConfig {
            y_51: fixture.y_51,
            y_fed: fixture.y_fed,
            federation_csv_blocks: fixture.federation_csv_blocks,
            // The published refund delay ([CFG-9]). Read from the Config where one exists;
            // this demo path carries the same value the depositor tooling defaults to.
            pegin_refund_timeout_blocks: cfg.bitcoin.pegin_refund_timeout_blocks.unwrap_or(4320),
            treasury_outpoint: fixture.treasury_outpoint,
            treasury_value: fixture.treasury_value,
        };
        let mut chain = BlockfrostCardanoChain::new(
            project_id,
            &bridge.tm_address,
            &bridge.tm_policy_id,
            heimdall::cardano::config_params::TM_ASSET_NAME_HEX,
            treasury_config,
            fixture.roster.clone(),
            cfg.cardano.blockfrost_url.as_deref(),
        )
        .with_local_fee_rate(cfg.bitcoin.fee_rate_sat_per_vb);
        chain = chain.with_cpo_source(
            Some(bridge.bridge_state_policy_id.as_str()),
            cfg.cardano.kupo_url.as_deref(),
        );
        if let Some(mnemonic) = &cfg.cardano.mnemonic {
            chain = chain
                .with_mnemonic(mnemonic)
                .map_err(|e| format!("with_mnemonic: {e}"))?;
        }
        // No Bitcoin wiring: this posts the TM to CARDANO, and the watchtower relays
        // the signed bytes from the record (WI-086). `--existing-tm-hex` used to need
        // a guard here against re-broadcasting somebody else's already-confirmed
        // transaction; with nothing able to broadcast, the guard has no subject.
        chain = chain.with_submit_config(cfg.cardano.submit_oracle);
        chain = chain.with_validity_window(cfg.cardano.tm_validity_window_secs.unwrap_or(1800));
        let chain = apply_tm_policy(chain, cfg)?;
        // The data-availability hint describes the peg-outs of the tx being posted.
        // Under --existing-tm-hex the posted bytes are somebody ELSE'S transaction:
        // the locally built TM's `fulfilled` list says nothing about which requests
        // that tx pays, and attaching it would publish a hint that points at the
        // wrong peg-out requests. Post an empty hint instead — the field is
        // unverified and reconstruction's fallback matcher recovers the true set
        // from the tx's own payment outputs against the attested root, so the only
        // cost is a slower rebuild.
        let hint: Vec<[u8; 36]> = if override_in_effect {
            warn!(
                "  [override] posting an EMPTY fulfilled_por_outpoints hint: the overriding tx \
                 is not the locally built TM, so the local peg-out set does not describe it. \
                 Reconstruction falls back to matching payments against the committed root."
            );
            Vec::new()
        } else {
            unsigned.fulfilled.iter().map(|f| f.outpoint).collect()
        };
        rt.block_on(chain.submit_signed_tm(&raw, &hint))
            .map_err(|e| format!("submit_signed_tm: {e}"))?;
        return Ok(());
    }

    // No Blockfrost configured: there is nowhere to post the TM, and the pre-protocol
    // shortcut that used to broadcast straight to Bitcoin is gone (WI-086) — it built a
    // movement that never landed on Cardano, so `confirm-tmtx` had nothing to confirm
    // and no watchtower could reconcile it. The signed bytes were printed above.
    Err(
        "cardano.blockfrost_project_id is unset, so the Treasury Movement cannot be posted \
         to Cardano — and posting it is the only thing that makes it relayable. The signed \
         Bitcoin transaction was printed above."
            .to_string(),
    )
}

fn print_bootstrap_treasury(cfg: &HeimdallConfig) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::{Address, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;

    let secp = Secp256k1::new();

    // The DEPLOYER's command: it prints the address the genesis BTC is sent to,
    // derived from the federation key this node holds rather than from any chain
    // state — at this point in a bridge's life there is none to read, and this
    // address is what the bridge is bootstrapped from (WI-069).
    //
    // Since WI-087 that key is normally `federation_setup_Y`, the ceremony's
    // group key, which a member holds a share of; `bitcoin.y_fed_seed_hex` is the
    // older single-holder form. Either one is the whole input here, because only
    // the PUBLIC half decides an address — and this is the last step at which it
    // is a LOCAL value: the line below is what gets published, after which it is
    // read from Config #11 under the name y_federation.
    let signer = federation_signer(cfg)?;
    let y_fed = signer.public_key()?;

    let network = cfg.bitcoin.parsed_network();
    let csv_blocks = csv_blocks_u16(cfg)?;

    // At bootstrap Y_51 = Y_fed.
    let spend_info = treasury_spend_info(&secp, y_fed, y_fed, csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address =
        Address::from_script(&script_pubkey, network).map_err(|e| format!("P2TR address: {e}"))?;

    println!("{address}");
    // The values that produced it. These go into the Config datum at genesis, and
    // every SPO then reads them from there instead of typing them.
    println!(
        "y_federation:          {}  ({})",
        hex::encode(y_fed.serialize()),
        signer.label()
    );
    println!("federation_csv_blocks: {csv_blocks}");
    Ok(())
}

/// Print the treasury Taproot address when Y_fed = Y_51 = FROST group key.
///
/// `frost_key_hex` must be the 32-byte x-only FROST group key as hex.
fn print_frost_treasury(
    cfg: &HeimdallConfig,
    frost_key_hex: Option<&str>,
    y_federation_hex: Option<&str>,
) -> Result<(), String> {
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::{Address, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::frost::dkg::run_demo_dkg;

    let secp = Secp256k1::new();
    let network = cfg.bitcoin.parsed_network();
    let csv_blocks = csv_blocks_u16(cfg)?;

    fn xonly(flag: &str, hex_str: &str) -> Result<UntweakedPublicKey, String> {
        let bytes: Vec<u8> = hex::decode(hex_str).map_err(|e| format!("{flag}: {e}"))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("{flag} must be 32 bytes (x-only), got {}", bytes.len()))?;
        UntweakedPublicKey::from_slice(&key)
            .map_err(|e| format!("{flag} is not a valid x-only pubkey: {e}"))
    }

    // No --frost-key: reproduce the deterministic demo DKG, exactly as `sweep-pegins`
    // and `show-treasury` do, so the address this prints is the one they will sign for.
    let group_key = match frost_key_hex {
        Some(h) => xonly("--frost-key", h)?,
        None => {
            let dkg = run_demo_dkg(
                b"heimdall-demo-seed-v1-0123456789",
                cfg.demo.min_signers,
                cfg.demo.max_signers,
            );
            group_xonly(dkg.public_key_package.verifying_key())?.xonly
        }
    };
    // The recovery leaf's key. Defaulting it to Y_51 is only correct at genesis; on a
    // deployed bridge y_federation is Config #11 and the two are different keys, so a
    // silent default would print a well-formed address holding nothing — the failure
    // mode WI-074 hit from the depositor side.
    let y_fed = match y_federation_hex {
        Some(h) => xonly("--y-federation", h)?,
        None => group_key,
    };

    println!(
        "FROST group key (x-only): {}",
        hex::encode(group_key.serialize())
    );
    println!(
        "y_federation (leaf key):  {}{}",
        hex::encode(y_fed.serialize()),
        if y_federation_hex.is_none() {
            "  (defaulted to Y_51 — genesis tree)"
        } else {
            ""
        }
    );
    println!("federation CSV blocks:    {csv_blocks}");

    let spend_info = treasury_spend_info(&secp, group_key, y_fed, csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address =
        Address::from_script(&script_pubkey, network).map_err(|e| format!("P2TR address: {e}"))?;

    println!("Treasury address: {address}");
    println!("Script pubkey: {}", hex::encode(script_pubkey.as_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_cardano_outref, parse_hex_n, parse_key32, pool_id_bech32, ref_script_already_deployed,
    };

    #[test]
    fn parse_cardano_outref_ok() {
        let (tx_id, index) = parse_cardano_outref(&format!("{}:7", "ab".repeat(32))).unwrap();
        assert_eq!(tx_id, [0xab; 32]);
        assert_eq!(index, 7);
    }

    #[test]
    fn parse_cardano_outref_rejects_malformed() {
        // no separator
        assert!(parse_cardano_outref("aabb").is_err());
        // hash not 32 bytes
        assert!(parse_cardano_outref("aabb:0").is_err());
        // non-hex hash
        assert!(parse_cardano_outref(&format!("{}:0", "zz".repeat(32))).is_err());
        // non-numeric / out-of-u32-range index
        assert!(parse_cardano_outref(&format!("{}:x", "ab".repeat(32))).is_err());
        assert!(parse_cardano_outref(&format!("{}:4294967296", "ab".repeat(32))).is_err());
    }

    #[test]
    fn parse_hex_n_checks_length() {
        assert_eq!(parse_hex_n::<2>("a1b2", "x").unwrap(), [0xa1, 0xb2]);
        assert!(parse_hex_n::<2>("a1", "x").is_err());
        assert!(parse_hex_n::<2>("zz", "x").is_err());
    }

    /// WI-092: what `sign-registration` prints must be what `register-spo`
    /// accepts, and the binding must be to THIS url. The self-check inside the
    /// command cannot catch a divergence between the two sides on its own — it
    /// signs and verifies with one message builder — so this pins the property
    /// the operator actually depends on: signatures made for one url do not
    /// verify for another, which is why the guide says byte-identical.
    #[test]
    fn air_gapped_signatures_verify_and_are_bound_to_the_url() {
        use bitcoin::key::Secp256k1;
        use bitcoin::secp256k1::Keypair;
        use heimdall::cardano::register_spo::{sign_registration, verify_registration};
        use pallas_crypto::key::ed25519;

        let secp = Secp256k1::new();
        let cold = ed25519::SecretKey::from([0x11u8; 32]);
        let bifrost = Keypair::from_seckey_slice(&secp, &[0x22u8; 32]).unwrap();
        let id_pk = bifrost.x_only_public_key().0.serialize();
        let url = b"http://spo1.example.com:18500";

        let sigs = sign_registration(&cold, &bifrost, url);
        assert!(verify_registration(&sigs, &id_pk, url).is_ok());

        // A trailing slash is a different url, and therefore a different message.
        let slashed = b"http://spo1.example.com:18500/";
        assert!(
            verify_registration(&sigs, &id_pk, slashed).is_err(),
            "signatures must not carry over to a different --bifrost-url"
        );
    }

    /// WI-091: the deploy commands used to park a second copy of a script this
    /// wallet already holds, locking another ~55 ADA for nothing — every consumer
    /// finds the first one by scanning this same wallet. The guard reports it and
    /// stops, and `--force` is the deliberate override.
    #[test]
    fn a_second_copy_of_a_ref_script_is_refused_unless_forced() {
        use heimdall::cardano::bf_http::BfUtxo;
        let hash = "ab".repeat(28);
        let holding = vec![BfUtxo {
            tx_hash: "cd".repeat(32),
            output_index: 0,
            amount: Vec::new(),
            inline_datum: None,
            reference_script_hash: Some(hash.clone()),
        }];
        assert!(ref_script_already_deployed(
            &holding, &hash, "registry", false
        ));
        assert!(
            !ref_script_already_deployed(&holding, &hash, "registry", true),
            "--force must deploy anyway"
        );
        // A wallet holding some OTHER script is not a duplicate.
        assert!(!ref_script_already_deployed(
            &holding,
            &"ef".repeat(28),
            "registry",
            false
        ));
        assert!(!ref_script_already_deployed(&[], &hash, "registry", false));
    }

    #[test]
    fn parse_key32_accepts_hex_and_textenvelope() {
        let hexkey = "11".repeat(32);
        assert_eq!(parse_key32(&hexkey, "k").unwrap(), [0x11; 32]);

        // cardano-cli TextEnvelope from a file.
        let dir = std::env::temp_dir().join(format!("heimdall-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cold.skey");
        std::fs::write(
            &path,
            format!(
                r#"{{"type": "StakePoolSigningKey_ed25519", "description": "", "cborHex": "5820{}"}}"#,
                "22".repeat(32)
            ),
        )
        .unwrap();
        assert_eq!(
            parse_key32(path.to_str().unwrap(), "k").unwrap(),
            [0x22; 32]
        );
        // TextEnvelope whose cborHex is not a 32-byte key
        std::fs::write(&path, r#"{"type": "x", "cborHex": "5840aabb"}"#).unwrap();
        assert!(parse_key32(path.to_str().unwrap(), "k").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // The bech32 form must round-trip back to the same 28 bytes under the
    // `pool` HRP (the id Blockfrost's /pools endpoint expects).
    #[test]
    fn pool_id_bech32_roundtrip() {
        let id = [0x5Au8; 28];
        let s = pool_id_bech32(&id);
        assert!(s.starts_with("pool1"), "{s}");
        let (hrp, data) = bitcoin::bech32::decode(&s).unwrap();
        assert_eq!(hrp.as_str(), "pool");
        assert_eq!(data, id);
    }

    // ---- WI-019: --evidence-file derivation glue ---------------------------

    use super::EvidenceFile;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use frost_secp256k1_tr::Identifier;
    use heimdall::cardano::blueprint::FaultVerifierKind;
    use heimdall::circuits::fault_evidence as fe;
    use heimdall::frost::participant;
    use heimdall::http::{auth, canonical, frost_bridge};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn corrupt_scalar(be: &[u8; 32]) -> [u8; 32] {
        use halo2_base::halo2_proofs::halo2curves::ff::Field;
        use halo2_base::halo2_proofs::halo2curves::secp256k1::Fq;
        use heimdall::circuits::dkg_fault::{axiom_scalar_from_be_bytes, be_bytes_from_fq};
        be_bytes_from_fq(axiom_scalar_from_be_bytes(be) + Fq::ONE)
    }

    /// A signed Round 1 PoK evidence; `corrupt` flips μ to make the PoK invalid.
    fn signed_round1(corrupt: bool) -> fe::Round1PokFaultEvidence {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC1);
        let (_s, pkg) =
            participant::dkg_part1(Identifier::try_from(1u16).unwrap(), 3, 2, &mut rng).unwrap();
        let (commitments, mut sigma_i) = frost_bridge::round1_fields(&pkg).unwrap();
        if corrupt {
            let mu: [u8; 32] = sigma_i[32..64].try_into().unwrap();
            sigma_i[32..64].copy_from_slice(&corrupt_scalar(&mu));
        }
        let pool = [0x11u8; 28];
        let evidence_hash =
            fe::round1_evidence_hash_from_fields(&pool, 1, &commitments, &sigma_i).unwrap();
        let canonical_bytes =
            canonical::round1(7, 51, 0, &pool, &commitments, &sigma_i, &evidence_hash);
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(&secp, &sk);
        fe::Round1PokFaultEvidence {
            epoch: 7,
            threshold: 51,
            attempt: 0,
            accused_pool_id: pool,
            bifrost_id_pk: kp.x_only_public_key().0.serialize(),
            identifier: 1,
            commitments,
            sigma_i,
            payload_signature: auth::sign_payload(&secp, &kp, &canonical_bytes),
        }
    }

    fn round1_json(ev: &fe::Round1PokFaultEvidence) -> serde_json::Value {
        serde_json::json!({
            "kind": "invalid-payload-round1",
            "accused_pool_id": hex::encode(ev.accused_pool_id),
            "bifrost_id_pk": hex::encode(ev.bifrost_id_pk),
            "epoch": ev.epoch, "threshold": ev.threshold, "attempt": ev.attempt,
            "identifier": ev.identifier,
            "commitments": ev.commitments.iter().map(hex::encode).collect::<Vec<_>>(),
            "sigma_i": hex::encode(ev.sigma_i),
            "payload_signature": hex::encode(ev.payload_signature),
        })
    }

    /// The CLI's JSON → derive() path reproduces the library's evidence_hash
    /// for a Round 1 PoK fault, and binds the correct namespace + kind.
    #[test]
    fn evidence_file_round1_derives_library_hash() {
        let ev = signed_round1(true);
        let parsed: EvidenceFile = serde_json::from_value(round1_json(&ev)).unwrap();
        let d = parsed.derive().unwrap();
        assert_eq!(d.kind, FaultVerifierKind::Round1);
        assert_eq!(d.accused_pool_id, ev.accused_pool_id);
        assert_eq!(d.evidence_hash, ev.evidence_hash().unwrap());
        assert_eq!(d.namespace_hash, ev.namespace_hash());
        assert!(d.round1_invalid.is_some());
        assert!(d.round2_invalid.is_none());
        assert!(d.equivocation.is_none());
    }

    /// A payload that actually verifies is rejected — no FaultProof for honest
    /// behavior.
    #[test]
    fn evidence_file_round1_rejects_honest_payload() {
        let parsed: EvidenceFile =
            serde_json::from_value(round1_json(&signed_round1(false))).unwrap();
        assert!(
            parsed
                .derive()
                .unwrap_err()
                .contains("does not encode a fault")
        );
    }

    /// The CLI refuses to forge: evidence whose accused signature does not
    /// verify is rejected before any hash is derived (spec §9.2).
    #[test]
    fn evidence_file_round1_rejects_bad_signature() {
        let ev = signed_round1(true);
        let mut json = round1_json(&ev);
        let mut sig = ev.payload_signature;
        sig[0] ^= 0x01;
        json["payload_signature"] = serde_json::Value::String(hex::encode(sig));
        let parsed: EvidenceFile = serde_json::from_value(json).unwrap();
        assert!(parsed.derive().unwrap_err().contains("signature"));
    }

    fn signed_equivocation() -> fe::EquivocationEvidence {
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(&secp, &sk);
        let pool = [0x22u8; 28];
        let mk = |seed: u64| {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (_s, pkg) =
                participant::dkg_part1(Identifier::try_from(1u16).unwrap(), 3, 2, &mut rng)
                    .unwrap();
            let (commitments, sigma_i) = frost_bridge::round1_fields(&pkg).unwrap();
            let evidence_hash =
                fe::round1_evidence_hash_from_fields(&pool, 1, &commitments, &sigma_i).unwrap();
            let bytes = canonical::round1(3, 51, 1, &pool, &commitments, &sigma_i, &evidence_hash);
            let sig = auth::sign_payload(&secp, &kp, &bytes);
            (bytes, sig)
        };
        let (payload_a, signature_a) = mk(0xA1);
        let (payload_b, signature_b) = mk(0xB2);
        fe::EquivocationEvidence {
            epoch: 3,
            threshold: 51,
            attempt: 1,
            phase: fe::NamespacePhase::Round1,
            accused_pool_id: pool,
            bifrost_id_pk: kp.x_only_public_key().0.serialize(),
            payload_a,
            signature_a,
            payload_b,
            signature_b,
        }
    }

    #[test]
    fn evidence_file_equivocation_derives_sorted_hash() {
        let ev = signed_equivocation();
        let json = serde_json::json!({
            "kind": "equivocation",
            "accused_pool_id": hex::encode(ev.accused_pool_id),
            "bifrost_id_pk": hex::encode(ev.bifrost_id_pk),
            "epoch": ev.epoch, "threshold": ev.threshold, "attempt": ev.attempt,
            "round": "round1",
            "payload_a": hex::encode(&ev.payload_a),
            "signature_a": hex::encode(ev.signature_a),
            "payload_b": hex::encode(&ev.payload_b),
            "signature_b": hex::encode(ev.signature_b),
        });
        let parsed: EvidenceFile = serde_json::from_value(json).unwrap();
        let d = parsed.derive().unwrap();
        assert_eq!(d.kind, FaultVerifierKind::Equivocation);
        assert_eq!(d.accused_pool_id, ev.accused_pool_id);
        assert_eq!(d.evidence_hash, ev.evidence_hash());
        assert_eq!(d.namespace_hash, ev.namespace_hash());
        // the equivocation witness is carried through to the mint redeemer
        let w = d.equivocation.expect("equivocation witness");
        assert_eq!(w.payload_a, ev.payload_a);
        assert_eq!(w.signature_a, ev.signature_a);
        assert_eq!(w.payload_b, ev.payload_b);
        assert_eq!(w.signature_b, ev.signature_b);
    }

    #[test]
    fn evidence_file_rejects_unknown_kind() {
        let json = serde_json::json!({
            "kind": "nonsense", "accused_pool_id": "22".repeat(28),
            "bifrost_id_pk": "33".repeat(32),
            "epoch": 0, "threshold": 51, "attempt": 0,
        });
        let parsed: EvidenceFile = serde_json::from_value(json).unwrap();
        assert!(parsed.derive().unwrap_err().contains("kind"));
    }
}
