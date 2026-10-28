use clap::{Args, Parser, Subcommand};
mod admin_local;
mod admin_password_input;
#[cfg(test)]
mod cli_profile_tests;
#[cfg(test)]
mod controller_snapshot_tests;
pub use admin_password_input::PasswordInputError;
use fleet_application::{
    ControllerDeliveryIdentity, DisabledSecretProvider, ResolvedSecret, RetentionPolicy,
    RunRetentionCleanup, RunRetentionCleanupInput, SecretProvider, SecretProviderError,
};
use fleet_core::{
    DatabaseSettings, LogProfile, format_error_message, format_warning_message, init_logging,
    redact_secret,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_rustls::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tungstenite::client::IntoClientRequest;
use tungstenite::{Connector, Message};

#[cfg(test)]
use std::sync::mpsc;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const LOG_TAIL_MAX_LINES: usize = 50;
const LOG_TAIL_MAX_LINE_BYTES: usize = 4096;
const LOG_TAIL_POLL_INTERVAL: Duration = Duration::from_millis(100);
const REMOTE_RUN_EXPIRES_IN_SECONDS: u64 = 300;
const AGENT_SESSION_OUTBOUND_QUEUE_CAPACITY: usize = 64;
const AGENT_SESSION_READ_POLL_INTERVAL: Duration = Duration::from_millis(250);
const AGENT_JOURNAL_MAX_REPORTS: u64 = 4096;
const AGENT_JOURNAL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const AGENT_JOURNAL_FINAL_RESERVE_REPORTS: u64 = 4;
const AGENT_JOURNAL_FINAL_RESERVE_BYTES: u64 = 4 * 1024 * 1024;
const AGENT_JOURNAL_WORKER_REQUESTS: usize = 16;
const AGENT_JOURNAL_WORKER_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
const AGENT_REPORT_BATCH_SIZE: u32 = 16;
const AGENT_REPORT_BATCH_BYTES: u64 = 8 * 1024 * 1024;
const AGENT_REPORT_SENDS_PER_TICK: usize = 4;
const AGENT_REPORT_SCAN_INTERVAL: Duration = Duration::from_millis(250);
const AGENT_REPORT_RETRY_BASE: Duration = Duration::from_secs(1);
const AGENT_REPORT_RETRY_MAX: Duration = Duration::from_secs(30);
const AGENT_JOURNAL_COMMIT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CLI_PROFILE_PATH: &str = ".fleet/cli-profile.json";
const CONTROLLER_SIGNING_STAGED_TRUST_BUNDLE_PATH: &str =
    "/api/controller/signing-rotation/rollout-trust-bundle/staged";
const AGENT_CERTIFICATE_LIFECYCLE_RUNTIME_NOT_IMPLEMENTED: &str =
    "certificate_lifecycle_runtime_not_implemented";

#[derive(Debug, Parser)]
#[command(name = "fleet")]
#[command(about = "Sponzey Fleet command line interface")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    #[arg(long, default_value = "product")]
    pub log_profile: LogProfileArg,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogProfileArg {
    Product,
    FieldDebug,
    Development,
}

impl From<LogProfileArg> for LogProfile {
    fn from(value: LogProfileArg) -> Self {
        match value {
            LogProfileArg::Product => Self::Product,
            LogProfileArg::FieldDebug => Self::FieldDebug,
            LogProfileArg::Development => Self::Development,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Login(LoginCommand),
    Controller(ControllerCommand),
    Agent(AgentCommand),
    Agents(AgentsCommand),
    Catalog(CatalogCommand),
    Jobs(JobsCommand),
    Approvals(ApprovalsCommand),
    Remediations(RemediationsCommand),
    Selectors(SelectorsCommand),
    Audit(AuditCommand),
    EnrollToken(EnrollTokenCommand),
    Run(RunCommand),
    Facts(FactsCommand),
    Metrics(MetricsCommand),
    Logs(LogsCommand),
    Drift(DriftCommand),
    Apply(ApplyCommand),
    Retention(RetentionCommand),
    Upgrade(UpgradeCommand),
    Demo(DemoCommand),
}

#[derive(Debug, Args)]
pub struct DemoCommand {
    #[arg(long)]
    keep_temp: bool,
    #[arg(long)]
    port: Option<u16>,
}

#[derive(Args)]
pub struct LoginCommand {
    #[arg(long)]
    controller_url: String,
    #[arg(
        long,
        conflicts_with = "token_stdin",
        help = "Legacy explicit token input; prefer the hidden prompt or --token-stdin to avoid shell history/process arguments"
    )]
    admin_token: Option<String>,
    #[arg(
        long,
        help = "Read one personal token from stdin through EOF; default is a hidden terminal prompt"
    )]
    token_stdin: bool,
    #[arg(
        long,
        help = "PEM public CA certificate for this Controller; saves its canonical path in this profile without changing system trust"
    )]
    tls_ca_cert: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_CLI_PROFILE_PATH)]
    profile_path: PathBuf,
}

impl std::fmt::Debug for LoginCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LoginCommand([REDACTED])")
    }
}

#[derive(Debug, Args, Clone)]
pub struct ProtectedApiArgs {
    #[arg(long)]
    pub controller_url: Option<String>,
    #[arg(long)]
    pub admin_token: Option<String>,
    #[arg(long, default_value = DEFAULT_CLI_PROFILE_PATH)]
    pub profile_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct ControllerCommand {
    #[command(subcommand)]
    pub command: ControllerSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ControllerSubcommand {
    Init {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
        #[arg(
            long,
            help = "The same SQLite database URL used by controller start --db"
        )]
        db: Option<String>,
    },
    #[command(about = "Manage personal administrators locally while the Controller is stopped")]
    Admin {
        #[command(subcommand)]
        command: ControllerAdminSubcommand,
    },
    #[command(
        about = "Start the Sponzey Fleet controller",
        long_about = "Start the Sponzey Fleet controller API, Web Admin UI, and agent gateway.\n\nThe bind host controls where the process listens. The external URL is the public URL agents and operators should use. Do not use 0.0.0.0 as an agent URL. HTTP URLs are allowed for tests only, but every HTTP use prints a warning because traffic is not encrypted. Product and production environments must use HTTPS.",
        after_help = "Examples:\n  Local loopback demo:\n    fleet controller start --host 127.0.0.1 --port 7700 --data-dir .fleet --external-url http://127.0.0.1:7700\n\n  Test-only HTTP remote controller with warning:\n    fleet controller start --host 0.0.0.0 --port 7700 --data-dir /var/lib/fleet --external-url http://192.168.0.10:7700\n\n  HTTPS behind DNS/reverse proxy:\n    fleet controller start --host 127.0.0.1 --port 7700 --data-dir /var/lib/fleet --external-url https://fleet.example.com\n\n  Built-in HTTPS listener:\n    fleet controller start --host 0.0.0.0 --port 7700 --data-dir /var/lib/fleet --external-url https://fleet.example.com --tls-cert /etc/fleet/tls/fullchain.pem --tls-key /etc/fleet/tls/privkey.pem"
    )]
    Start {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 7700)]
        port: u16,
        #[arg(
            long,
            help = "Public controller URL agents use; http:// is test-only and prints warnings"
        )]
        external_url: Option<String>,
        #[arg(
            long,
            help = "Controller database URL; sqlite:// works today, postgresql:// is recognized but not implemented yet"
        )]
        db: Option<String>,
        #[arg(long, help = "PEM certificate chain for built-in HTTPS listener")]
        tls_cert: Option<PathBuf>,
        #[arg(long, help = "PEM private key for built-in HTTPS listener")]
        tls_key: Option<PathBuf>,
        #[arg(
            long,
            help = "PEM CA certificate for future agent client-certificate mTLS; currently rejected until enforcement is implemented"
        )]
        agent_client_ca_cert: Option<PathBuf>,
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
    },
    InstallService {
        #[arg(long)]
        binary: Option<PathBuf>,
        #[arg(long, default_value = "/var/lib/fleet")]
        data_dir: PathBuf,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    StartService {
        #[arg(long)]
        dry_run: bool,
    },
    RestartService {
        #[arg(long)]
        dry_run: bool,
    },
    StatusService {
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Show controller signing rotation readiness status")]
    SigningRotationStatus {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    #[command(about = "Mutate controller signing rotation state")]
    SigningRotation {
        #[command(subcommand)]
        command: ControllerSigningRotationSubcommand,
    },
    LogsService {
        #[arg(long, default_value_t = 50)]
        lines: usize,
        #[arg(long)]
        dry_run: bool,
    },
    UninstallService {
        #[arg(long)]
        dry_run: bool,
    },
    #[command(
        about = "Create a controller data backup archive",
        long_about = "Create a JSON backup archive for the controller data under <data-dir>/controller.\n\nThe archive contains controller keys, SQLite data, metadata, and checksums. Treat it as sensitive because it contains enough controller state to restore the fleet."
    )]
    Backup {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
        #[arg(long, help = "Backup archive path to create")]
        output: PathBuf,
    },
    #[command(
        about = "Restore a controller data backup archive",
        long_about = "Restore a JSON backup archive into <data-dir>/controller.\n\nDry-run validates format, checksums, schema compatibility, and SQLite integrity without writing. Actual restore refuses to overwrite existing controller data unless --force is provided."
    )]
    Restore {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
        #[arg(long, help = "Backup archive path to restore")]
        input: PathBuf,
        #[arg(
            long,
            help = "Validate the archive and print the restore plan without writing"
        )]
        dry_run: bool,
        #[arg(
            long,
            help = "Allow replacing an existing non-empty controller data directory"
        )]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ControllerAdminSubcommand {
    #[command(
        about = "Initialize the first personal owner and disable the shared admin token atomically"
    )]
    InitOwner(ControllerOwnerInitArgs),
    #[command(
        about = "Recover a personal owner's access using local OS authority while the Controller is stopped"
    )]
    RecoverOwner(ControllerOwnerRecoveryArgs),
}

#[derive(Args)]
pub struct ControllerOwnerInitArgs {
    #[arg(long, default_value = ".fleet")]
    data_dir: PathBuf,
    #[arg(
        long,
        help = "The same SQLite database URL used by controller start --db"
    )]
    db: Option<String>,
    #[arg(long)]
    username: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(
        long,
        help = "Read one UTF-8 password through EOF from stdin instead of a hidden terminal prompt; never put passwords in arguments or environment variables"
    )]
    password_stdin: bool,
}

impl std::fmt::Debug for ControllerOwnerInitArgs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerOwnerInitArgs")
            .field("data_dir", &"[CONFIGURED]")
            .field("db", &self.db.as_ref().map(|_| "[CONFIGURED]"))
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("password_stdin", &self.password_stdin)
            .finish()
    }
}

#[derive(Args)]
pub struct ControllerOwnerRecoveryArgs {
    #[arg(long, default_value = ".fleet")]
    data_dir: PathBuf,
    #[arg(
        long,
        help = "The same SQLite database URL used by controller start --db"
    )]
    db: Option<String>,
    #[arg(
        long,
        help = "Immutable login name of the existing person whose owner access will be recovered"
    )]
    username: String,
    #[arg(
        long,
        help = "Read one UTF-8 password through EOF from stdin instead of hidden terminal confirmation"
    )]
    password_stdin: bool,
}

impl std::fmt::Debug for ControllerOwnerRecoveryArgs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerOwnerRecoveryArgs")
            .field("data_dir", &"[CONFIGURED]")
            .field("db", &self.db.as_ref().map(|_| "[CONFIGURED]"))
            .field("username", &self.username)
            .field("password_stdin", &self.password_stdin)
            .finish()
    }
}

#[derive(Debug, Subcommand)]
pub enum ControllerSigningRotationSubcommand {
    RestartPlan {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    RestartAction {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        confirm_external_restart: bool,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    Request {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        new_fingerprint: String,
        #[arg(long)]
        old_key_verifies_for_seconds: Option<u64>,
        #[arg(long)]
        old_key_verifies_until_ms: Option<u64>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    Validate {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        candidate_public_key_path: PathBuf,
        #[arg(long)]
        candidate_private_key_path: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    Activate {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    Retire {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    Fail {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    RolloutTrustBundle {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        previous_public_key_path: Option<PathBuf>,
        #[arg(long = "agent-id")]
        agent_ids: Vec<String>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    RetryTrustBundle {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        previous_public_key_path: Option<PathBuf>,
        #[arg(long = "agent-id")]
        agent_ids: Vec<String>,
        #[arg(long)]
        max_agent_count: Option<usize>,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
    StagedTrustBundle {
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        previous_public_key_path: Option<PathBuf>,
        #[arg(long = "agent-id")]
        agent_ids: Vec<String>,
        #[arg(long)]
        batch_size: usize,
        #[arg(long)]
        max_failures: usize,
        #[arg(long)]
        ack_timeout_seconds: u64,
        #[arg(long, help = "Print the secret-free JSON response")]
        json: bool,
    },
}

#[derive(Debug, Args)]
#[command(about = "Manage the local Sponzey Fleet agent")]
pub struct AgentCommand {
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AgentSubcommand {
    #[command(
        about = "Enroll this host as an agent",
        long_about = "Enroll this host with a controller using a one-time enrollment token.\n\nEnrollment writes the local agent identity, private key, labels, and pinned controller fingerprint under the selected data directory. Run this once before starting the agent.",
        visible_alias = "enroll",
        after_help = "Examples:\n  Local loopback development:\n    fleet agent init --url http://127.0.0.1:7700 --token <token> --name web-01 --labels role=web,env=dev\n\n  Test-only remote HTTP with warning:\n    fleet agent init --data-dir /var/lib/fleet --url http://192.168.0.10:7700 --token <token> --name test-web-01 --labels role=web,env=test\n\n  HTTPS:\n    fleet agent init --data-dir /var/lib/fleet --url https://fleet.example.com --token <token> --name prod-web-01 --labels role=web,env=prod\n\n  HTTPS with a private CA:\n    fleet agent init --data-dir /var/lib/fleet --url https://fleet.example.com --tls-ca-cert /etc/fleet/tls/ca.pem --token <token> --name prod-web-01"
    )]
    Init {
        #[arg(long, help = "Controller URL to enroll against")]
        url: String,
        #[arg(long, help = "One-time enrollment token created by the controller")]
        token: String,
        #[arg(long, help = "Human-readable agent name shown in inventory")]
        name: String,
        #[arg(
            long,
            default_value = "",
            help = "Comma-separated labels used for targeting, for example role=web,env=prod"
        )]
        labels: String,
        #[arg(
            long,
            help = "Additional PEM CA certificate used to trust a private/self-signed controller TLS endpoint"
        )]
        tls_ca_cert: Option<PathBuf>,
        #[arg(long, default_value = ".fleet", help = "Agent data directory")]
        data_dir: PathBuf,
    },
    #[command(
        about = "Start the enrolled local agent",
        long_about = "Start the enrolled local agent persistent session loop.\n\nThe agent reads its local identity from <data-dir>/agent/agent.conf, verifies the pinned controller fingerprint before opening the session, sends heartbeat liveness ticks, static facts inventory, metrics snapshots, and product-safe agent operational logs through one outbound writer queue, and receives controller-signed tasks on the same session. Heartbeat is only a liveness signal; facts, metrics, and logs each have their own bootstrap CLI interval. Connection failures are retried indefinitely by default. The agent must be enrolled before this command can run.",
        after_help = "Examples:\n  fleet agent start --data-dir .fleet\n  fleet agent start --data-dir /var/lib/fleet\n  fleet agent start --data-dir .fleet --once\n  fleet agent start --data-dir .fleet --facts-interval-seconds 300 --metrics-interval-seconds 30 --log-upload-interval-seconds 30\n\nLocal development flow:\n  fleet controller init --data-dir .fleet\n  fleet enroll-token create --data-dir .fleet --labels role=web,env=dev\n  fleet agent init --data-dir .fleet --url http://127.0.0.1:7700 --token <token> --name web-01 --labels role=web,env=dev\n  fleet agent start --data-dir .fleet"
    )]
    Start {
        #[arg(
            long,
            default_value = ".fleet",
            help = "Directory containing agent/agent.conf and agent/agent_private.key"
        )]
        data_dir: PathBuf,
        #[arg(
            long,
            help = "Send one heartbeat, process pending signed tasks once, then exit"
        )]
        once: bool,
        #[arg(
            long,
            default_value_t = 30,
            help = "Seconds between heartbeat liveness ticks; this does not control facts, metrics, log upload, or task dispatch"
        )]
        heartbeat_interval_seconds: u64,
        #[arg(
            long,
            default_value_t = 300,
            help = "Seconds between static inventory facts snapshots after the initial session snapshot"
        )]
        facts_interval_seconds: u64,
        #[arg(
            long,
            default_value_t = 30,
            help = "Seconds between usage metrics snapshots after the initial session snapshot"
        )]
        metrics_interval_seconds: u64,
        #[arg(long, help = "Disable periodic product-safe agent log upload")]
        disable_log_upload: bool,
        #[arg(
            long,
            default_value_t = 30,
            help = "Seconds between product-safe agent log uploads"
        )]
        log_upload_interval_seconds: u64,
        #[arg(
            long,
            default_value_t = 0,
            help = "Maximum reconnect attempts before exit; 0 means retry indefinitely"
        )]
        max_reconnect_attempts: u32,
    },
    #[command(
        about = "Install the agent as a systemd service",
        long_about = "Render or install the Linux systemd unit for running 'fleet agent start'.\n\nDry-run is safe on every platform. Writing service files requires Linux and root privileges."
    )]
    InstallService {
        #[arg(long, help = "Absolute fleet binary path to pin in the service unit")]
        binary: Option<PathBuf>,
        #[arg(
            long,
            default_value = "/var/lib/fleet",
            help = "Persistent agent data directory used by the service"
        )]
        data_dir: PathBuf,
        #[arg(long, help = "Linux service user")]
        user: Option<String>,
        #[arg(long, help = "Linux service group")]
        group: Option<String>,
        #[arg(long, help = "Print the unit file without writing system files")]
        dry_run: bool,
    },
    #[command(about = "Start the installed agent systemd service")]
    StartService {
        #[arg(long, help = "Print the systemctl command without executing it")]
        dry_run: bool,
    },
    #[command(about = "Show the installed agent systemd service status")]
    StatusService {
        #[arg(long, help = "Print the systemctl command without executing it")]
        dry_run: bool,
    },
    #[command(about = "Show recent installed agent service logs from journald")]
    LogsService {
        #[arg(long, default_value_t = 50, help = "Number of recent journald lines")]
        lines: usize,
        #[arg(long, help = "Print the journalctl command without executing it")]
        dry_run: bool,
    },
    #[command(about = "Disable and remove the installed agent systemd service")]
    UninstallService {
        #[arg(long, help = "Print the uninstall commands without executing them")]
        dry_run: bool,
    },
}

#[derive(Debug, Args)]
pub struct AgentsCommand {
    #[command(subcommand)]
    pub command: AgentsSubcommand,
}

#[derive(Debug, Args)]
pub struct CatalogCommand {
    #[command(subcommand)]
    pub command: CatalogSubcommand,
}
#[derive(Debug, Subcommand)]
pub enum CatalogSubcommand {
    List {
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Register {
        source_id: String,
        url: String,
        reference: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Sync {
        source_id: String,
        operation_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Activate {
        source_id: String,
        commit: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentsSubcommand {
    List {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
    },
    RemoteList {
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    RemoteGet {
        agent_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    RequestCertificateIssuance {
        agent_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        json: bool,
    },
    CertificateStatus {
        agent_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct JobsCommand {
    #[command(subcommand)]
    pub command: JobsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum JobsSubcommand {
    List {
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Get {
        job_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Output {
        job_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Cancel {
        job_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Args)]
pub struct ApprovalsCommand {
    #[command(subcommand)]
    pub command: ApprovalsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsSubcommand {
    List {
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Approve {
        approval_id: String,
        #[arg(long, default_value = "approved from CLI")]
        reason: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Reject {
        approval_id: String,
        #[arg(long, default_value = "rejected from CLI")]
        reason: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Args)]
pub struct RemediationsCommand {
    #[command(subcommand)]
    pub command: RemediationsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RemediationsSubcommand {
    List {
        #[arg(long)]
        agent_id: Option<String>,
        #[arg(long)]
        policy_id: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Get {
        remediation_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    RequestApproval {
        remediation_id: String,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long)]
        job_id: Option<String>,
        #[arg(long, default_value = "remediation requires approval")]
        reason: String,
        #[arg(long, default_value_t = REMOTE_RUN_EXPIRES_IN_SECONDS)]
        expires_in_seconds: u64,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Approve {
        remediation_id: String,
        #[arg(long)]
        approval_id: String,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        runbook: PathBuf,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = REMOTE_RUN_EXPIRES_IN_SECONDS)]
        expires_in_seconds: u64,
        #[arg(long)]
        nonce_prefix: Option<String>,
        #[arg(long, default_value = "approved remediation")]
        reason: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Running {
        remediation_id: String,
        #[arg(long)]
        job_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Result {
        remediation_id: String,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        status: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
    Verify {
        remediation_id: String,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        policy_name: String,
        #[arg(long)]
        job_id: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Args)]
pub struct SelectorsCommand {
    #[command(subcommand)]
    pub command: SelectorsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SelectorsSubcommand {
    Preview {
        #[arg(long)]
        selector: String,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Args)]
pub struct AuditCommand {
    #[command(subcommand)]
    pub command: AuditSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditSubcommand {
    Export {
        #[arg(long)]
        category: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        before: Option<String>,
        #[command(flatten)]
        api: ProtectedApiArgs,
    },
}

#[derive(Debug, Args)]
pub struct EnrollTokenCommand {
    #[command(subcommand)]
    pub command: EnrollTokenSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum EnrollTokenSubcommand {
    Create {
        #[arg(long, default_value = "")]
        labels: String,
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
        #[arg(long, default_value_t = 3600)]
        expires_in_seconds: u64,
        #[arg(long)]
        controller_url: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        print_init_command: bool,
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
    },
    List {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
    },
    Revoke {
        id: String,
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct RunCommand {
    #[arg(long)]
    pub selector: Option<String>,

    #[arg(long)]
    pub confirm_risk: bool,

    #[arg(long)]
    pub controller_url: Option<String>,

    #[arg(long)]
    pub admin_token: Option<String>,

    #[arg(long, default_value = DEFAULT_CLI_PROFILE_PATH)]
    pub profile_path: PathBuf,

    #[arg(long)]
    pub remote: bool,

    #[arg(long)]
    pub job_id: Option<String>,

    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,

    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct FactsCommand {
    pub agent: Option<String>,
}

#[derive(Debug, Args)]
pub struct MetricsCommand {
    pub agent: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApplyCommand {
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct RetentionCommand {
    #[command(subcommand)]
    pub command: RetentionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RetentionSubcommand {
    Cleanup {
        #[arg(long, default_value = ".fleet")]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 30)]
        older_than_days: u64,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Args)]
pub struct LogsCommand {
    pub target: Option<String>,

    #[arg(long)]
    pub file: Option<String>,

    #[arg(long)]
    pub follow: bool,

    #[arg(long)]
    pub max_duration_seconds: Option<u64>,
}

#[derive(Debug, Args)]
pub struct DriftCommand {
    #[command(subcommand)]
    pub command: DriftSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum DriftSubcommand {
    Check {
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Args)]
#[command(
    about = "Inspect the Sponzey Fleet upgrade plan",
    long_about = "Inspect the current upgrade policy without replacing the running binary.\n\nAutomatic self-upgrade is intentionally not implemented yet. Use --dry-run to see the required backup, artifact integrity, channel, and recovery steps before upgrading with an external package manager or release artifact."
)]
pub struct UpgradeCommand {
    #[arg(long, default_value = "stable")]
    channel: UpgradeChannelArg,
    #[arg(
        long,
        help = "Target version to inspect; defaults to latest in the channel"
    )]
    version: Option<String>,
    #[arg(long, help = "Print the upgrade plan without changing files")]
    dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum UpgradeChannelArg {
    Stable,
    Beta,
}

impl UpgradeChannelArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

#[derive(Debug)]
pub enum CliError {
    AdminInput(PasswordInputError),
    AdminIdentity(fleet_application::admin_identity::AdminAccessError),
    AdminLocalRequiresSqlite,
    MissingControllerSigningIdentity,
    InvalidControllerSigningIdentity,
    Io(std::io::Error),
    Controller(Box<fleet_controller::ControllerError>),
    Identity(fleet_core::IdentityError),
    Store(fleet_store::StoreError),
    Http(String),
    ControllerNotInitialized { data_dir: PathBuf },
    HighRiskConfirmationRequired,
    EmptyCommand,
    MissingPolicy,
    ServiceInstallRequiresDryRun,
    ServiceOperationRequiresLinux,
    ServiceOperationRequiresRoot,
    ServiceBinaryMustBeAbsolute(PathBuf),
    InvalidServiceAccount(String),
    UpgradeRequiresDryRun,
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdminInput(error) => Display::fmt(error, formatter),
            Self::AdminIdentity(error) => Display::fmt(error, formatter),
            Self::AdminLocalRequiresSqlite => formatter.write_str("local administrator commands require the same SQLite database as the Controller; Postgres Controller readiness is unsupported"),
            Self::MissingControllerSigningIdentity => formatter.write_str("personal Controller signing identity is missing; restore the original signing keys from backup"),
            Self::InvalidControllerSigningIdentity => formatter.write_str("Controller signing identity is invalid; restore the original signing keys from backup"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Controller(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "identity error: {error}"),
            Self::Store(error) => write!(formatter, "store error: {error:?}"),
            Self::Http(error) => write!(formatter, "http error: {error}"),
            Self::ControllerNotInitialized { data_dir } => {
                write!(
                    formatter,
                    "controller is not initialized for data dir: {}\n\nInitialize it once before starting the controller:\n\n  fleet controller init --data-dir \"{}\"\n  fleet controller start --host 127.0.0.1 --port 7700 --data-dir \"{}\" --external-url http://127.0.0.1:7700\n\nIf you use local scripts:\n\n  ./scripts/run_controller.sh --host 127.0.0.1 --port 7700 --data-dir \"{}\" --external-url http://127.0.0.1:7700",
                    data_dir.display(),
                    data_dir.display(),
                    data_dir.display(),
                    data_dir.display()
                )
            }
            Self::HighRiskConfirmationRequired => {
                write!(formatter, "high-risk command requires --confirm-risk")
            }
            Self::EmptyCommand => write!(formatter, "command cannot be empty"),
            Self::MissingPolicy => write!(formatter, "drift check requires --policy"),
            Self::ServiceInstallRequiresDryRun => {
                write!(
                    formatter,
                    "service install writes system files and requires Linux root; use --dry-run to inspect the unit first"
                )
            }
            Self::ServiceOperationRequiresLinux => {
                write!(formatter, "systemd service operations require Linux")
            }
            Self::ServiceOperationRequiresRoot => {
                write!(
                    formatter,
                    "systemd service operations require root; rerun with sudo"
                )
            }
            Self::ServiceBinaryMustBeAbsolute(path) => {
                write!(
                    formatter,
                    "service binary path must be absolute: {}",
                    path.display()
                )
            }
            Self::InvalidServiceAccount(value) => {
                write!(formatter, "invalid service user/group value: {value}")
            }
            Self::UpgradeRequiresDryRun => {
                write!(
                    formatter,
                    "automatic self-upgrade is not implemented; rerun with --dry-run to inspect the supported external upgrade plan"
                )
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<PasswordInputError> for CliError {
    fn from(value: PasswordInputError) -> Self {
        Self::AdminInput(value)
    }
}

impl From<fleet_application::admin_identity::AdminAccessError> for CliError {
    fn from(value: fleet_application::admin_identity::AdminAccessError) -> Self {
        Self::AdminIdentity(value)
    }
}

impl From<fleet_core::controller_data::ControllerDataError> for CliError {
    fn from(value: fleet_core::controller_data::ControllerDataError) -> Self {
        Self::from(fleet_controller::ControllerError::from(value))
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<fleet_store::StoreError> for CliError {
    fn from(value: fleet_store::StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<fleet_controller::ControllerError> for CliError {
    fn from(value: fleet_controller::ControllerError) -> Self {
        Self::Controller(Box::new(value))
    }
}

impl From<fleet_core::IdentityError> for CliError {
    fn from(value: fleet_core::IdentityError) -> Self {
        Self::Identity(value)
    }
}

pub fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.log_profile.into());

    match execute(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", format_error_message(error.to_string()));
            ExitCode::from(2)
        }
    }
}

pub fn execute(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Login(command) => execute_login(command),
        Command::Controller(command) => execute_controller(command),
        Command::Agent(command) => execute_agent(command),
        Command::Agents(command) => execute_agents(command),
        Command::Catalog(command) => execute_catalog(command),
        Command::Jobs(command) => execute_jobs(command),
        Command::Approvals(command) => execute_approvals(command),
        Command::Remediations(command) => execute_remediations(command),
        Command::Selectors(command) => execute_selectors(command),
        Command::Audit(command) => execute_audit(command),
        Command::EnrollToken(command) => execute_enroll_token(command),
        Command::Run(command) => execute_run(command),
        Command::Facts(command) => execute_facts(command),
        Command::Metrics(command) => execute_metrics(command),
        Command::Logs(command) => execute_logs(command),
        Command::Drift(command) => execute_drift(command),
        Command::Apply(command) => execute_apply(command),
        Command::Retention(command) => execute_retention(command),
        Command::Upgrade(command) => execute_upgrade(command),
        Command::Demo(command) => execute_demo(command),
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliProfile {
    controller_url: String,
    admin_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_ca_cert: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
struct ProtectedApiClient {
    controller_url: String,
    admin_token: String,
    tls_ca_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for CliProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CliProfile([REDACTED])")
    }
}

impl std::fmt::Debug for ProtectedApiClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedApiClient([REDACTED])")
    }
}

impl Drop for CliProfile {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.admin_token);
    }
}

impl Drop for ProtectedApiClient {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.admin_token);
    }
}

fn execute_login(command: LoginCommand) -> Result<(), CliError> {
    let controller_url = canonical_profile_url(&command.controller_url)?;
    let tls_ca_cert = command
        .tls_ca_cert
        .as_deref()
        .map(|path| {
            fs::canonicalize(path)
                .map_err(|_| CliError::Http("could not resolve CLI public CA certificate".into()))
        })
        .transpose()?;
    let tls_ca_pem = read_profile_ca(tls_ca_cert.as_deref())?;
    let legacy_input = command.admin_token.is_some();
    let token = match command.admin_token {
        Some(token) => zeroize::Zeroizing::new(token),
        None => admin_password_input::read_personal_token(command.token_stdin)
            .map_err(|_| CliError::Http("personal token input failed; use the hidden terminal prompt or --token-stdin with one token followed by EOF".into()))?,
    };
    validate_profile_token(&token)?;
    if !legacy_input {
        validate_personal_token(&token)?;
    }
    if token.starts_with("fpat_") {
        // Verify current server authority before replacing an existing profile.
        let client = ProtectedApiClient {
            controller_url: controller_url.clone(),
            admin_token: token.to_string(),
            tls_ca_pem,
        };
        let body = zeroize::Zeroizing::new(client.get("/api/auth/session")?);
        let session: serde_json::Value = serde_json::from_str(&body)
            .map_err(|_| CliError::Http("invalid personal session response".into()))?;
        if session
            .get("user")
            .and_then(|user| user.get("id"))
            .and_then(|id| id.as_str())
            .is_none()
            || session
                .get("expires_at")
                .and_then(|expiry| expiry.as_u64())
                .is_none()
            || session.get("csrf_token") != Some(&serde_json::Value::Null)
        {
            return Err(CliError::Http("invalid personal session response".into()));
        }
    }
    let profile = CliProfile {
        controller_url,
        admin_token: token.to_string(),
        tls_ca_cert,
    };
    save_cli_profile(&command.profile_path, &profile)?;
    println!("profile_path={}", command.profile_path.display());
    println!("controller_url={}", profile.controller_url);
    println!("status=created");
    Ok(())
}

fn save_cli_profile(path: &Path, profile: &CliProfile) -> Result<(), CliError> {
    canonical_profile_url(&profile.controller_url)?;
    validate_profile_token(&profile.admin_token)?;
    if fs::symlink_metadata(path).is_ok() {
        ensure_secure_profile_permissions(path)?;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(parent)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(CliError::Http("CLI profile directory must be owned by the current user and not writable by others".into()));
        }
    }
    let body = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(profile)
            .map_err(|_| CliError::Http("could not serialize CLI profile".into()))?,
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(body.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| CliError::Http("could not atomically save CLI profile".into()))?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_cli_profile(path: &Path) -> Result<CliProfile, CliError> {
    ensure_secure_profile_permissions(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options.open(path)?;
    validate_profile_metadata(&file.metadata()?)?;
    let mut body = zeroize::Zeroizing::new(String::new());
    file.take(16_385)
        .read_to_string(&mut body)
        .map_err(|_| CliError::Http("could not read CLI profile".into()))?;
    if body.len() > 16_384 {
        return Err(CliError::Http("CLI profile exceeds the size limit".into()));
    }
    let mut profile: CliProfile = serde_json::from_str(&body).map_err(|_| {
        CliError::Http("invalid CLI profile; save a new profile with fleet login".into())
    })?;
    profile.controller_url = canonical_profile_url(&profile.controller_url)?;
    validate_profile_token(&profile.admin_token)?;
    Ok(profile)
}

fn ensure_secure_profile_permissions(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::Http(format!(
                "CLI profile not found: {}; run `fleet login --controller-url <url>` and enter your personal token at the hidden prompt",
                path.display()
            ))
        } else {
            CliError::Io(error)
        }
    })?;
    validate_profile_metadata(&metadata)
}

fn validate_profile_metadata(metadata: &fs::Metadata) -> Result<(), CliError> {
    if !metadata.is_file() {
        return Err(CliError::Http(
            "CLI profile must be a regular file, not a symlink".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.permissions().mode();
        if mode & 0o7777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(CliError::Http("CLI profile has insecure ownership, links or permissions; expected an owned mode 600 file".into()));
        }
    }
    Ok(())
}

fn canonical_profile_url(raw: &str) -> Result<String, CliError> {
    let invalid = || {
        CliError::Http("controller URL must be an HTTP(S) origin without credentials, path, query, fragment or wildcard host".into())
    };
    if raw.len() > 2048 || raw.contains('\\') || raw.chars().any(char::is_whitespace) {
        return Err(invalid());
    }
    let url = reqwest::Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err(invalid());
    }
    let canonical = url.origin().ascii_serialization();
    parse_controller_url(&canonical).map_err(|_| invalid())?;
    Ok(canonical)
}

fn validate_profile_token(token: &str) -> Result<(), CliError> {
    if token.is_empty()
        || token.len() > 1024
        || !token.bytes().all(|value| value.is_ascii_graphic())
    {
        return Err(CliError::Http(
            "invalid CLI token input; expected one nonempty token without whitespace".into(),
        ));
    }
    Ok(())
}

fn validate_personal_token(token: &str) -> Result<(), CliError> {
    if !token.strip_prefix("fpat_").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|v| v.is_ascii_digit() || matches!(v, b'a'..=b'f'))
    }) {
        return Err(CliError::Http("enter the personal token shown in Settings > My account; passwords and web session cookies cannot be used as CLI tokens".into()));
    }
    Ok(())
}

/// Loads one bounded public CA at CLI bootstrap; request effects use these immutable bytes.
fn read_profile_ca(path: Option<&Path>) -> Result<Option<Vec<u8>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let invalid = || {
        CliError::Http("invalid CLI public CA certificate; expected a regular PEM certificate file of at most 16 KiB".into())
    };
    if path.as_os_str().len() > 2048 {
        return Err(invalid());
    }
    if !fs::metadata(path).map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    let file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > 16_384 {
        return Err(invalid());
    }
    let mut pem = zeroize::Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(16_385)
        .read_to_end(&mut pem)
        .map_err(|_| invalid())?;
    if pem.len() > 16_384 {
        return Err(invalid());
    }
    let mut reader = BufReader::new(pem.as_slice());
    let items = rustls_pemfile::read_all(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if items.is_empty() {
        return Err(invalid());
    }
    let mut roots = RootCertStore::empty();
    for item in items {
        let rustls_pemfile::Item::X509Certificate(certificate) = item else {
            return Err(invalid());
        };
        roots.add(certificate).map_err(|_| invalid())?;
    }
    Ok(Some(pem.to_vec()))
}

fn resolve_protected_api(args: &ProtectedApiArgs) -> Result<ProtectedApiClient, CliError> {
    let profile_needed = args.controller_url.is_none() || args.admin_token.is_none();
    let profile = if profile_needed {
        Some(read_cli_profile(&args.profile_path)?)
    } else {
        None
    };
    let controller_url = args
        .controller_url
        .clone()
        .or_else(|| {
            profile
                .as_ref()
                .map(|profile| profile.controller_url.clone())
        })
        .ok_or_else(|| CliError::Http("--controller-url is required".to_owned()))?;
    let controller_url = canonical_profile_url(&controller_url)?;
    if args.admin_token.is_none()
        && profile
            .as_ref()
            .is_some_and(|p| p.controller_url != controller_url)
    {
        return Err(CliError::Http("saved CLI token belongs to a different Controller URL; run fleet login for this server".into()));
    }
    let admin_token = args
        .admin_token
        .clone()
        .or_else(|| profile.as_ref().map(|profile| profile.admin_token.clone()))
        .ok_or_else(|| CliError::Http("--admin-token is required".to_owned()))?;
    validate_profile_token(&admin_token)?;
    Ok(ProtectedApiClient {
        controller_url,
        admin_token,
        tls_ca_pem: read_profile_ca(profile.as_ref().and_then(|p| p.tls_ca_cert.as_deref()))?,
    })
}

fn run_command_api_args(command: &RunCommand) -> ProtectedApiArgs {
    ProtectedApiArgs {
        controller_url: command.controller_url.clone(),
        admin_token: command.admin_token.clone(),
        profile_path: command.profile_path.clone(),
    }
}

impl ProtectedApiClient {
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, CliError> {
        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = &self.tls_ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem)
                .map_err(|_| CliError::Http("invalid CLI public CA certificate".into()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder
            .build()
            .map_err(|_| CliError::Http("could not initialize protected HTTP client".into()))?;
        let response = http_request_url_with_client(
            &client,
            &self.controller_url,
            method,
            path,
            Some(&self.admin_token),
            body,
        )?;
        protected_response_body(&response, &[200, 201, 202])
    }

    fn get(&self, path: &str) -> Result<String, CliError> {
        self.request("GET", path, None)
    }

    fn post(&self, path: &str, body: Option<&str>) -> Result<String, CliError> {
        self.request("POST", path, body)
    }
}

fn protected_response_body(response: &str, success_codes: &[u16]) -> Result<String, CliError> {
    let status = http_response_status_code(response).unwrap_or(0);
    if success_codes.contains(&status) {
        return Ok(http_response_body(response).to_owned());
    }
    Err(CliError::Http(render_http_status_error(status)))
}

fn http_response_status_code(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn http_response_body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or_default()
}

fn render_http_status_error(status: u16) -> String {
    match status {
        401 => "unauthorized: credential is missing, invalid, expired or revoked; create a personal token in Settings > My account and run fleet login again".to_owned(),
        403 => "forbidden: your account lacks the required permission".to_owned(),
        404 => "not found: requested resource does not exist".to_owned(),
        409 => "conflict: request conflicts with current state".to_owned(),
        0 => "request failed: malformed HTTP response".to_owned(),
        _ => format!("request failed: HTTP {status}"),
    }
}

fn print_json_response(body: &str) -> Result<(), CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json).map_err(|error| CliError::Http(error.to_string()))?
    );
    Ok(())
}

fn render_agent_certificate_issuance_request_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    Ok(vec![
        format!(
            "agent_id={}\taction={}\tstate={}",
            json_field(&json, "agent_id"),
            json_field(&json, "action"),
            json_field(&json, "lifecycle_state")
        ),
        format!(
            "dispatch_status={}\taudit_event_action={}",
            json_field(&json, "dispatch_status"),
            json_field(&json, "audit_event_action")
        ),
        format!(
            "current_fingerprint_prefix={}\tnext_fingerprint_prefix={}",
            json_optional_field(&json, "current_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned()),
            json_optional_field(&json, "next_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned())
        ),
    ])
}

fn render_agent_certificate_lifecycle_status_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    Ok(vec![
        format!(
            "agent_id={}\tstate={}\trecord_present={}",
            json_field(&json, "agent_id"),
            json_field(&json, "lifecycle_state"),
            json_field(&json, "record_present")
        ),
        format!(
            "current_fingerprint_prefix={}\tnext_fingerprint_prefix={}",
            json_optional_field(&json, "current_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned()),
            json_optional_field(&json, "next_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned())
        ),
        format!(
            "grace_until_ms={}\trevocation_reason={}\tupdated_at_ms={}",
            json_optional_number(&json, "grace_until_ms")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            json_optional_field(&json, "revocation_reason").unwrap_or_else(|| "none".to_owned()),
            json_optional_number(&json, "updated_at_ms")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned())
        ),
    ])
}

fn render_controller_signing_rotation_status_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "controller_id={}\tstate={}\treadiness={}",
            json_field(&json, "controller_id"),
            json_field(&json, "persisted_state"),
            json_field(&json, "readiness")
        ),
        format!(
            "active_signing_fingerprint_prefix={}\tselected_signing_fingerprint_prefix={}",
            json_field(&json, "active_signing_fingerprint_prefix"),
            json_field(&json, "selected_signing_fingerprint_prefix")
        ),
        format!(
            "old_fingerprint_prefix={}\tnew_fingerprint_prefix={}",
            json_field(&json, "old_fingerprint_prefix"),
            json_optional_field(&json, "new_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned())
        ),
        format!(
            "bootstrap_guard={}\tagent_trust_rollout={}",
            json_field(&json, "bootstrap_guard"),
            json_field(&json, "agent_trust_rollout")
        ),
    ];
    if let Some(window) = json_optional_number(&json, "old_key_verifies_until_ms") {
        lines.push(format!("old_key_verifies_until_ms={window}"));
    }
    Ok(lines)
}

fn render_controller_signing_rotation_restart_plan_for_cli(
    body: &str,
) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "controller_id={}\trestart_required={}\treload_supported={}",
            json_field(&json, "controller_id"),
            json_field(&json, "restart_required"),
            json_field(&json, "reload_supported")
        ),
        format!(
            "recommended_action={}\treadiness={}",
            json_field(&json, "recommended_action"),
            json_field(&json, "readiness")
        ),
        format!(
            "bootstrap_guard={}\tagent_trust_rollout={}",
            json_field(&json, "bootstrap_guard"),
            json_field(&json, "agent_trust_rollout")
        ),
        format!(
            "active_signing_fingerprint_prefix={}\tselected_signing_fingerprint_prefix={}",
            json_field(&json, "active_signing_fingerprint_prefix"),
            json_field(&json, "selected_signing_fingerprint_prefix")
        ),
    ];
    if let Some(reason) = json_optional_field(&json, "blocked_reason") {
        lines.push(format!("blocked_reason={reason}"));
    }
    append_json_string_array_lines(
        &mut lines,
        &json,
        "verification_commands",
        "verification_command",
    );
    append_json_string_array_lines(&mut lines, &json, "safety_notes", "safety_note");
    Ok(lines)
}

fn render_controller_signing_rotation_restart_action_for_cli(
    body: &str,
) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "controller_id={}\taction={}",
            json_field(&json, "controller_id"),
            json_field(&json, "action")
        ),
        format!(
            "action_status={}\trestart_required={}\treload_supported={}",
            json_field(&json, "action_status"),
            json_field(&json, "restart_required"),
            json_field(&json, "reload_supported")
        ),
        format!(
            "readiness={}\tbootstrap_guard={}",
            json_field(&json, "readiness"),
            json_field(&json, "bootstrap_guard")
        ),
        format!(
            "active_signing_fingerprint_prefix={}\tselected_signing_fingerprint_prefix={}",
            json_field(&json, "active_signing_fingerprint_prefix"),
            json_field(&json, "selected_signing_fingerprint_prefix")
        ),
        format!("service_command={}", json_field(&json, "service_command")),
    ];
    append_json_string_array_lines(
        &mut lines,
        &json,
        "verification_commands",
        "verification_command",
    );
    append_json_string_array_lines(&mut lines, &json, "safety_notes", "safety_note");
    Ok(lines)
}

fn render_controller_signing_trust_bundle_rollout_for_cli(
    body: &str,
) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "controller_id={}\tstate={}",
            json_field(&json, "controller_id"),
            json_field(&json, "persisted_state")
        ),
        format!(
            "attempted_count={}\tupdated_count={}\tskipped_count={}\tfailed_count={}",
            json_field(&json, "attempted_count"),
            json_field(&json, "updated_count"),
            json_field(&json, "skipped_count"),
            json_field(&json, "failed_count")
        ),
        format!(
            "entries_count={}\tcurrent_fingerprint_prefix={}\tprevious_fingerprint_prefix={}",
            json_field(&json, "entries_count"),
            json_field(&json, "current_fingerprint_prefix"),
            json_optional_field(&json, "previous_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned())
        ),
    ];
    if let Some(results) = json.get("agent_results").and_then(|value| value.as_array()) {
        for result in results {
            lines.push(format!(
                "agent_id={}\tstatus={}",
                json_field(result, "agent_id"),
                json_field(result, "status")
            ));
        }
    }
    Ok(lines)
}

fn render_controller_signing_trust_bundle_staged_rollout_for_cli(
    body: &str,
) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "controller_id={}\tstate={}\trollout_state={}",
            json_field(&json, "controller_id"),
            json_field(&json, "persisted_state"),
            json_field(&json, "rollout_state")
        ),
        format!(
            "target_count={}\tplanned_count={}\tattempted_count={}\tupdated_count={}",
            json_field(&json, "target_count"),
            json_field(&json, "planned_count"),
            json_field(&json, "attempted_count"),
            json_field(&json, "updated_count")
        ),
        format!(
            "skipped_count={}\tfailed_count={}\talready_current_count={}\tunavailable_count={}\tpending_count={}",
            json_field(&json, "skipped_count"),
            json_field(&json, "failed_count"),
            json_field(&json, "already_current_count"),
            json_field(&json, "unavailable_count"),
            json_field(&json, "pending_count")
        ),
        format!(
            "entries_count={}\tcurrent_fingerprint_prefix={}\tprevious_fingerprint_prefix={}",
            json_field(&json, "entries_count"),
            json_field(&json, "current_fingerprint_prefix"),
            json_optional_field(&json, "previous_fingerprint_prefix")
                .unwrap_or_else(|| "none".to_owned())
        ),
    ];
    if let Some(results) = json.get("agent_results").and_then(|value| value.as_array()) {
        for result in results {
            lines.push(format!(
                "agent_id={}\tstatus={}",
                json_field(result, "agent_id"),
                json_field(result, "status")
            ));
        }
    }
    Ok(lines)
}

fn append_json_string_array_lines(
    lines: &mut Vec<String>,
    json: &serde_json::Value,
    field: &str,
    label: &str,
) {
    let Some(values) = json.get(field).and_then(|value| value.as_array()) else {
        return;
    };
    for value in values.iter().filter_map(|value| value.as_str()) {
        lines.push(format!("{label}={value}"));
    }
}

fn json_optional_number(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

fn execute_controller(command: ControllerCommand) -> Result<(), CliError> {
    match command.command {
        ControllerSubcommand::Init { data_dir, db } => {
            use fleet_application::admin_identity::AdminIdentityRead;
            let database = parse_controller_database_settings(db.as_deref(), &data_dir)?;
            let database_path = database
                .sqlite_path()
                .ok_or(CliError::AdminLocalRequiresSqlite)?;
            let _lease = fleet_core::controller_data::ControllerDataLease::acquire(&data_dir)?;
            admin_local::prepare_controller_dir(&data_dir)?;
            fs::create_dir_all(agent_dir(&data_dir))?;
            let store = fleet_store::SqliteStore::open(database_path)?;
            let mode = store.auth_state()?.mode;
            let controller_fingerprint = admin_local::bootstrap_signing_identity(&data_dir, mode)?;
            println!("controller initialized at {}", data_dir.display());
            println!("controller fingerprint: {controller_fingerprint}");
            if mode != fleet_domain::AdminAuthMode::LegacyBootstrap {
                println!("personal administrator mode: shared admin token disabled");
            } else if let Some(admin_token) = fleet_controller::create_admin_token(&store)? {
                println!("admin token: {admin_token}");
            } else {
                println!("admin token: already initialized");
            }
            Ok(())
        }
        ControllerSubcommand::Admin {
            command: ControllerAdminSubcommand::InitOwner(args),
        } => {
            let account = admin_local::initialize_owner_with(&args, || {
                admin_password_input::read_new_password(args.password_stdin)
            })?;
            println!(
                "owner initialized: id={} username={}",
                account.id.as_str(),
                account.username.as_str()
            );
            println!("personal administrator mode enabled; shared admin token disabled");
            Ok(())
        }
        ControllerSubcommand::Admin {
            command: ControllerAdminSubcommand::RecoverOwner(args),
        } => {
            let account = admin_local::recover_owner_with(&args, || {
                admin_password_input::read_new_password(args.password_stdin)
            })?;
            println!(
                "owner access recovered: id={} username={}",
                account.id.as_str(),
                account.username.as_str()
            );
            println!(
                "previous sessions, personal tokens and unused setup codes for this person are invalid"
            );
            Ok(())
        }
        ControllerSubcommand::Start {
            host,
            port,
            external_url,
            db,
            tls_cert,
            tls_key,
            agent_client_ca_cert,
            data_dir,
        } => {
            let database = parse_controller_database_settings(db.as_deref(), &data_dir)?;
            ensure_controller_initialized_for_start(&data_dir)?;
            fleet_controller::start_controller_server(fleet_controller::ControllerServerConfig {
                host,
                port,
                external_url,
                tls_cert_path: tls_cert,
                tls_key_path: tls_key,
                agent_client_ca_cert_path: agent_client_ca_cert,
                data_dir,
                database: Some(database),
                secret_provider: None,
            })?;
            Ok(())
        }
        ControllerSubcommand::InstallService {
            binary,
            data_dir,
            user,
            group,
            dry_run,
        } => {
            let unit = render_service_unit(
                ServiceRole::Controller,
                &resolve_service_binary(binary)?,
                &data_dir,
                user.as_deref(),
                group.as_deref(),
            )?;
            if !dry_run {
                install_systemd_service(ServiceRole::Controller, &unit)?;
                return Ok(());
            }
            print!("{unit}");
            Ok(())
        }
        ControllerSubcommand::StartService { dry_run } => {
            start_systemd_service(ServiceRole::Controller, dry_run)
        }
        ControllerSubcommand::RestartService { dry_run } => {
            restart_systemd_service(ServiceRole::Controller, dry_run)
        }
        ControllerSubcommand::StatusService { dry_run } => {
            status_systemd_service(ServiceRole::Controller, dry_run)
        }
        ControllerSubcommand::SigningRotationStatus { api, json } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get("/api/controller/signing-rotation/status")?;
            if json {
                return print_json_response(&body);
            }
            for line in render_controller_signing_rotation_status_for_cli(&body)? {
                println!("{line}");
            }
            Ok(())
        }
        ControllerSubcommand::SigningRotation { command } => {
            execute_controller_signing_rotation(command)
        }
        ControllerSubcommand::LogsService { lines, dry_run } => {
            logs_systemd_service(ServiceRole::Controller, lines, dry_run)
        }
        ControllerSubcommand::UninstallService { dry_run } => {
            uninstall_systemd_service(ServiceRole::Controller, dry_run)
        }
        ControllerSubcommand::Backup { data_dir, output } => {
            execute_controller_backup(&data_dir, &output)
        }
        ControllerSubcommand::Restore {
            data_dir,
            input,
            dry_run,
            force,
        } => execute_controller_restore(&data_dir, &input, dry_run, force),
    }
}

fn execute_controller_signing_rotation(
    command: ControllerSigningRotationSubcommand,
) -> Result<(), CliError> {
    let (api, path, body, json) = match command {
        ControllerSigningRotationSubcommand::RestartPlan { api, json } => {
            let client = resolve_protected_api(&api)?;
            let response = client.get("/api/controller/signing-rotation/restart-plan")?;
            if json {
                return print_json_response(&response);
            }
            for line in render_controller_signing_rotation_restart_plan_for_cli(&response)? {
                println!("{line}");
            }
            return Ok(());
        }
        ControllerSigningRotationSubcommand::RestartAction {
            api,
            confirm_external_restart,
            reason,
            json,
        } => (
            api,
            "/api/controller/signing-rotation/restart-action",
            serde_json::json!({
                "confirm_external_restart": confirm_external_restart,
                "reason": reason
            })
            .to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::Request {
            api,
            new_fingerprint,
            old_key_verifies_for_seconds,
            old_key_verifies_until_ms,
            reason,
            json,
        } => (
            api,
            "/api/controller/signing-rotation/request",
            serde_json::json!({
                "new_fingerprint": new_fingerprint,
                "old_key_verifies_for_seconds": old_key_verifies_for_seconds,
                "old_key_verifies_until_ms": old_key_verifies_until_ms,
                "reason": reason,
            })
            .to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::Validate {
            api,
            candidate_public_key_path,
            candidate_private_key_path,
            reason,
            json,
        } => (
            api,
            "/api/controller/signing-rotation/validate",
            serde_json::json!({
                "candidate_public_key_path": candidate_public_key_path,
                "candidate_private_key_path": candidate_private_key_path,
                "reason": reason,
            })
            .to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::Activate { api, reason, json } => (
            api,
            "/api/controller/signing-rotation/activate",
            serde_json::json!({ "reason": reason }).to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::Retire { api, reason, json } => (
            api,
            "/api/controller/signing-rotation/retire",
            serde_json::json!({ "reason": reason }).to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::Fail { api, reason, json } => (
            api,
            "/api/controller/signing-rotation/fail",
            serde_json::json!({ "reason": reason }).to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::RolloutTrustBundle {
            api,
            previous_public_key_path,
            agent_ids,
            json,
        } => (
            api,
            "/api/controller/signing-rotation/rollout-trust-bundle",
            serde_json::json!({
                "previous_public_key_path": previous_public_key_path,
                "agent_ids": agent_ids
            })
            .to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::RetryTrustBundle {
            api,
            previous_public_key_path,
            agent_ids,
            max_agent_count,
            json,
        } => (
            api,
            "/api/controller/signing-rotation/rollout-trust-bundle/retry",
            serde_json::json!({
                "previous_public_key_path": previous_public_key_path,
                "agent_ids": agent_ids,
                "max_agent_count": max_agent_count
            })
            .to_string(),
            json,
        ),
        ControllerSigningRotationSubcommand::StagedTrustBundle {
            api,
            previous_public_key_path,
            agent_ids,
            batch_size,
            max_failures,
            ack_timeout_seconds,
            json,
        } => (
            api,
            CONTROLLER_SIGNING_STAGED_TRUST_BUNDLE_PATH,
            controller_signing_staged_trust_bundle_request_body(
                previous_public_key_path,
                agent_ids,
                batch_size,
                max_failures,
                ack_timeout_seconds,
            ),
            json,
        ),
    };
    let client = resolve_protected_api(&api)?;
    let response = client.post(path, Some(&body))?;
    if json {
        return print_json_response(&response);
    }
    if path == "/api/controller/signing-rotation/restart-action" {
        for line in render_controller_signing_rotation_restart_action_for_cli(&response)? {
            println!("{line}");
        }
        return Ok(());
    }
    if path == "/api/controller/signing-rotation/rollout-trust-bundle"
        || path == "/api/controller/signing-rotation/rollout-trust-bundle/retry"
    {
        for line in render_controller_signing_trust_bundle_rollout_for_cli(&response)? {
            println!("{line}");
        }
        return Ok(());
    }
    if path == CONTROLLER_SIGNING_STAGED_TRUST_BUNDLE_PATH {
        for line in render_controller_signing_trust_bundle_staged_rollout_for_cli(&response)? {
            println!("{line}");
        }
        return Ok(());
    }
    for line in render_controller_signing_rotation_status_for_cli(&response)? {
        println!("{line}");
    }
    Ok(())
}

fn controller_signing_staged_trust_bundle_request_body(
    previous_public_key_path: Option<PathBuf>,
    agent_ids: Vec<String>,
    batch_size: usize,
    max_failures: usize,
    ack_timeout_seconds: u64,
) -> String {
    serde_json::json!({
        "previous_public_key_path": previous_public_key_path,
        "agent_ids": agent_ids,
        "batch_size": batch_size,
        "max_failures": max_failures,
        "ack_timeout_seconds": ack_timeout_seconds
    })
    .to_string()
}

const CONTROLLER_BACKUP_FORMAT: &str = "fleet-controller-backup";
const CONTROLLER_BACKUP_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
struct ControllerBackupArchive {
    format: String,
    format_version: u32,
    package_version: String,
    created_at_ms: u64,
    source_data_dir: String,
    schema_version: i64,
    sqlite_integrity_check: String,
    files: Vec<ControllerBackupFile>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ControllerBackupFile {
    path: String,
    size_bytes: u64,
    sha256: String,
    content_hex: String,
}

impl std::fmt::Debug for ControllerBackupArchive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerBackupArchive")
            .field("format_version", &self.format_version)
            .field("schema_version", &self.schema_version)
            .field("file_count", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ControllerBackupFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerBackupFile")
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for ControllerBackupFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.content_hex.zeroize();
    }
}

fn execute_controller_backup(data_dir: &Path, output: &Path) -> Result<(), CliError> {
    let _lease = fleet_core::controller_data::ControllerDataLease::acquire(data_dir)?;
    directory_exists_and_is_non_empty(&controller_dir(data_dir))?;
    ensure_controller_initialized_for_start(data_dir)?;
    let db_path = controller_db_path(data_dir);
    if !db_path.is_file() {
        return Err(CliError::Http(format!(
            "controller database was not found: {}",
            db_path.display()
        )));
    }
    let snapshot = fleet_store::sqlite_snapshot::inspect_quiescent_sqlite_snapshot(&db_path)
        .map_err(|error| CliError::Http(error.to_string()))?;
    let archive = build_controller_backup_archive(data_dir, snapshot.schema_version, "ok".into())?;
    validate_backup_archive(&archive)?;
    verify_backup_snapshot(&archive)?;
    write_backup_archive(output, &archive)?;
    println!("backup_archive={}", output.display());
    println!("format={}", archive.format);
    println!("format_version={}", archive.format_version);
    println!("schema_version={}", archive.schema_version);
    println!("file_count={}", archive.files.len());
    println!(
        "{}",
        format_warning_message(
            "backup contains sensitive controller state; store it securely and do not share it",
        )
    );
    Ok(())
}

fn execute_controller_restore(
    data_dir: &Path,
    input: &Path,
    dry_run: bool,
    force: bool,
) -> Result<(), CliError> {
    let lease = if dry_run {
        None
    } else {
        Some(fleet_core::controller_data::ControllerDataLease::acquire(
            data_dir,
        )?)
    };
    let archive = read_backup_archive(input)?;
    validate_backup_archive(&archive)?;
    if archive.schema_version > fleet_store::CURRENT_SCHEMA_VERSION {
        return Err(CliError::Http(format!(
            "backup schema version {} is newer than this binary supports ({})",
            archive.schema_version,
            fleet_store::CURRENT_SCHEMA_VERSION
        )));
    }
    verify_backup_snapshot(&archive)?;
    let target_controller_dir = controller_dir(data_dir);
    let existing_non_empty = directory_exists_and_is_non_empty(&target_controller_dir)?;
    if dry_run {
        println!("restore_dry_run=true");
        println!("input={}", input.display());
        println!("target_data_dir={}", data_dir.display());
        println!("schema_version={}", archive.schema_version);
        println!("file_count={}", archive.files.len());
        println!("would_overwrite={existing_non_empty}");
        return Ok(());
    }
    if existing_non_empty && !force {
        return Err(CliError::Http(format!(
            "refusing to overwrite existing controller data dir {}; rerun with --force after taking a backup",
            target_controller_dir.display()
        )));
    }

    let mut builder = tempfile::Builder::new();
    builder.prefix(".fleet-restore-");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o700));
    // Unique, owned, private and on the target filesystem. Never delete a guessed staging path.
    let temporary = builder.tempdir_in(data_dir)?;
    restore_archive_into_temp_dir(&archive, temporary.path())?;
    let lease = lease
        .as_ref()
        .ok_or_else(|| CliError::Http("restore requires a local data lease".into()))?;
    verify_restored_controller_dir(temporary.path(), lease)?;
    sync_restore_tree(temporary.path())?;
    replace_controller_dir(data_dir, temporary.path(), force)?;
    // The exchange above is the commit point. A later sync/cleanup failure must never report
    // the previous target as still installed or attempt an unguarded reverse exchange.
    match finalize_controller_restore(data_dir, temporary) {
        RestoreFinalization::Complete => {}
        RestoreFinalization::DurabilityUnconfirmed => println!(
            "{}",
            format_warning_message(
                "restore is installed, but directory durability could not be confirmed; private rollback staging was retained; keep the Controller stopped and inspect the backup before restarting"
            )
        ),
        RestoreFinalization::CleanupPending => println!(
            "{}",
            format_warning_message(
                "restore is installed; cleanup of its private old snapshot is pending"
            )
        ),
    }
    println!("restore_dry_run=false");
    println!("restored_data_dir={}", data_dir.display());
    println!("schema_version={}", fleet_store::CURRENT_SCHEMA_VERSION);
    println!("backup_schema_version={}", archive.schema_version);
    println!("file_count={}", archive.files.len());
    println!(
        "{}",
        format_warning_message(
            "restored backup contains controller secrets; verify filesystem permissions before production use",
        )
    );
    Ok(())
}

fn build_controller_backup_archive(
    data_dir: &Path,
    schema_version: i64,
    sqlite_integrity_check: String,
) -> Result<ControllerBackupArchive, CliError> {
    let files = collect_controller_backup_files(data_dir)?;
    Ok(ControllerBackupArchive {
        format: CONTROLLER_BACKUP_FORMAT.to_owned(),
        format_version: CONTROLLER_BACKUP_FORMAT_VERSION,
        package_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_at_ms: epoch_millis() as u64,
        source_data_dir: data_dir.display().to_string(),
        schema_version,
        sqlite_integrity_check,
        files,
    })
}

fn collect_controller_backup_files(data_dir: &Path) -> Result<Vec<ControllerBackupFile>, CliError> {
    let mut files = Vec::new();
    collect_controller_backup_files_from_dir(data_dir, &controller_dir(data_dir), &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_controller_backup_files_from_dir(
    data_dir: &Path,
    directory: &Path,
    files: &mut Vec<ControllerBackupFile>,
) -> Result<(), CliError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_controller_backup_files_from_dir(data_dir, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(CliError::Http(
                "controller backup only supports regular files".into(),
            ));
        }
        let relative_path = backup_relative_path(data_dir, &path)?;
        let content = zeroize::Zeroizing::new(fs::read(&path)?);
        let sha256 = sha256_hex(&content);
        files.push(ControllerBackupFile {
            path: relative_path,
            size_bytes: content.len() as u64,
            sha256,
            content_hex: hex_encode(&content),
        });
    }
    Ok(())
}

fn backup_relative_path(data_dir: &Path, path: &Path) -> Result<String, CliError> {
    let relative = path
        .strip_prefix(data_dir)
        .map_err(|_| CliError::Http("backup path is outside data dir".into()))?;
    let parts = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_string_lossy().to_string()),
            _ => Err(CliError::Http("invalid backup path component".into())),
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(parts.join("/"))
}

fn write_backup_archive(output: &Path, archive: &ControllerBackupArchive) -> Result<(), CliError> {
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let body = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(archive)
            .map_err(|_| CliError::Http("cannot encode controller backup".into()))?,
    );
    // tempfile creates a fresh 0600 file. No fixed .tmp name or pre-existing output is reused.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&body)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output).map_err(|_| {
        CliError::Http(
            "cannot install backup; use a new output filename and check its directory".into(),
        )
    })?;
    Ok(())
}

fn read_backup_archive(input: &Path) -> Result<ControllerBackupArchive, CliError> {
    let body = zeroize::Zeroizing::new(fs::read(input)?);
    serde_json::from_slice(&body)
        .map_err(|_| CliError::Http("invalid controller backup JSON".into()))
}

fn validate_backup_archive(archive: &ControllerBackupArchive) -> Result<(), CliError> {
    if archive.format != CONTROLLER_BACKUP_FORMAT {
        return Err(CliError::Http("unsupported backup format".into()));
    }
    if archive.format_version != CONTROLLER_BACKUP_FORMAT_VERSION {
        return Err(CliError::Http(format!(
            "unsupported backup format version: {}",
            archive.format_version
        )));
    }
    if archive.files.is_empty() {
        return Err(CliError::Http(
            "backup archive contains no files".to_owned(),
        ));
    }
    let mut paths = HashSet::new();
    for file in &archive.files {
        validate_backup_file_path(&file.path)?;
        if !paths.insert(file.path.as_str())
            || [
                "controller/fleet.db-journal",
                "controller/fleet.db-wal",
                "controller/fleet.db-shm",
            ]
            .contains(&file.path.as_str())
        {
            return Err(CliError::Http(
                "backup contains duplicate or transient file entries".into(),
            ));
        }
        let content = zeroize::Zeroizing::new(hex_decode(&file.content_hex)?);
        if content.len() as u64 != file.size_bytes {
            return Err(CliError::Http("backup file size mismatch".into()));
        }
        let actual = sha256_hex(&content);
        if actual != file.sha256 {
            return Err(CliError::Http("backup checksum mismatch".into()));
        }
    }
    if !archive
        .files
        .iter()
        .any(|file| file.path == "controller/fleet.db")
    {
        return Err(CliError::Http(
            "backup archive does not contain controller/fleet.db".to_owned(),
        ));
    }
    Ok(())
}

fn validate_backup_file_path(path: &str) -> Result<(), CliError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !path.starts_with("controller/")
    {
        return Err(CliError::Http("invalid backup file path".into()));
    }
    Ok(())
}

/// Validates the payload in private, automatically removed scratch. Never migrates a source
/// or changes target state/epochs. The manifest's integrity label is not evidence by itself.
fn verify_backup_snapshot(archive: &ControllerBackupArchive) -> Result<(), CliError> {
    let content = |name: &str| -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
        let file = archive
            .files
            .iter()
            .find(|file| file.path == name)
            .ok_or_else(|| {
                CliError::Http("backup is missing required controller identity or database".into())
            })?;
        Ok(zeroize::Zeroizing::new(hex_decode(&file.content_hex)?))
    };
    let mut scratch = tempfile::NamedTempFile::new()?;
    scratch.write_all(&content("controller/fleet.db")?)?;
    scratch.flush()?;
    let inspected = fleet_store::sqlite_snapshot::inspect_quiescent_sqlite_snapshot(scratch.path())
        .map_err(|error| CliError::Http(error.to_string()))?;
    if inspected.schema_version != archive.schema_version || archive.sqlite_integrity_check != "ok"
    {
        return Err(CliError::Http(
            "backup database schema or integrity metadata does not match".into(),
        ));
    }
    let public = content("controller/controller_public.key")?;
    let private = content("controller/controller_private.key")?;
    let public =
        std::str::from_utf8(&public).map_err(|_| CliError::InvalidControllerSigningIdentity)?;
    let private =
        std::str::from_utf8(&private).map_err(|_| CliError::InvalidControllerSigningIdentity)?;
    fleet_core::validate_signing_material_pair(
        public.trim(),
        private.trim(),
        "fleet-backup-signing-validation",
    )
    .map_err(|_| CliError::InvalidControllerSigningIdentity)?;
    Ok(())
}

fn restore_archive_into_temp_dir(
    archive: &ControllerBackupArchive,
    temp_root: &Path,
) -> Result<(), CliError> {
    for file in &archive.files {
        let path = temp_root.join(&file.path);
        if let Some(parent) = path.parent() {
            let mut directory = fs::DirBuilder::new();
            directory.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directory.mode(0o700);
            }
            directory.create(parent)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&path)?;
        let body = zeroize::Zeroizing::new(hex_decode(&file.content_hex)?);
        output.write_all(&body)?;
        output.sync_all()?;
    }
    Ok(())
}

fn verify_restored_controller_dir(
    temp_root: &Path,
    lease: &fleet_core::controller_data::ControllerDataLease,
) -> Result<(), CliError> {
    let db_path = temp_root.join("controller").join("fleet.db");
    let mut store = fleet_store::SqliteStore::open(&db_path)
        .map_err(|_| CliError::Http("restore candidate migration failed".into()))?;
    let integrity = store
        .integrity_check()
        .map_err(|_| CliError::Http("restore candidate integrity check failed".into()))?;
    if integrity != "ok" {
        return Err(CliError::Http(
            "restored sqlite integrity check failed".into(),
        ));
    }
    fleet_application::RotateControllerStoreEpoch::execute(&mut store)
        .map_err(|_| CliError::Http("restore candidate delivery epoch rotation failed".into()))?;
    admin_local::invalidate_restored_human_credentials(&mut store, lease)?;
    Ok(())
}

/// Caller holds the data lease and owns a fully synced candidate. Success is the commit point;
/// the exchanged old target stays inside staging until the caller confirms durability/cleanup.
fn replace_controller_dir(data_dir: &Path, temp_root: &Path, force: bool) -> Result<(), CliError> {
    let target_controller_dir = controller_dir(data_dir);
    let temp_controller_dir = temp_root.join("controller");
    let target_exists = match fs::symlink_metadata(&target_controller_dir) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => {
            return Err(CliError::Http(
                "restore target must be a real controller directory".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if target_exists && directory_exists_and_is_non_empty(&target_controller_dir)? && !force {
        return Err(CliError::Http(format!(
            "refusing to overwrite existing controller data dir {}",
            target_controller_dir.display()
        )));
    }
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        let flags = if target_exists {
            RenameFlags::EXCHANGE
        } else {
            RenameFlags::NOREPLACE
        };
        renameat_with(CWD, &temp_controller_dir, CWD, &target_controller_dir, flags)
            .map_err(|_| CliError::Http("atomic restore installation failed; target was not replaced; filesystem must support atomic directory exchange/no-replace".into()))?;
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = temp_controller_dir;
        return Err(CliError::Http(
            "atomic controller restore is unsupported on this platform".into(),
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreFinalization {
    Complete,
    DurabilityUnconfirmed,
    CleanupPending,
}

/// Installation has already committed. Retain rollback staging if parent-directory syncing
/// fails, and distinguish cleanup failure from a failure to install the new target.
fn finalize_controller_restore(
    data_dir: &Path,
    temporary: tempfile::TempDir,
) -> RestoreFinalization {
    if sync_directory(data_dir).is_err() {
        let _retained = temporary.keep();
        RestoreFinalization::DurabilityUnconfirmed
    } else if temporary.close().is_err() {
        RestoreFinalization::CleanupPending
    } else {
        RestoreFinalization::Complete
    }
}

fn sync_restore_tree(path: &Path) -> Result<(), CliError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_restore_tree(&entry.path())?;
        } else {
            fs::File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(path)?;
    Ok(())
}

fn directory_exists_and_is_non_empty(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(CliError::Http(
                "restore target must be a real directory".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    Ok(fs::read_dir(path)?.next().transpose()?.is_some())
}

fn sha256_hex(content: &[u8]) -> String {
    hex_encode(&Sha256::digest(content))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, CliError> {
    if !value.len().is_multiple_of(2) {
        return Err(CliError::Http(
            "hex content must have even length".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| CliError::Http("invalid backup hex encoding".into()))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| CliError::Http("invalid hex byte in backup content".into()))
        })
        .collect()
}

fn execute_enroll_token(command: EnrollTokenCommand) -> Result<(), CliError> {
    match command.command {
        EnrollTokenSubcommand::Create {
            labels,
            max_uses,
            expires_in_seconds,
            controller_url,
            name,
            print_init_command,
            data_dir,
        } => {
            fs::create_dir_all(controller_dir(&data_dir))?;
            let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir))?;
            let token = prefixed_ulid("enroll")?;
            let token_id = prefixed_ulid("et")?;
            store.insert_enrollment_token_hash(
                &token_id,
                &fleet_controller::hash_token(&token),
                &labels,
                SystemTime::now() + Duration::from_secs(expires_in_seconds),
                max_uses,
            )?;
            store.write_audit_event(fleet_domain::AuditEvent {
                category: fleet_domain::AuditCategory::Security,
                action: "enrollment_token_created".to_owned(),
                actor: fleet_domain::AuditActor::new("cli"),
                target: fleet_domain::AuditTarget::new(&token_id),
                value: fleet_domain::AuditValue::SecretRef(format!(
                    "labels={},max_uses={},expires_in_seconds={}",
                    labels, max_uses, expires_in_seconds
                )),
                occurred_at: SystemTime::now(),
            })?;
            if print_init_command {
                let controller_url = controller_url.ok_or_else(|| {
                    CliError::Http(
                        "--controller-url is required with --print-init-command".to_owned(),
                    )
                })?;
                let name = name.unwrap_or_else(|| "<agent-name>".to_owned());
                println!(
                    "fleet agent init --url {} --token {} --name {} --labels {}",
                    shell_arg(&controller_url),
                    shell_arg(&token),
                    shell_arg(&name),
                    shell_arg(&labels)
                );
            } else {
                println!("{token}");
            }
            Ok(())
        }
        EnrollTokenSubcommand::List { data_dir } => {
            let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir))?;
            let records = store.list_enrollment_tokens()?;
            if records.is_empty() {
                println!("no enrollment tokens");
                return Ok(());
            }
            println!("id\tlabels\tmax_uses\tused_count\tremaining_uses\trevoked\texpires_at_epoch");
            for record in records {
                let remaining_uses = record.max_uses.saturating_sub(record.used_count);
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    record.id,
                    record.default_labels,
                    record.max_uses,
                    record.used_count,
                    remaining_uses,
                    record.revoked,
                    epoch_seconds(record.expires_at)
                );
            }
            Ok(())
        }
        EnrollTokenSubcommand::Revoke { id, data_dir } => {
            let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir))?;
            if store.revoke_enrollment_token(&id)? {
                store.write_audit_event(fleet_domain::AuditEvent {
                    category: fleet_domain::AuditCategory::Security,
                    action: "enrollment_token_revoked".to_owned(),
                    actor: fleet_domain::AuditActor::new("cli"),
                    target: fleet_domain::AuditTarget::new(&id),
                    value: fleet_domain::AuditValue::SecretRef("revoked".to_owned()),
                    occurred_at: SystemTime::now(),
                })?;
                println!("revoked enrollment token: {id}");
            } else {
                println!("enrollment token not found: {id}");
            }
            Ok(())
        }
    }
}

fn execute_agent(command: AgentCommand) -> Result<(), CliError> {
    match command.command {
        AgentSubcommand::Init {
            url,
            token,
            name,
            labels,
            tls_ca_cert,
            data_dir,
        } => {
            warn_if_insecure_http_url(&url);
            fs::create_dir_all(agent_dir(&data_dir))?;
            let agent_id = format!("agent-{name}");
            let key_pair = fleet_core::generate_agent_key_pair()?;
            let tls_ca_cert = tls_ca_cert
                .as_deref()
                .map(canonicalize_tls_ca_cert)
                .transpose()?;
            let response = enroll_agent_via_controller(
                &url,
                tls_ca_cert.as_deref(),
                &fleet_controller::EnrollAgentRequest {
                    token: token.clone(),
                    agent_id,
                    name: name.clone(),
                    public_key: key_pair.public_key_hex.clone(),
                    fingerprint: key_pair.fingerprint.clone(),
                    labels: parse_labels(&labels)?,
                },
            )?;
            let tls_ca_cert_line = tls_ca_cert
                .as_ref()
                .map(|path| format!("tls_ca_cert={}\n", path.display()))
                .unwrap_or_default();
            let config = format!(
                "url={}\n{}agent_id={}\nname={}\nlabels={}\nfingerprint={}\ncontroller_fingerprint={}\n",
                url,
                tls_ca_cert_line,
                response.agent_id,
                name,
                labels,
                key_pair.fingerprint,
                response.controller_fingerprint
            );
            write_secure_file(&agent_dir(&data_dir).join("agent.conf"), &config)?;
            write_secure_file(
                &agent_dir(&data_dir).join("agent_private.key"),
                &format!("{}\n", key_pair.private_key_hex),
            )?;
            append_line(
                &agent_dir(&data_dir).join("agents.tsv"),
                &format!("{name}\t{labels}\tPending\n"),
            )?;
            println!(
                "agent enrolled: {}",
                redact_secret(&format!("name={name} token={token}"))
            );
            println!(
                "controller fingerprint: {}",
                response.controller_fingerprint
            );
            Ok(())
        }
        AgentSubcommand::Start {
            data_dir,
            once,
            heartbeat_interval_seconds,
            facts_interval_seconds,
            metrics_interval_seconds,
            disable_log_upload,
            log_upload_interval_seconds,
            max_reconnect_attempts,
        } => {
            let path = agent_dir(&data_dir).join("agent.conf");
            if !path.exists() {
                return Err(CliError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "agent is not enrolled",
                )));
            }
            if log_upload_interval_seconds == 0 {
                return Err(CliError::Http(
                    "log upload interval must be at least 1 second; use --disable-log-upload to turn it off"
                        .to_owned(),
                ));
            }
            if heartbeat_interval_seconds == 0 {
                return Err(CliError::Http(
                    "heartbeat interval must be at least 1 second".to_owned(),
                ));
            }
            if facts_interval_seconds == 0 {
                return Err(CliError::Http(
                    "facts interval must be at least 1 second".to_owned(),
                ));
            }
            if metrics_interval_seconds == 0 {
                return Err(CliError::Http(
                    "metrics interval must be at least 1 second".to_owned(),
                ));
            }
            let config = read_agent_config(&path)?;
            warn_if_insecure_http_url(&config.url);
            run_agent_session_loop(
                &config,
                AgentHeartbeatOptions {
                    once,
                    heartbeat_interval: Duration::from_secs(heartbeat_interval_seconds),
                    facts_interval: Duration::from_secs(facts_interval_seconds),
                    metrics_interval: Duration::from_secs(metrics_interval_seconds),
                    log_upload: AgentLogUploadOptions {
                        enabled: !disable_log_upload,
                        interval: Duration::from_secs(log_upload_interval_seconds),
                    },
                    max_reconnect_attempts,
                },
            )?;
            Ok(())
        }
        AgentSubcommand::InstallService {
            binary,
            data_dir,
            user,
            group,
            dry_run,
        } => {
            let unit = render_service_unit(
                ServiceRole::Agent,
                &resolve_service_binary(binary)?,
                &data_dir,
                user.as_deref(),
                group.as_deref(),
            )?;
            if !dry_run {
                install_systemd_service(ServiceRole::Agent, &unit)?;
                return Ok(());
            }
            print!("{unit}");
            Ok(())
        }
        AgentSubcommand::StartService { dry_run } => {
            start_systemd_service(ServiceRole::Agent, dry_run)
        }
        AgentSubcommand::StatusService { dry_run } => {
            status_systemd_service(ServiceRole::Agent, dry_run)
        }
        AgentSubcommand::LogsService { lines, dry_run } => {
            logs_systemd_service(ServiceRole::Agent, lines, dry_run)
        }
        AgentSubcommand::UninstallService { dry_run } => {
            uninstall_systemd_service(ServiceRole::Agent, dry_run)
        }
    }
}

fn execute_catalog(command: CatalogCommand) -> Result<(), CliError> {
    let (client, path, body) = match command.command {
        CatalogSubcommand::List { api } => (
            resolve_protected_api(&api)?,
            "/api/catalog/sources".to_owned(),
            None,
        ),
        CatalogSubcommand::Register {
            source_id,
            url,
            reference,
            api,
        } => (
            resolve_protected_api(&api)?,
            "/api/catalog/sources".to_owned(),
            Some(
                serde_json::json!({"source_id": source_id, "url": url, "reference": reference})
                    .to_string(),
            ),
        ),
        CatalogSubcommand::Sync {
            source_id,
            operation_id,
            api,
        } => (
            resolve_protected_api(&api)?,
            format!("/api/catalog/sources/{source_id}/sync"),
            Some(serde_json::json!({"operation_id": operation_id}).to_string()),
        ),
        CatalogSubcommand::Activate {
            source_id,
            commit,
            api,
        } => (
            resolve_protected_api(&api)?,
            format!("/api/catalog/sources/{source_id}/activate"),
            Some(serde_json::json!({"commit": commit}).to_string()),
        ),
    };
    let response = if let Some(body) = body {
        client.post(&path, Some(&body))?
    } else {
        client.get(&path)?
    };
    print_json_response(&response)
}

fn execute_agents(command: AgentsCommand) -> Result<(), CliError> {
    match command.command {
        AgentsSubcommand::List { data_dir } => {
            let db_path = controller_db_path(&data_dir);
            if db_path.exists() {
                let store = fleet_store::SqliteStore::open(db_path)?;
                let agents = store.list_agents()?;
                if agents.is_empty() {
                    println!("no agents");
                    return Ok(());
                }
                for agent in agents {
                    let labels = agent
                        .labels()
                        .iter()
                        .map(|label| format!("{}={}", label.key(), label.value()))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{}\t{}\t{:?}",
                        agent.name().as_str(),
                        labels,
                        agent.status()
                    );
                }
                return Ok(());
            }

            let path = agent_dir(&data_dir).join("agents.tsv");
            if !path.exists() {
                println!("no agents");
                return Ok(());
            }
            let mut body = String::new();
            fs::File::open(path)?.read_to_string(&mut body)?;
            print!("{body}");
            Ok(())
        }
        AgentsSubcommand::RemoteList { api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get("/api/agents")?;
            print_json_response(&body)
        }
        AgentsSubcommand::RemoteGet { agent_id, api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get(&format!("/api/agents/{agent_id}"))?;
            print_json_response(&body)
        }
        AgentsSubcommand::RequestCertificateIssuance {
            agent_id,
            api,
            json,
        } => {
            let client = resolve_protected_api(&api)?;
            let response = client.post(
                &format!("/api/agents/{agent_id}/certificate-lifecycle/request-issuance"),
                Some("{}"),
            )?;
            if json {
                return print_json_response(&response);
            }
            for line in render_agent_certificate_issuance_request_for_cli(&response)? {
                println!("{line}");
            }
            Ok(())
        }
        AgentsSubcommand::CertificateStatus {
            agent_id,
            api,
            json,
        } => {
            let client = resolve_protected_api(&api)?;
            let response = client.get(&format!(
                "/api/agents/{agent_id}/certificate-lifecycle/status"
            ))?;
            if json {
                return print_json_response(&response);
            }
            for line in render_agent_certificate_lifecycle_status_for_cli(&response)? {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn execute_jobs(command: JobsCommand) -> Result<(), CliError> {
    match command.command {
        JobsSubcommand::List { api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get("/api/jobs")?;
            print_json_response(&body)
        }
        JobsSubcommand::Get { job_id, api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get(&format!("/api/jobs/{job_id}"))?;
            print_json_response(&body)
        }
        JobsSubcommand::Output { job_id, api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get(&format!("/api/jobs/{job_id}/output"))?;
            for line in render_job_output_api_for_cli(&body)? {
                println!("{line}");
            }
            Ok(())
        }
        JobsSubcommand::Cancel { job_id, api } => {
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "reason": "canceled from CLI" }).to_string();
            let response = client.post(&format!("/api/jobs/{job_id}/cancel"), Some(&body))?;
            print_json_response(&response)
        }
    }
}

fn execute_approvals(command: ApprovalsCommand) -> Result<(), CliError> {
    match command.command {
        ApprovalsSubcommand::List { api } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get("/api/approvals?status=pending")?;
            print_json_response(&body)
        }
        ApprovalsSubcommand::Approve {
            approval_id,
            reason,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "reason": reason }).to_string();
            let response = client.post(
                &format!("/api/approvals/{approval_id}/approve"),
                Some(&body),
            )?;
            print_json_response(&response)
        }
        ApprovalsSubcommand::Reject {
            approval_id,
            reason,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "reason": reason }).to_string();
            let response =
                client.post(&format!("/api/approvals/{approval_id}/reject"), Some(&body))?;
            print_json_response(&response)
        }
    }
}

fn execute_remediations(command: RemediationsCommand) -> Result<(), CliError> {
    match command.command {
        RemediationsSubcommand::List {
            agent_id,
            policy_id,
            limit,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get(&remediations_list_path(
                agent_id.as_deref(),
                policy_id.as_deref(),
                limit,
            ))?;
            print_remediation_response(&body)
        }
        RemediationsSubcommand::Get {
            remediation_id,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let body = client.get(&format!(
                "/api/remediations/{}",
                query_encode(&remediation_id)
            ))?;
            print_remediation_response(&body)
        }
        RemediationsSubcommand::RequestApproval {
            remediation_id,
            approval_id,
            job_id,
            reason,
            expires_in_seconds,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({
                "approval_id": approval_id,
                "job_id": job_id,
                "reason": reason,
                "expires_in_seconds": expires_in_seconds
            })
            .to_string();
            let response = client.post(
                &format!(
                    "/api/remediations/{}/approval-request",
                    query_encode(&remediation_id)
                ),
                Some(&body),
            )?;
            print_remediation_response(&response)
        }
        RemediationsSubcommand::Approve {
            remediation_id,
            approval_id,
            job_id,
            runbook,
            timeout_seconds,
            expires_in_seconds,
            nonce_prefix,
            reason,
            api,
        } => {
            let client = resolve_protected_api(&api)?;
            let runbook_document = fs::read_to_string(&runbook)?;
            let body = build_remediation_approve_body(
                &approval_id,
                &job_id,
                &runbook_document,
                timeout_seconds,
                expires_in_seconds,
                nonce_prefix.as_deref(),
                &reason,
            );
            let response = client.post(
                &format!(
                    "/api/remediations/{}/approve",
                    query_encode(&remediation_id)
                ),
                Some(&body),
            )?;
            print_remediation_response(&response)
        }
        RemediationsSubcommand::Running {
            remediation_id,
            job_id,
            api,
        } => {
            warn_deprecated_manual_remediation_lifecycle("running");
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "job_id": job_id }).to_string();
            let response = client.post(
                &format!(
                    "/api/remediations/{}/running",
                    query_encode(&remediation_id)
                ),
                Some(&body),
            )?;
            print_remediation_response(&response)
        }
        RemediationsSubcommand::Result {
            remediation_id,
            job_id,
            status,
            api,
        } => {
            warn_deprecated_manual_remediation_lifecycle("result");
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "job_id": job_id, "status": status }).to_string();
            let response = client.post(
                &format!("/api/remediations/{}/result", query_encode(&remediation_id)),
                Some(&body),
            )?;
            print_remediation_response(&response)
        }
        RemediationsSubcommand::Verify {
            remediation_id,
            agent_id,
            policy_id,
            policy_name,
            job_id,
            api,
        } => {
            warn_deprecated_manual_remediation_lifecycle("verify");
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({
                "agent_id": agent_id,
                "policy_id": policy_id,
                "policy_name": policy_name,
                "job_id": job_id
            })
            .to_string();
            let response = client.post(
                &format!("/api/remediations/{}/verify", query_encode(&remediation_id)),
                Some(&body),
            )?;
            print_remediation_response(&response)
        }
    }
}

fn execute_selectors(command: SelectorsCommand) -> Result<(), CliError> {
    match command.command {
        SelectorsSubcommand::Preview { selector, api } => {
            let client = resolve_protected_api(&api)?;
            let body = serde_json::json!({ "selector": selector }).to_string();
            let response = client.post("/api/selectors/preview", Some(&body))?;
            for line in render_selector_preview_for_cli(&response)? {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn execute_audit(command: AuditCommand) -> Result<(), CliError> {
    match command.command {
        AuditSubcommand::Export {
            category,
            limit,
            before,
            api,
        } => {
            if limit == 0 {
                return Err(CliError::Http(
                    "audit export limit must be greater than zero".to_owned(),
                ));
            }
            let client = resolve_protected_api(&api)?;
            let path = audit_export_path(category.as_deref(), limit, before.as_deref());
            let body = client.get(&path)?;
            for line in render_audit_export_jsonl(&body)? {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn execute_run(command: RunCommand) -> Result<(), CliError> {
    if !command.confirm_risk {
        return Err(CliError::HighRiskConfirmationRequired);
    }
    let Some((program, args)) = command.command.split_first() else {
        return Err(CliError::EmptyCommand);
    };
    if command.remote || command.controller_url.is_some() || command.admin_token.is_some() {
        return execute_remote_run(&command, program, args);
    }
    let output = fleet_runner::run_command(program, args)?;
    let context = run_context_label(command.selector.as_deref());
    if let Some(selector) = context.strip_prefix("selector:") {
        println!("selector: {selector}");
    }
    let (stdout, stderr) = render_command_output(&output);
    print!("{stdout}");
    eprint!("{stderr}");
    println!("exit_code={}", output.exit_code);
    Ok(())
}

fn execute_remote_run(
    command: &RunCommand,
    program: &str,
    args: &[String],
) -> Result<(), CliError> {
    let client = resolve_protected_api(&run_command_api_args(command))?;
    if command.selector.is_none() {
        return Err(CliError::Http(
            "remote run requires --selector in MVP".to_owned(),
        ));
    }
    let job_id = command.job_id.clone().unwrap_or(prefixed_ulid("job-cli")?);
    let body = remote_run_request_body(command, &job_id, program, args)?;
    let response_body = client.post("/api/jobs/command", Some(&body))?;
    let response_json: serde_json::Value =
        serde_json::from_str(&response_body).map_err(|error| CliError::Http(error.to_string()))?;
    println!(
        "job_id={}",
        response_json
            .get("job_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&job_id)
    );
    println!(
        "target_count={}",
        response_json
            .get("target_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    let status = remote_run_response_status(&response_json);
    println!("status={status}");
    if remote_run_response_needs_approval(&response_json) {
        if let Some(approval_request_id) = remote_run_response_approval_request_id(&response_json) {
            println!("approval_request_id={approval_request_id}");
        }
        println!("output_state=waiting_for_approval");
        return Ok(());
    }

    let output_path = format!("/api/jobs/{job_id}/output");
    let output = client.get(&output_path)?;
    for line in render_job_output_api_for_cli(&output)? {
        println!("{line}");
    }
    Ok(())
}

fn remote_run_response_status(response_json: &serde_json::Value) -> &str {
    response_json
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("queued")
}

fn remote_run_response_approval_request_id(response_json: &serde_json::Value) -> Option<&str> {
    response_json
        .get("approval_request_id")
        .and_then(serde_json::Value::as_str)
}

fn remote_run_response_needs_approval(response_json: &serde_json::Value) -> bool {
    remote_run_response_status(response_json) == "pending_approval"
        || remote_run_response_approval_request_id(response_json).is_some()
}

fn remote_run_request_body(
    command: &RunCommand,
    job_id: &str,
    program: &str,
    args: &[String],
) -> Result<String, CliError> {
    serde_json::to_string(&serde_json::json!({
        "job_id": job_id,
        "target_agent_ids": [],
        "selector": command.selector,
        "program": program,
        "args": args,
        "timeout_seconds": command.timeout_seconds,
        "confirmed_high_risk": true,
        "confirmed_by": "cli-admin-token",
        "expires_in_seconds": REMOTE_RUN_EXPIRES_IN_SECONDS,
        "nonce_prefix": job_id
    }))
    .map_err(|error| CliError::Http(error.to_string()))
}

fn render_command_output(output: &fleet_runner::CommandOutput) -> (String, String) {
    (redact_secret(&output.stdout), redact_secret(&output.stderr))
}

fn run_context_label(selector: Option<&str>) -> String {
    selector
        .map(|selector| format!("selector:{selector}"))
        .unwrap_or_else(|| "local".to_owned())
}

fn render_job_output_api_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let chunks: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let Some(chunks) = chunks.as_array() else {
        return Err(CliError::Http(
            "job output response must be an array".to_owned(),
        ));
    };
    Ok(chunks
        .iter()
        .map(|chunk| {
            let agent_id = chunk
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown-agent");
            let stream = chunk
                .get("stream")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("stdout");
            let sequence = chunk
                .get("sequence")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let data = chunk
                .get("data")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            format!("[{agent_id} {stream} #{sequence}] {}", redact_secret(data))
        })
        .collect())
}

fn render_selector_preview_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let preview: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let mut lines = vec![
        format!(
            "matched_count={}",
            preview
                .get("matched_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        ),
        format!(
            "selected_count={}",
            preview
                .get("selected_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        ),
        format!(
            "disabled_count={}",
            preview
                .get("disabled_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        ),
        format!(
            "offline_count={}",
            preview
                .get("offline_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        ),
    ];
    if let Some(warnings) = preview
        .get("warnings")
        .and_then(serde_json::Value::as_array)
    {
        for warning in warnings {
            let code = warning
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("warning");
            let message = warning
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            lines.push(format!("warning={code}:{message}"));
        }
    }
    if let Some(agents) = preview.get("agents").and_then(serde_json::Value::as_array) {
        for agent in agents {
            let agent_id = agent
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let name = agent
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let status = agent
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let selected = agent
                .get("selected_for_dispatch")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            lines.push(format!(
                "agent={agent_id}\tname={name}\tstatus={status}\tselected={selected}"
            ));
        }
    }
    Ok(lines)
}

fn audit_export_path(category: Option<&str>, limit: usize, before: Option<&str>) -> String {
    let mut query = Vec::new();
    if let Some(category) = category.filter(|value| !value.is_empty()) {
        query.push(format!("category={}", query_encode(category)));
    }
    query.push(format!("limit={limit}"));
    if let Some(before) = before.filter(|value| !value.is_empty()) {
        query.push(format!("before={}", query_encode(before)));
    }
    format!("/api/audit/export?{}", query.join("&"))
}

fn remediations_list_path(agent_id: Option<&str>, policy_id: Option<&str>, limit: usize) -> String {
    let mut query = Vec::new();
    if let Some(agent_id) = agent_id.filter(|value| !value.is_empty()) {
        query.push(format!("agent_id={}", query_encode(agent_id)));
    }
    if let Some(policy_id) = policy_id.filter(|value| !value.is_empty()) {
        query.push(format!("policy_id={}", query_encode(policy_id)));
    }
    query.push(format!("limit={}", limit.max(1)));
    format!("/api/remediations?{}", query.join("&"))
}

fn build_remediation_approve_body(
    approval_id: &str,
    job_id: &str,
    runbook_document: &str,
    timeout_seconds: u64,
    expires_in_seconds: u64,
    nonce_prefix: Option<&str>,
    reason: &str,
) -> String {
    serde_json::json!({
        "approval_id": approval_id,
        "job_id": job_id,
        "runbook_document": runbook_document,
        "timeout_seconds": timeout_seconds,
        "expires_in_seconds": expires_in_seconds,
        "nonce_prefix": nonce_prefix,
        "reason": reason
    })
    .to_string()
}

fn render_audit_export_jsonl(body: &str) -> Result<Vec<String>, CliError> {
    let page: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    let Some(items) = page.get("items").and_then(serde_json::Value::as_array) else {
        return Err(CliError::Http(
            "audit export response must contain an items array".to_owned(),
        ));
    };
    items
        .iter()
        .map(|item| serde_json::to_string(item).map_err(|error| CliError::Http(error.to_string())))
        .collect()
}

fn print_remediation_response(body: &str) -> Result<(), CliError> {
    for line in render_remediation_api_for_cli(body)? {
        println!("{line}");
    }
    Ok(())
}

/// Warns before retaining a compatibility call that the Controller will reject.
fn warn_deprecated_manual_remediation_lifecycle(command: &str) {
    eprintln!(
        "{}",
        format_warning_message(format!(
            "remediations {command} is deprecated and will return 409; wait for authenticated agent task events and persisted verification evidence"
        ))
    );
}

fn render_remediation_api_for_cli(body: &str) -> Result<Vec<String>, CliError> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|error| CliError::Http(error.to_string()))?;
    if let Some(items) = json.as_array() {
        return Ok(items.iter().map(remediation_summary_line).collect());
    }
    if let Some(remediation) = json.get("remediation") {
        let mut lines = vec![remediation_summary_line(remediation)];
        if let Some(approval) = json.get("approval") {
            lines.push(format!(
                "approval_id={}\tapproval_status={}\tapproval_job_id={}",
                json_field(approval, "id"),
                json_field(approval, "status"),
                json_field(approval, "job_id")
            ));
        }
        if json.get("assignment_count").is_some() || json.get("status").is_some() {
            lines.push(format!(
                "job_id={}\tassignment_count={}\tstatus={}",
                json_field(&json, "job_id"),
                json_field(&json, "assignment_count"),
                json_field(&json, "status")
            ));
        }
        return Ok(lines);
    }
    Ok(vec![remediation_summary_line(&json)])
}

fn remediation_summary_line(value: &serde_json::Value) -> String {
    format!(
        "remediation_id={}\tpolicy_id={}\tagent_id={}\tstatus={}\trunbook_ref={}\tjob_id={}\tlifecycle_source={}\tverification_job_id={}\tverification_assignment_status={}\tverification_evidence_status={}\tlegacy_state={}",
        json_field(value, "id"),
        json_field(value, "policy_id"),
        json_field(value, "agent_id"),
        json_field(value, "status"),
        json_field(value, "runbook_ref"),
        json_field(value, "job_id"),
        json_field(value, "lifecycle_source"),
        json_field(value, "verification_job_id"),
        json_field(value, "verification_assignment_status"),
        json_field(value, "verification_evidence_status"),
        json_field(value, "legacy_state")
    )
}

fn json_field(value: &serde_json::Value, key: &str) -> String {
    match value.get(key) {
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(serde_json::Value::Bool(value)) => value.to_string(),
        Some(serde_json::Value::Null) | None => "".to_owned(),
        Some(other) => other.to_string(),
    }
}

fn json_optional_field(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key)? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn query_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn execute_facts(command: FactsCommand) -> Result<(), CliError> {
    let mut facts = collect_local_facts();
    if let Some(object) = facts.as_object_mut() {
        object.insert(
            "agent".to_owned(),
            serde_json::Value::String(command.agent.unwrap_or_else(|| "local".to_owned())),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&facts).map_err(|error| CliError::Http(error.to_string()))?
    );
    Ok(())
}

fn execute_metrics(command: MetricsCommand) -> Result<(), CliError> {
    let mut metrics = collect_local_metrics();
    if let Some(object) = metrics.as_object_mut() {
        object.insert(
            "agent".to_owned(),
            serde_json::Value::String(command.agent.unwrap_or_else(|| "local".to_owned())),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&metrics)
            .map_err(|error| CliError::Http(error.to_string()))?
    );
    Ok(())
}

fn execute_apply(command: ApplyCommand) -> Result<(), CliError> {
    let body = fs::read_to_string(command.file)?;
    let runbook = fleet_domain::parse_runbook_document(&body)
        .map_err(|error| CliError::Http(format!("invalid runbook: {error}")))?;
    let plan = fleet_runner::build_runbook_execution_plan(
        &runbook,
        fleet_runner::LinuxPackageManager::Apt,
    )
    .map_err(|error| CliError::Http(format!("invalid runbook primitive: {error}")))?;
    println!("runbook valid: {}", runbook.name);
    println!("task_count={}", runbook.tasks.len());
    println!("execution_plan_steps={}", plan.steps.len());
    println!("execution=not_started");
    println!("note=runbook validation only; execution must use signed task dispatch");
    Ok(())
}

fn execute_retention(command: RetentionCommand) -> Result<(), CliError> {
    match command.command {
        RetentionSubcommand::Cleanup {
            data_dir,
            older_than_days,
            dry_run,
        } => {
            let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir))?;
            let now = SystemTime::now();
            let policy = RetentionPolicy::uniform(Duration::from_secs(
                older_than_days.saturating_mul(86_400),
            ));
            let mut repo = &store;
            let mut audit = &store;
            let output = RunRetentionCleanup::execute(
                &mut repo,
                &mut audit,
                RunRetentionCleanupInput {
                    now,
                    policy,
                    dry_run,
                    actor: "cli".to_owned(),
                    target: "controller-store".to_owned(),
                },
            )
            .map_err(map_cli_retention_cleanup_error)?;
            let summary = output.summary;
            println!("job_output_chunks={}", summary.job_output_chunks);
            println!("facts_snapshots={}", summary.facts_snapshots);
            println!("metrics_snapshots={}", summary.metrics_snapshots);
            println!("agent_log_chunks={}", summary.agent_log_chunks);
            println!("total={}", summary.total());
            println!("dry_run={dry_run}");
            Ok(())
        }
    }
}

fn map_cli_retention_cleanup_error(
    error: fleet_application::RunRetentionCleanupError<
        fleet_store::StoreError,
        fleet_store::StoreError,
    >,
) -> CliError {
    match error {
        fleet_application::RunRetentionCleanupError::Domain(error) => CliError::Http(error),
        fleet_application::RunRetentionCleanupError::Repository(error)
        | fleet_application::RunRetentionCleanupError::Audit(error) => CliError::Store(error),
    }
}

fn execute_logs(command: LogsCommand) -> Result<(), CliError> {
    if let Some(file) = command.file {
        stream_log_file(
            Path::new(&file),
            LogStreamOptions {
                follow: command.follow,
                max_duration: command.max_duration_seconds.map(Duration::from_secs),
                poll_interval: LOG_TAIL_POLL_INTERVAL,
            },
            |line| println!("{line}"),
            || false,
        )?;
        return Ok(());
    }
    if let Some(target) = command.target.as_deref()
        && let Some(command) = journald_command_for_service(target)
    {
        println!("log target={target}");
        println!(
            "journald command: {} {}",
            command.program,
            command.args.join(" ")
        );
        return Ok(());
    }
    println!(
        "log target={}",
        command.target.as_deref().unwrap_or("local")
    );
    println!("no log file provided");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct LogStreamOptions {
    follow: bool,
    max_duration: Option<Duration>,
    poll_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournaldCommand {
    program: String,
    args: Vec<String>,
}

fn journald_command_for_service(service: &str) -> Option<JournaldCommand> {
    if !is_safe_journald_service_name(service) {
        return None;
    }
    Some(JournaldCommand {
        program: "journalctl".to_owned(),
        args: vec![
            "-u".to_owned(),
            service.to_owned(),
            "--no-pager".to_owned(),
            "-n".to_owned(),
            LOG_TAIL_MAX_LINES.to_string(),
        ],
    })
}

fn is_safe_journald_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '@' | '-')
        })
}

fn stream_log_file(
    path: &Path,
    options: LogStreamOptions,
    mut emit: impl FnMut(String),
    mut should_cancel: impl FnMut() -> bool,
) -> Result<(), CliError> {
    let body = fs::read_to_string(path)?;
    for line in render_log_tail(&body) {
        emit(line);
    }
    if !options.follow {
        return Ok(());
    }

    let mut offset = body.len();
    let started_at = Instant::now();
    loop {
        if should_cancel() {
            return Ok(());
        }
        if options
            .max_duration
            .is_some_and(|duration| started_at.elapsed() >= duration)
        {
            return Ok(());
        }

        let next_body = fs::read_to_string(path)?;
        if next_body.len() < offset {
            offset = 0;
        }
        if next_body.len() > offset {
            for line in render_appended_log_lines(&next_body[offset..]) {
                emit(line);
            }
            offset = next_body.len();
        }
        std::thread::sleep(options.poll_interval);
    }
}

fn render_log_tail(body: &str) -> Vec<String> {
    body.lines()
        .rev()
        .take(LOG_TAIL_MAX_LINES)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(redact_and_truncate_log_line)
        .collect()
}

fn render_appended_log_lines(body: &str) -> Vec<String> {
    body.lines().map(redact_and_truncate_log_line).collect()
}

fn redact_and_truncate_log_line(line: &str) -> String {
    let redacted = redact_secret(line);
    if redacted.len() <= LOG_TAIL_MAX_LINE_BYTES {
        return redacted;
    }

    let mut end = LOG_TAIL_MAX_LINE_BYTES;
    while !redacted.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &redacted[..end])
}

fn execute_drift(command: DriftCommand) -> Result<(), CliError> {
    match command.command {
        DriftSubcommand::Check { policy } => {
            let policy = policy.ok_or(CliError::MissingPolicy)?;
            let body = fs::read_to_string(policy)?;
            let parsed = fleet_domain::parse_policy_document(&body)
                .map_err(|error| CliError::Http(format!("invalid policy: {error}")))?;
            let report =
                fleet_runner::evaluate_policy_drift(&parsed, &fleet_runner::LocalDriftProbe);
            println!("status={}", drift_status_to_cli(&report.status));
            println!("policy={}", report.policy_name);
            println!("expected={}", report.expected);
            println!("actual={}", report.actual);
            Ok(())
        }
    }
}

fn execute_upgrade(command: UpgradeCommand) -> Result<(), CliError> {
    if !command.dry_run {
        return Err(CliError::UpgradeRequiresDryRun);
    }
    for line in upgrade_dry_run_lines(&command) {
        println!("{line}");
    }
    Ok(())
}

fn upgrade_dry_run_lines(command: &UpgradeCommand) -> Vec<String> {
    let target_version = command.version.as_deref().unwrap_or("latest");
    vec![
        "upgrade_dry_run=true".to_owned(),
        format!("current_version={}", env!("CARGO_PKG_VERSION")),
        format!("channel={}", command.channel.as_str()),
        format!("target_version={target_version}"),
        "backup_required=true".to_owned(),
        "recommended_backup_command=fleet controller backup --data-dir <controller-data-dir> --output ./fleet-controller-before-upgrade.backup.json".to_owned(),
        "artifact_integrity_required=true".to_owned(),
        "artifact_integrity_command=./scripts/verify_standalone_artifacts.sh dist/release".to_owned(),
        "artifact_signature_command=./scripts/verify_release_signature.sh dist/release <release-public-key.pem>".to_owned(),
        "recovery_policy=restore the previous fleet binary; if controller data was migrated or changed, restore the controller backup before restarting services".to_owned(),
        "service_policy=stop services before binary replacement, then restart and verify with status-service".to_owned(),
    ]
}

fn drift_status_to_cli(status: &fleet_domain::DriftStatus) -> &'static str {
    match status {
        fleet_domain::DriftStatus::Compliant => "compliant",
        fleet_domain::DriftStatus::Drifted => "drifted",
        fleet_domain::DriftStatus::Unknown => "unknown",
    }
}

fn execute_demo(command: DemoCommand) -> Result<(), CliError> {
    let port = match command.port {
        Some(port) => {
            ensure_loopback_port_available(port)?;
            port
        }
        None => free_loopback_port()?,
    };
    let data_dir = unique_demo_dir();
    let setup_lease = fleet_core::controller_data::ControllerDataLease::acquire(&data_dir)?;
    admin_local::prepare_controller_dir(&data_dir)?;
    fs::create_dir_all(agent_dir(&data_dir))?;

    let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir))?;
    let controller_fingerprint = ensure_controller_identity(&data_dir)?;
    let admin_token = fleet_controller::create_admin_token(&store)?
        .ok_or_else(|| CliError::Http("demo data dir unexpectedly reused".to_owned()))?;
    let enroll_token = prefixed_ulid("enroll-demo")?;
    store.insert_enrollment_token_hash(
        "et-demo",
        &fleet_controller::hash_token(&enroll_token),
        "role=web,env=demo",
        SystemTime::now() + Duration::from_secs(300),
        1,
    )?;
    drop(store);

    drop(setup_lease);

    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let server_data_dir = data_dir.clone();
    let handle = std::thread::spawn(move || {
        fleet_controller::start_controller_server_until(
            fleet_controller::ControllerServerConfig {
                host: "127.0.0.1".to_owned(),
                port,
                external_url: Some(format!("http://127.0.0.1:{port}")),
                tls_cert_path: None,
                tls_key_path: None,
                agent_client_ca_cert_path: None,
                data_dir: server_data_dir,
                database: None,
                secret_provider: None,
            },
            move || thread_shutdown.load(Ordering::SeqCst),
        )
    });
    let _guard = DemoGuard {
        data_dir: data_dir.clone(),
        keep_temp: command.keep_temp,
        shutdown,
        handle: Some(handle),
    };

    wait_for_controller_health(port)?;
    let controller_url = format!("http://127.0.0.1:{port}");
    let agent_config = enroll_demo_agent(&data_dir, &controller_url, &enroll_token)?;
    create_demo_command_job(port, &admin_token)?;
    run_agent_heartbeat_once(&agent_config, true)?;
    let output = wait_for_demo_output(
        || http_get(port, "/api/jobs/job-demo-1/output", Some(&admin_token)),
        std::thread::sleep,
        Duration::from_secs(5),
    )?;
    let rendered_output = render_job_output_api_for_cli(&output)?;

    println!("demo controller: {controller_url}");
    println!("demo admin: {controller_url}/admin");
    println!("demo controller fingerprint: {controller_fingerprint}");
    eprintln!(
        "{}",
        format_warning_message(format!(
            "demo uses insecure HTTP controller URL: {controller_url}; HTTP is test-only and not encrypted; use HTTPS for product or production environments"
        ))
    );
    if command.keep_temp {
        println!("demo data dir: {}", data_dir.display());
    }
    println!("demo command output: demo-ok");
    for line in rendered_output {
        print!("{line}");
    }
    Ok(())
}

fn wait_for_demo_output(
    mut read: impl FnMut() -> Result<String, CliError>,
    mut sleep: impl FnMut(Duration),
    limit: Duration,
) -> Result<String, CliError> {
    let started = std::time::Instant::now();
    loop {
        let output = read()?;
        if output.contains("demo-ok") {
            return Ok(output);
        }
        if started.elapsed() >= limit {
            return Err(CliError::Http(
                "demo command output was not observed before deadline".to_owned(),
            ));
        }
        sleep(Duration::from_millis(50).min(limit.saturating_sub(started.elapsed())));
    }
}

fn enroll_demo_agent(
    data_dir: &Path,
    controller_url: &str,
    token: &str,
) -> Result<LocalAgentConfig, CliError> {
    let key_pair = fleet_core::generate_agent_key_pair()?;
    let response = enroll_agent_via_controller(
        controller_url,
        None,
        &fleet_controller::EnrollAgentRequest {
            token: token.to_owned(),
            agent_id: "agent-web-01".to_owned(),
            name: "web-01".to_owned(),
            public_key: key_pair.public_key_hex.clone(),
            fingerprint: key_pair.fingerprint.clone(),
            labels: parse_labels("role=web,env=demo")?,
        },
    )?;
    let config_body = format!(
        "url={controller_url}\nagent_id={}\nname=web-01\nlabels=role=web,env=demo\nfingerprint={}\ncontroller_fingerprint={}\n",
        response.agent_id, key_pair.fingerprint, response.controller_fingerprint
    );
    write_secure_file(&agent_dir(data_dir).join("agent.conf"), &config_body)?;
    write_secure_file(
        &agent_dir(data_dir).join("agent_private.key"),
        &format!("{}\n", key_pair.private_key_hex),
    )?;
    read_agent_config(&agent_dir(data_dir).join("agent.conf"))
}

fn create_demo_command_job(port: u16, admin_token: &str) -> Result<(), CliError> {
    let body = serde_json::json!({
        "job_id": "job-demo-1",
        "target_agent_ids": ["agent-web-01"],
        "program": "echo",
        "args": ["demo-ok"],
        "timeout_seconds": 30,
        "confirmed_high_risk": false,
        "confirmed_by": "demo-admin",
        "expires_in_seconds": 60,
        "nonce_prefix": "demo"
    })
    .to_string();
    let response = http_request(
        port,
        "POST",
        "/api/jobs/command",
        Some(admin_token),
        Some(&body),
    )?;
    if !response.starts_with("HTTP/1.1 201") {
        return Err(CliError::Http(
            response.lines().next().unwrap_or("").to_owned(),
        ));
    }
    Ok(())
}

fn wait_for_controller_health(port: u16) -> Result<(), CliError> {
    for _ in 0..100 {
        if http_get(port, "/healthz", None)
            .map(|body| body.contains("\"status\":\"ok\""))
            .unwrap_or(false)
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(CliError::Http(
        "demo controller did not become healthy".to_owned(),
    ))
}

fn http_get(port: u16, path: &str, bearer_token: Option<&str>) -> Result<String, CliError> {
    let response = http_request(port, "GET", path, bearer_token, None)?;
    if !response.starts_with("HTTP/1.1 200") {
        return Err(CliError::Http(
            response.lines().next().unwrap_or("").to_owned(),
        ));
    }
    Ok(response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_owned())
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    body: Option<&str>,
) -> Result<String, CliError> {
    let body = body.unwrap_or_default();
    let auth_header = bearer_token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let content_headers = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_header}{content_headers}Connection: close\r\n\r\n{body}"
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn http_request_url_with_client(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    body: Option<&str>,
) -> Result<String, CliError> {
    let endpoint = parse_controller_url(url)?;
    warn_if_insecure_http_endpoint(&endpoint);
    let body = body.unwrap_or_default();
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|error| CliError::Http(error.to_string()))?;
    let mut request = client.request(method, endpoint.api_url(path));
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    if !body.is_empty() {
        request = request
            .header("content-type", "application/json")
            .body(body.to_owned());
    }
    let response = request
        .send()
        .map_err(|error| CliError::Http(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown"),
        body.len(),
        body
    ))
}

fn free_loopback_port() -> Result<u16, CliError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn ensure_loopback_port_available(port: u16) -> Result<(), CliError> {
    TcpListener::bind(("127.0.0.1", port))
        .map(|_| ())
        .map_err(|error| CliError::Http(format!("demo port {port} is unavailable: {error}")))
}

fn unique_demo_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fleet-demo-{}-{}",
        std::process::id(),
        epoch_millis()
    ))
}

struct DemoGuard {
    data_dir: PathBuf,
    keep_temp: bool,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<(), fleet_controller::ControllerError>>>,
}

impl Drop for DemoGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if !self.keep_temp {
            let _ = fs::remove_dir_all(&self.data_dir);
        }
    }
}

fn controller_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("controller")
}

fn agent_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("agent")
}

fn controller_db_path(data_dir: &Path) -> PathBuf {
    controller_dir(data_dir).join("fleet.db")
}

fn ensure_controller_initialized_for_start(data_dir: &Path) -> Result<(), CliError> {
    let controller_path = controller_dir(data_dir);
    let public_key_path = controller_path.join("controller_public.key");
    let private_key_path = controller_path.join("controller_private.key");
    if !controller_path.is_dir() || !public_key_path.is_file() || !private_key_path.is_file() {
        return Err(CliError::ControllerNotInitialized {
            data_dir: data_dir.to_path_buf(),
        });
    }
    Ok(())
}

fn parse_controller_database_settings(
    value: Option<&str>,
    data_dir: &Path,
) -> Result<DatabaseSettings, CliError> {
    DatabaseSettings::parse_optional(value, controller_db_path(data_dir))
        .map_err(|error| CliError::Http(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceRole {
    Controller,
    Agent,
}

fn resolve_service_binary(binary: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let path = match binary {
        Some(path) => path,
        None => std::env::current_exe()?,
    };
    if !path.is_absolute() {
        return Err(CliError::ServiceBinaryMustBeAbsolute(path));
    }
    Ok(path)
}

fn render_service_unit(
    role: ServiceRole,
    binary: &Path,
    data_dir: &Path,
    user: Option<&str>,
    group: Option<&str>,
) -> Result<String, CliError> {
    if !binary.is_absolute() {
        return Err(CliError::ServiceBinaryMustBeAbsolute(binary.to_path_buf()));
    }
    validate_service_account(user)?;
    validate_service_account(group)?;

    let (description, role_args) = match role {
        ServiceRole::Controller => (
            "Sponzey Fleet Controller",
            format!("controller start --data-dir {}", systemd_arg(data_dir)),
        ),
        ServiceRole::Agent => (
            "Sponzey Fleet Agent",
            format!("agent start --data-dir {}", systemd_arg(data_dir)),
        ),
    };
    let mut unit = format!(
        "[Unit]\nDescription={description}\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} {role_args}\nRestart=on-failure\n",
        systemd_arg(binary)
    );
    if let Some(user) = user {
        unit.push_str(&format!("User={user}\n"));
    }
    if let Some(group) = group {
        unit.push_str(&format!("Group={group}\n"));
    }
    unit.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    Ok(unit)
}

fn service_unit_name(role: ServiceRole) -> &'static str {
    match role {
        ServiceRole::Controller => "fleet-controller.service",
        ServiceRole::Agent => "fleet-agent.service",
    }
}

fn systemd_unit_path(role: ServiceRole) -> PathBuf {
    Path::new("/etc/systemd/system").join(service_unit_name(role))
}

fn render_systemctl_command(action: &str, role: ServiceRole) -> String {
    format!("systemctl {action} {}", service_unit_name(role))
}

fn render_service_status_command(role: ServiceRole) -> String {
    format!("systemctl status {} --no-pager", service_unit_name(role))
}

fn render_service_logs_command(role: ServiceRole, lines: usize) -> String {
    format!(
        "journalctl -u {} --no-pager -n {lines}",
        service_unit_name(role)
    )
}

fn render_uninstall_service_commands(role: ServiceRole) -> Vec<String> {
    vec![
        render_systemctl_command("disable --now", role),
        format!("rm {}", systemd_arg(&systemd_unit_path(role))),
        "systemctl daemon-reload".to_owned(),
    ]
}

fn start_systemd_service(role: ServiceRole, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        println!("{}", render_systemctl_command("start", role));
        return Ok(());
    }
    ensure_systemd_operation_allowed()?;
    run_systemctl(&["start", service_unit_name(role)])
}

fn restart_systemd_service(role: ServiceRole, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        println!("{}", render_systemctl_command("restart", role));
        return Ok(());
    }
    ensure_systemd_operation_allowed()?;
    run_systemctl(&["restart", service_unit_name(role)])
}

fn status_systemd_service(role: ServiceRole, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        println!("{}", render_service_status_command(role));
        return Ok(());
    }
    ensure_systemd_query_allowed()?;
    let status = ProcessCommand::new("systemctl")
        .arg("status")
        .arg(service_unit_name(role))
        .arg("--no-pager")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Io(std::io::Error::other(format!(
            "systemctl status {} failed with status {status}",
            service_unit_name(role)
        ))))
    }
}

fn logs_systemd_service(role: ServiceRole, lines: usize, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        println!("{}", render_service_logs_command(role, lines));
        return Ok(());
    }
    ensure_systemd_query_allowed()?;
    let status = ProcessCommand::new("journalctl")
        .arg("-u")
        .arg(service_unit_name(role))
        .arg("--no-pager")
        .arg("-n")
        .arg(lines.to_string())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Io(std::io::Error::other(format!(
            "journalctl -u {} failed with status {status}",
            service_unit_name(role)
        ))))
    }
}

fn install_systemd_service(role: ServiceRole, unit: &str) -> Result<(), CliError> {
    ensure_systemd_operation_allowed()?;
    let path = systemd_unit_path(role);
    fs::write(&path, unit)?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", service_unit_name(role)])
}

fn uninstall_systemd_service(role: ServiceRole, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        for command in render_uninstall_service_commands(role) {
            println!("{command}");
        }
        return Ok(());
    }
    ensure_systemd_operation_allowed()?;
    run_systemctl(&["disable", "--now", service_unit_name(role)])?;
    let path = systemd_unit_path(role);
    if path.exists() {
        fs::remove_file(path)?;
    }
    run_systemctl(&["daemon-reload"])
}

fn ensure_systemd_operation_allowed() -> Result<(), CliError> {
    ensure_systemd_query_allowed()?;
    if effective_user_id()? != 0 {
        return Err(CliError::ServiceOperationRequiresRoot);
    }
    Ok(())
}

fn ensure_systemd_query_allowed() -> Result<(), CliError> {
    if std::env::consts::OS != "linux" {
        return Err(CliError::ServiceOperationRequiresLinux);
    }
    Ok(())
}

fn effective_user_id() -> Result<u32, CliError> {
    let output = ProcessCommand::new("id").arg("-u").output()?;
    if !output.status.success() {
        return Err(CliError::Io(std::io::Error::other(
            "failed to determine effective user id",
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse::<u32>()
        .map_err(|error| CliError::Io(std::io::Error::other(error.to_string())))
}

fn run_systemctl(args: &[&str]) -> Result<(), CliError> {
    let status = ProcessCommand::new("systemctl").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Io(std::io::Error::other(format!(
            "systemctl {} failed with status {status}",
            args.join(" ")
        ))))
    }
}

fn validate_service_account(value: Option<&str>) -> Result<(), CliError> {
    let Some(value) = value else {
        return Ok(());
    };
    let valid = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if valid {
        Ok(())
    } else {
        Err(CliError::InvalidServiceAccount(value.to_owned()))
    }
}

fn systemd_arg(path: &Path) -> String {
    let value = path.display().to_string();
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | ':'))
    {
        return value;
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn shell_arg(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | ':' | '=' | ','))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn epoch_seconds(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ensure_controller_identity(data_dir: &Path) -> Result<String, CliError> {
    let public_key_path = controller_dir(data_dir).join("controller_public.key");
    let private_key_path = controller_dir(data_dir).join("controller_private.key");

    match (public_key_path.exists(), private_key_path.exists()) {
        (false, false) => {
            let key_pair = fleet_core::generate_agent_key_pair()?;
            write_once(&public_key_path, &format!("{}\n", key_pair.public_key_hex))?;
            write_once_secure(
                &private_key_path,
                &format!("{}\n", key_pair.private_key_hex),
            )?;
            Ok(key_pair.fingerprint)
        }
        (true, true) => {
            validate_secure_file_permissions(&private_key_path)?;
            let public_key = fs::read_to_string(public_key_path)?.trim().to_owned();
            Ok(fleet_core::fingerprint_public_key(&public_key)?)
        }
        _ => Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "controller identity is incomplete; public and private key files must exist together",
        ))),
    }
}

fn append_line(path: &Path, line: &str) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())
}

fn write_once(path: &Path, body: &str) -> Result<(), std::io::Error> {
    if path.exists() {
        return Ok(());
    }
    fs::write(path, body)
}

fn write_once_secure(path: &Path, body: &str) -> Result<(), std::io::Error> {
    if path.exists() {
        return Ok(());
    }
    write_secure_file(path, body)
}

fn write_secure_file(path: &Path, body: &str) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(body.as_bytes())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }

    #[cfg(not(unix))]
    {
        fs::write(path, body)
    }
}

fn write_secure_file_atomic(path: &Path, body: &str) -> Result<(), std::io::Error> {
    let tmp_path = path.with_extension("tmp");
    write_secure_file(&tmp_path, body)?;
    fs::rename(tmp_path, path)
}

fn validate_secure_file_permissions(path: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} must not be readable, writable, or executable by group/other",
                    path.display()
                ),
            )));
        }
    }

    Ok(())
}

fn canonicalize_tls_ca_cert(path: &Path) -> Result<PathBuf, CliError> {
    let path = fs::canonicalize(path)?;
    let certificates = load_pem_certificates(&path)?;
    if certificates.is_empty() {
        return Err(CliError::Http(format!(
            "TLS CA certificate file has no certificates: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn load_pem_certificates(
    path: &Path,
) -> Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>, CliError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            CliError::Http(format!(
                "failed to parse TLS CA certificate file {}: {error}",
                path.display()
            ))
        })
}

fn parse_labels(labels: &str) -> Result<Vec<fleet_controller::EnrollAgentLabel>, CliError> {
    labels
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').ok_or_else(|| {
                CliError::Http(format!("invalid label, expected key=value: {part}"))
            })?;
            Ok(fleet_controller::EnrollAgentLabel {
                key: key.to_owned(),
                value: value.to_owned(),
            })
        })
        .collect()
}

fn enroll_agent_via_controller(
    url: &str,
    tls_ca_cert: Option<&Path>,
    request: &fleet_controller::EnrollAgentRequest,
) -> Result<fleet_controller::EnrollAgentResponse, CliError> {
    let body = serde_json::to_string(request).map_err(|error| CliError::Http(error.to_string()))?;
    let endpoint = parse_controller_url(url)?;
    let enroll_url = endpoint.api_url("/api/agents/enroll");
    let response = reqwest_client(tls_ca_cert)?
        .post(&enroll_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .map_err(|error| {
            CliError::Http(http_request_error_message(
                "agent enrollment",
                &enroll_url,
                &error,
            ))
        })?;
    let status = response.status();
    if status.as_u16() != 201 {
        return Err(CliError::Http(format!(
            "HTTP/1.1 {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("request failed")
        )));
    }
    response
        .json()
        .map_err(|error| CliError::Http(error.to_string()))
}

fn controller_identity_via_controller(
    url: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<fleet_controller::ControllerIdentityResponse, CliError> {
    let endpoint = parse_controller_url(url)?;
    let identity_url = endpoint.api_url("/api/controller/identity");
    let response = reqwest_client(tls_ca_cert)?
        .get(&identity_url)
        .send()
        .map_err(|error| {
            CliError::Http(http_request_error_message(
                "controller identity request",
                &identity_url,
                &error,
            ))
        })?;
    let status = response.status();
    if status.as_u16() != 200 {
        return Err(CliError::Http(format!(
            "HTTP/1.1 {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("request failed")
        )));
    }
    response
        .json()
        .map_err(|error| CliError::Http(error.to_string()))
}

fn http_request_error_message(action: &str, url: &str, error: &dyn StdError) -> String {
    let mut message = format!("{action} failed for {url}: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_message = cause.to_string();
        if !cause_message.is_empty() && !message.contains(&cause_message) {
            message.push_str(": ");
            message.push_str(&cause_message);
        }
        source = cause.source();
    }
    message.push_str(
        ". Check that the controller is running, the URL host/port are reachable from this agent, the controller is bound to a reachable host such as 0.0.0.0 for remote tests, and any firewall allows the port.",
    );
    message
}

fn reqwest_client(tls_ca_cert: Option<&Path>) -> Result<reqwest::blocking::Client, CliError> {
    let mut builder = reqwest::blocking::Client::builder();
    if let Some(path) = tls_ca_cert {
        let certificate = reqwest::Certificate::from_pem(&fs::read(path)?)
            .map_err(|error| CliError::Http(format!("invalid TLS CA certificate: {error}")))?;
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|error| CliError::Http(error.to_string()))
}

fn connect_agent_websocket(
    ws_url: &str,
    endpoint: &ControllerEndpoint,
    tls_ca_cert: Option<&Path>,
) -> Result<
    (
        tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
        tungstenite::handshake::client::Response,
    ),
    CliError,
> {
    if tls_ca_cert.is_none() {
        return tungstenite::connect(ws_url).map_err(|error| CliError::Http(error.to_string()));
    }

    let request = ws_url
        .into_client_request()
        .map_err(|error| CliError::Http(error.to_string()))?;
    let stream = TcpStream::connect(format!(
        "{}:{}",
        display_socket_host(&endpoint.host),
        endpoint.port
    ))?;
    stream.set_nodelay(true)?;
    let connector = match endpoint.scheme {
        ControllerUrlScheme::Http => None,
        ControllerUrlScheme::Https => Some(Connector::Rustls(build_websocket_tls_config(
            tls_ca_cert.expect("checked above"),
        )?)),
    };

    tungstenite::client_tls_with_config(request, stream, None, connector)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn build_websocket_tls_config(tls_ca_cert: &Path) -> Result<Arc<RustlsClientConfig>, CliError> {
    ensure_rustls_crypto_provider();
    let mut root_store = RootCertStore::empty();
    let mut added = 0_usize;
    for certificate in load_pem_certificates(tls_ca_cert)? {
        root_store
            .add(certificate)
            .map_err(|error| CliError::Http(format!("invalid TLS CA certificate: {error}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(CliError::Http(format!(
            "TLS CA certificate file has no certificates: {}",
            tls_ca_cert.display()
        )));
    }
    Ok(Arc::new(
        RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ))
}

fn ensure_rustls_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerUrlScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControllerEndpoint {
    scheme: ControllerUrlScheme,
    host: String,
    port: u16,
}

impl ControllerEndpoint {
    fn api_url(&self, path: &str) -> String {
        let scheme = match self.scheme {
            ControllerUrlScheme::Http => "http",
            ControllerUrlScheme::Https => "https",
        };
        let host = display_url_host(&self.host);
        format!("{scheme}://{host}:{}{}", self.port, normalized_path(path))
    }

    fn websocket_url(&self, path: &str) -> String {
        let scheme = match self.scheme {
            ControllerUrlScheme::Http => "ws",
            ControllerUrlScheme::Https => "wss",
        };
        let host = display_url_host(&self.host);
        format!("{scheme}://{host}:{}{}", self.port, normalized_path(path))
    }
}

fn normalized_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn display_url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn display_socket_host(host: &str) -> String {
    display_url_host(host)
}

fn parse_controller_url(url: &str) -> Result<ControllerEndpoint, CliError> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        (ControllerUrlScheme::Http, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (ControllerUrlScheme::Https, rest)
    } else {
        return Err(CliError::Http(
            "controller URL must start with http:// or https://".to_owned(),
        ));
    };

    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(CliError::Http(
            "controller URL host cannot be empty".to_owned(),
        ));
    }
    let (host, port) = parse_controller_authority(authority, scheme)?;
    if is_wildcard_host(&host) {
        return Err(CliError::Http(
            "controller URL must not use a wildcard host such as 0.0.0.0".to_owned(),
        ));
    }
    Ok(ControllerEndpoint { scheme, host, port })
}

fn parse_controller_authority(
    authority: &str,
    scheme: ControllerUrlScheme,
) -> Result<(String, u16), CliError> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| CliError::Http("invalid bracketed IPv6 host".to_owned()))?;
        let port = if let Some(port) = rest.strip_prefix(':') {
            parse_controller_port(port)?
        } else {
            default_controller_port(scheme)
        };
        return Ok((host.to_owned(), port));
    }

    let colon_count = authority
        .chars()
        .filter(|character| *character == ':')
        .count();
    if colon_count > 1 {
        return Ok((authority.to_owned(), default_controller_port(scheme)));
    }

    if let Some((host, port)) = authority.split_once(':') {
        if host.is_empty() {
            return Err(CliError::Http(
                "controller URL host cannot be empty".to_owned(),
            ));
        }
        return Ok((host.to_owned(), parse_controller_port(port)?));
    }

    Ok((authority.to_owned(), default_controller_port(scheme)))
}

fn parse_controller_port(port: &str) -> Result<u16, CliError> {
    if port.is_empty() {
        return Err(CliError::Http("controller port cannot be empty".to_owned()));
    }
    port.parse::<u16>()
        .map_err(|_| CliError::Http("invalid controller port".to_owned()))
}

fn default_controller_port(scheme: ControllerUrlScheme) -> u16 {
    match scheme {
        ControllerUrlScheme::Http => 80,
        ControllerUrlScheme::Https => 443,
    }
}

fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::")
}

fn warn_if_insecure_http_url(url: &str) {
    if let Ok(endpoint) = parse_controller_url(url) {
        warn_if_insecure_http_endpoint(&endpoint);
    }
}

fn warn_if_insecure_http_endpoint(endpoint: &ControllerEndpoint) {
    if endpoint.scheme == ControllerUrlScheme::Http {
        eprintln!(
            "{}",
            format_warning_message(format!(
                "insecure HTTP controller URL enabled: {}; HTTP is test-only and not encrypted; use HTTPS for product or production environments",
                endpoint.api_url("").trim_end_matches('/')
            ))
        );
    }
}

#[derive(Debug, Clone)]
struct LocalAgentConfig {
    url: String,
    tls_ca_cert: Option<PathBuf>,
    agent_id: String,
    fingerprint: String,
    private_key: String,
    controller_fingerprint: String,
    replay_store_path: PathBuf,
    delivery_journal_path: PathBuf,
    controller_trust_bundle_path: PathBuf,
    controller_trust_bundle: Option<fleet_domain::ControllerSigningTrustBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AgentControllerTrustBundleSidecar {
    entries: Vec<fleet_protocol::ControllerSigningTrustEntryWire>,
}

#[derive(Debug, Clone, Copy)]
struct AgentHeartbeatOptions {
    once: bool,
    heartbeat_interval: Duration,
    facts_interval: Duration,
    metrics_interval: Duration,
    log_upload: AgentLogUploadOptions,
    max_reconnect_attempts: u32,
}

#[derive(Debug, Clone, Copy)]
struct AgentLogUploadOptions {
    enabled: bool,
    interval: Duration,
}

fn read_agent_config(path: &Path) -> Result<LocalAgentConfig, CliError> {
    validate_secure_file_permissions(path)?;
    let body = fs::read_to_string(path)?;
    let value = |key: &str| {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(str::to_owned)
            .ok_or_else(|| CliError::Http(format!("missing agent config key: {key}")))
    };
    let optional_value = |key: &str| {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(PathBuf::from)
    };
    let private_key_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("agent_private.key");
    validate_secure_file_permissions(&private_key_path)?;
    let private_key = fs::read_to_string(private_key_path)?.trim().to_owned();
    let controller_trust_bundle_path = agent_controller_trust_bundle_path(path);
    let controller_trust_bundle =
        read_agent_controller_trust_bundle_sidecar(&controller_trust_bundle_path)?;
    Ok(LocalAgentConfig {
        url: value("url")?,
        tls_ca_cert: optional_value("tls_ca_cert"),
        agent_id: value("agent_id")?,
        fingerprint: value("fingerprint")?,
        private_key,
        controller_fingerprint: value("controller_fingerprint")?,
        replay_store_path: agent_replay_store_path(path),
        delivery_journal_path: agent_delivery_journal_path(path),
        controller_trust_bundle_path,
        controller_trust_bundle,
    })
}

fn agent_replay_store_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("task_nonces.log")
}

fn agent_delivery_journal_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("journal")
        .join("reports.sqlite3")
}

fn agent_controller_trust_bundle_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("controller_trust_bundle.json")
}

fn agent_nonce_replay_guard(
    config: &LocalAgentConfig,
) -> Result<fleet_runner::NonceReplayGuard, CliError> {
    fleet_runner::NonceReplayGuard::file_backed(&config.replay_store_path)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn legacy_controller_signing_trust_bundle(
    config: &LocalAgentConfig,
    controller_public_key: &str,
) -> Result<fleet_domain::ControllerSigningTrustBundle, CliError> {
    let fingerprint =
        fleet_domain::SigningKeyFingerprint::new(config.controller_fingerprint.clone())
            .map_err(|error| CliError::Http(error.to_string()))?;
    let public_key =
        fleet_domain::ControllerSigningPublicKey::new(controller_public_key.to_owned())
            .map_err(|error| CliError::Http(error.to_string()))?;
    fleet_domain::ControllerSigningTrustBundle::from_legacy_pinned(fingerprint, public_key)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn controller_signing_trust_bundle_from_wire(
    entries: &[fleet_protocol::ControllerSigningTrustEntryWire],
) -> Result<fleet_domain::ControllerSigningTrustBundle, CliError> {
    let mut domain_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let role = match entry.role {
            fleet_protocol::ControllerSigningTrustRoleWire::Current => {
                fleet_domain::ControllerSigningTrustRole::Current
            }
            fleet_protocol::ControllerSigningTrustRoleWire::Previous => {
                fleet_domain::ControllerSigningTrustRole::Previous
            }
        };
        domain_entries.push(
            fleet_domain::ControllerSigningTrustEntry::new(
                role,
                fleet_domain::SigningKeyFingerprint::new(entry.fingerprint.clone())
                    .map_err(|error| CliError::Http(error.to_string()))?,
                fleet_domain::ControllerSigningPublicKey::new(entry.public_key.clone())
                    .map_err(|error| CliError::Http(error.to_string()))?,
                millis_to_system_time(entry.valid_from_ms),
                entry.valid_until_ms.map(millis_to_system_time),
            )
            .map_err(|error| CliError::Http(error.to_string()))?,
        );
    }
    fleet_domain::ControllerSigningTrustBundle::new(domain_entries)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn controller_signing_trust_bundle_to_wire(
    bundle: &fleet_domain::ControllerSigningTrustBundle,
) -> Vec<fleet_protocol::ControllerSigningTrustEntryWire> {
    bundle
        .entries()
        .iter()
        .map(|entry| fleet_protocol::ControllerSigningTrustEntryWire {
            fingerprint: entry.fingerprint().as_str().to_owned(),
            public_key: entry.public_key().as_str().to_owned(),
            role: match entry.role() {
                fleet_domain::ControllerSigningTrustRole::Current => {
                    fleet_protocol::ControllerSigningTrustRoleWire::Current
                }
                fleet_domain::ControllerSigningTrustRole::Previous => {
                    fleet_protocol::ControllerSigningTrustRoleWire::Previous
                }
            },
            valid_from_ms: system_time_to_millis(entry.valid_from()),
            valid_until_ms: entry.valid_until().map(system_time_to_millis),
        })
        .collect()
}

fn read_agent_controller_trust_bundle_sidecar(
    path: &Path,
) -> Result<Option<fleet_domain::ControllerSigningTrustBundle>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    validate_secure_file_permissions(path)?;
    let body = fs::read_to_string(path)?;
    let sidecar: AgentControllerTrustBundleSidecar =
        serde_json::from_str(&body).map_err(|error| {
            CliError::Http(format!("invalid controller trust bundle sidecar: {error}"))
        })?;
    controller_signing_trust_bundle_from_wire(&sidecar.entries).map(Some)
}

fn write_agent_controller_trust_bundle_sidecar(
    path: &Path,
    bundle: &fleet_domain::ControllerSigningTrustBundle,
) -> Result<(), CliError> {
    let sidecar = AgentControllerTrustBundleSidecar {
        entries: controller_signing_trust_bundle_to_wire(bundle),
    };
    let body = serde_json::to_string_pretty(&sidecar).map_err(|error| {
        CliError::Http(format!(
            "serialize controller trust bundle sidecar: {error}"
        ))
    })?;
    write_secure_file_atomic(path, &format!("{body}\n"))?;
    Ok(())
}

fn validate_pinned_controller_identity(
    config: &LocalAgentConfig,
    identity: &fleet_controller::ControllerIdentityResponse,
) -> Result<(), CliError> {
    let observed_fingerprint = controller_signing_fingerprint(identity);
    if observed_fingerprint != config.controller_fingerprint {
        return Err(CliError::Http(format!(
            "controller signing fingerprint changed from {} to {}; explicit re-enroll is required because this may indicate controller key rotation or a security issue",
            config.controller_fingerprint, observed_fingerprint
        )));
    }
    Ok(())
}

fn controller_signing_fingerprint(identity: &fleet_controller::ControllerIdentityResponse) -> &str {
    if identity.controller_signing_fingerprint.is_empty() {
        &identity.controller_fingerprint
    } else {
        &identity.controller_signing_fingerprint
    }
}

fn controller_signing_public_key(identity: &fleet_controller::ControllerIdentityResponse) -> &str {
    if identity.controller_signing_public_key.is_empty() {
        &identity.controller_public_key
    } else {
        &identity.controller_signing_public_key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSessionEnd {
    ControllerClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct AgentSessionTickActions {
    heartbeat: bool,
    facts: bool,
    metrics: bool,
    log: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentSessionInbound {
    Message(Box<fleet_protocol::WireMessage>),
    Idle,
    Closed,
}

fn run_agent_session_loop(
    config: &LocalAgentConfig,
    options: AgentHeartbeatOptions,
) -> Result<(), CliError> {
    let mut session_runtime = agent_session_runtime(config)?;
    run_agent_session_loop_with_state(
        &mut session_runtime,
        options,
        |runtime| run_agent_session_once(config, options, runtime),
        std::thread::sleep,
    )
}

fn run_agent_session_loop_with<F, S>(
    options: AgentHeartbeatOptions,
    mut session_once: F,
    mut sleep: S,
) -> Result<(), CliError>
where
    F: FnMut() -> Result<AgentSessionEnd, CliError>,
    S: FnMut(Duration),
{
    let mut reconnect_attempts = 0;
    loop {
        match session_once() {
            Ok(AgentSessionEnd::ControllerClosed) => {
                reconnect_attempts = 0;
                println!("agent session closed by controller");
                if options.once {
                    return Ok(());
                }
                sleep(options.heartbeat_interval);
            }
            Err(error) => {
                if is_fatal_agent_session_error(&error) {
                    return Err(error);
                }
                reconnect_attempts += 1;
                if options.once
                    || (options.max_reconnect_attempts != 0
                        && reconnect_attempts > options.max_reconnect_attempts)
                {
                    return Err(error);
                }
                eprintln!(
                    "{}",
                    format_warning_message(format!("agent session failed: {error}"))
                );
                sleep(reconnect_backoff(reconnect_attempts));
            }
        }
    }
}

fn run_agent_session_loop_with_state<T, F, S>(
    state: &mut T,
    options: AgentHeartbeatOptions,
    mut session_once: F,
    sleep: S,
) -> Result<(), CliError>
where
    F: FnMut(&mut T) -> Result<AgentSessionEnd, CliError>,
    S: FnMut(Duration),
{
    run_agent_session_loop_with(options, || session_once(state), sleep)
}

#[cfg(test)]
fn run_agent_session_loop_with_state_for_test<T, F, S>(
    state: &mut T,
    options: AgentHeartbeatOptions,
    session_once: F,
    sleep: S,
) -> Result<(), CliError>
where
    F: FnMut(&mut T) -> Result<AgentSessionEnd, CliError>,
    S: FnMut(Duration),
{
    run_agent_session_loop_with_state(state, options, session_once, sleep)
}

fn is_fatal_agent_session_error(error: &CliError) -> bool {
    matches!(
        error,
        CliError::Http(message) if message.contains("controller signing fingerprint changed")
    )
}

fn agent_session_tick_actions(
    heartbeat_elapsed: Duration,
    facts_elapsed: Duration,
    metrics_elapsed: Duration,
    log_elapsed: Duration,
    options: AgentHeartbeatOptions,
) -> AgentSessionTickActions {
    AgentSessionTickActions {
        heartbeat: heartbeat_elapsed >= options.heartbeat_interval,
        facts: facts_elapsed >= options.facts_interval,
        metrics: metrics_elapsed >= options.metrics_interval,
        log: should_upload_agent_log(options.log_upload, log_elapsed),
    }
}

#[cfg(test)]
fn run_agent_heartbeat_loop_with<F, S>(
    options: AgentHeartbeatOptions,
    mut heartbeat_once: F,
    mut sleep: S,
) -> Result<(), CliError>
where
    F: FnMut(bool) -> Result<(), CliError>,
    S: FnMut(Duration),
{
    let mut reconnect_attempts = 0;
    let mut elapsed_since_log_upload = options.log_upload.interval;
    loop {
        let upload_log = should_upload_agent_log(options.log_upload, elapsed_since_log_upload);
        match heartbeat_once(upload_log) {
            Ok(()) => {
                reconnect_attempts = 0;
                println!("agent heartbeat sent");
                if options.once {
                    return Ok(());
                }
                elapsed_since_log_upload = if upload_log {
                    Duration::ZERO
                } else {
                    elapsed_since_log_upload.saturating_add(options.heartbeat_interval)
                };
                sleep(options.heartbeat_interval);
            }
            Err(error) => {
                reconnect_attempts += 1;
                if options.once
                    || (options.max_reconnect_attempts != 0
                        && reconnect_attempts > options.max_reconnect_attempts)
                {
                    return Err(error);
                }
                eprintln!(
                    "{}",
                    format_warning_message(format!("agent heartbeat failed: {error}"))
                );
                sleep(reconnect_backoff(reconnect_attempts));
            }
        }
    }
}

fn should_upload_agent_log(options: AgentLogUploadOptions, elapsed: Duration) -> bool {
    options.enabled && elapsed >= options.interval
}

fn reconnect_backoff(attempt: u32) -> Duration {
    Duration::from_secs(2_u64.saturating_pow(attempt.min(5)))
}

fn run_agent_heartbeat_once(
    config: &LocalAgentConfig,
    upload_agent_log: bool,
) -> Result<(), CliError> {
    let identity = controller_identity_via_controller(&config.url, config.tls_ca_cert.as_deref())?;
    validate_pinned_controller_identity(config, &identity)?;
    let endpoint = parse_controller_url(&config.url)?;
    let ws_url = endpoint.websocket_url("/api/agents/ws");
    let (mut socket, _) =
        connect_agent_websocket(&ws_url, &endpoint, config.tls_ca_cert.as_deref())?;
    let correlation_id = prefixed_ulid("corr")?;
    let _delivery_identity = perform_agent_session_handshake(&mut socket, config, &correlation_id)?;
    set_agent_socket_read_timeout(&mut socket, Some(Duration::from_secs(10)))?;

    let heartbeat = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.clone(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::Heartbeat {
            agent_id: config.agent_id.clone(),
            status: "online".to_owned(),
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&heartbeat)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;

    send_wire_message_to_socket(
        &mut socket,
        &agent_capability_snapshot_message(config, &correlation_id)?,
    )?;
    send_facts_snapshot(&mut socket, config, &correlation_id)?;
    send_metrics_snapshot(&mut socket, config, &correlation_id)?;
    if upload_agent_log {
        send_agent_log_chunk(
            &mut socket,
            config,
            &correlation_id,
            &agent_operational_log_line(config),
        )?;
    }
    read_and_handle_task_assignment(
        &mut socket,
        config,
        controller_signing_public_key(&identity),
        &correlation_id,
    )?;

    Ok(())
}

type AgentWebSocket = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>;
type AgentOutboundQueue =
    Arc<Mutex<fleet_agent::AgentSessionSupervisor<fleet_protocol::WireMessage>>>;

#[derive(Default)]
struct AgentTaskRuntimeState {
    current_task_id: Mutex<Option<String>>,
    cancel_requested: AtomicBool,
}

#[derive(Clone)]
struct AgentTaskSessionState {
    busy: Arc<AtomicBool>,
    runtime: Arc<AgentTaskRuntimeState>,
    replay_guard: Arc<Mutex<fleet_runner::NonceReplayGuard>>,
    controller_trust_bundle: Arc<Mutex<Option<fleet_domain::ControllerSigningTrustBundle>>>,
    journal_client: Arc<Mutex<Option<fleet_agent::journal_worker::JournalClient>>>,
    delivery_identity: Arc<Mutex<Option<ControllerDeliveryIdentity>>>,
}

struct AgentSessionRuntime {
    task_state: AgentTaskSessionState,
    connection: fleet_agent::AgentSessionSupervisor<()>,
    outbound_queue: AgentOutboundQueue,
    journal_worker: Option<fleet_agent::journal_worker::JournalWorker>,
    journal_namespace: Option<String>,
}

struct AgentTaskExecutionSession<'a> {
    outbound_sender: &'a AgentOutboundQueue,
    config: &'a LocalAgentConfig,
    controller_public_key: &'a str,
    correlation_id: &'a str,
    task_state: &'a AgentTaskSessionState,
    journal_client: &'a fleet_agent::journal_worker::JournalClient,
    controller_namespace: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentControllerSigningTrustBundleUpdateOutcome {
    current_fingerprint: String,
    entries_count: usize,
}

impl AgentTaskRuntimeState {
    fn start_task(&self, task_id: &str) -> Result<(), CliError> {
        let mut current = self
            .current_task_id
            .lock()
            .map_err(|_| CliError::Http("agent task runtime lock poisoned".to_owned()))?;
        *current = Some(task_id.to_owned());
        self.cancel_requested.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn request_cancel(&self, task_id: &str) -> Result<bool, CliError> {
        let current = self
            .current_task_id
            .lock()
            .map_err(|_| CliError::Http("agent task runtime lock poisoned".to_owned()))?;
        if current.as_deref() == Some(task_id) {
            self.cancel_requested.store(true, Ordering::SeqCst);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn should_cancel(&self, task_id: &str) -> bool {
        if !self.cancel_requested.load(Ordering::SeqCst) {
            return false;
        }
        self.current_task_id
            .lock()
            .map(|current| current.as_deref() == Some(task_id))
            .unwrap_or(false)
    }

    fn finish_task(&self, task_id: &str) {
        if let Ok(mut current) = self.current_task_id.lock()
            && current.as_deref() == Some(task_id)
        {
            *current = None;
            self.cancel_requested.store(false, Ordering::SeqCst);
        }
    }
}

fn apply_agent_controller_signing_trust_bundle_update(
    task_state: &AgentTaskSessionState,
    entries: &[fleet_protocol::ControllerSigningTrustEntryWire],
    persistence_path: Option<&Path>,
) -> Result<AgentControllerSigningTrustBundleUpdateOutcome, CliError> {
    let bundle = controller_signing_trust_bundle_from_wire(entries)?;
    let current_fingerprint = bundle
        .entries()
        .iter()
        .find(|entry| entry.role() == fleet_domain::ControllerSigningTrustRole::Current)
        .map(|entry| entry.fingerprint().as_str().to_owned())
        .ok_or_else(|| {
            CliError::Http("controller signing trust bundle is missing current entry".to_owned())
        })?;
    let entries_count = bundle.entries().len();
    if let Some(path) = persistence_path {
        write_agent_controller_trust_bundle_sidecar(path, &bundle)?;
    }
    let mut runtime_bundle = task_state
        .controller_trust_bundle
        .lock()
        .map_err(|_| CliError::Http("agent controller trust bundle lock poisoned".to_owned()))?;
    *runtime_bundle = Some(bundle);
    Ok(AgentControllerSigningTrustBundleUpdateOutcome {
        current_fingerprint,
        entries_count,
    })
}

fn agent_task_session_state(config: &LocalAgentConfig) -> Result<AgentTaskSessionState, CliError> {
    Ok(AgentTaskSessionState {
        busy: Arc::new(AtomicBool::new(false)),
        runtime: Arc::new(AgentTaskRuntimeState::default()),
        replay_guard: Arc::new(Mutex::new(agent_nonce_replay_guard(config)?)),
        controller_trust_bundle: Arc::new(Mutex::new(config.controller_trust_bundle.clone())),
        journal_client: Arc::new(Mutex::new(None)),
        delivery_identity: Arc::new(Mutex::new(None)),
    })
}

fn agent_session_runtime(config: &LocalAgentConfig) -> Result<AgentSessionRuntime, CliError> {
    Ok(AgentSessionRuntime {
        task_state: agent_task_session_state(config)?,
        connection: fleet_agent::AgentSessionSupervisor::new(0),
        outbound_queue: Arc::new(Mutex::new(fleet_agent::AgentSessionSupervisor::new(
            AGENT_SESSION_OUTBOUND_QUEUE_CAPACITY,
        ))),
        journal_worker: None,
        journal_namespace: None,
    })
}

fn ensure_agent_journal_worker(
    runtime: &mut AgentSessionRuntime,
    config: &LocalAgentConfig,
    delivery_identity: &ControllerDeliveryIdentity,
) -> Result<fleet_agent::journal_worker::JournalClient, CliError> {
    if let Some(bound_namespace) = runtime.journal_namespace.as_deref() {
        if bound_namespace != delivery_identity.namespace {
            return Err(CliError::Http(
                "agent journal belongs to a different controller identity".to_owned(),
            ));
        }
    } else {
        ensure_agent_journal_directory(&config.delivery_journal_path)?;
        let repository = fleet_store::agent_journal::SqliteAgentJournal::open(
            &config.delivery_journal_path,
            &delivery_identity.namespace,
            &config.agent_id,
        )
        .map_err(|error| CliError::Http(error.to_string()))?;
        let capacity = fleet_domain::delivery::JournalCapacity::new(
            fleet_domain::delivery::JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            fleet_domain::delivery::JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .map_err(|error| CliError::Http(error.to_string()))?;
        let limits = fleet_agent::journal_worker::JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .map_err(|error| CliError::Http(error.to_string()))?;
        let worker =
            fleet_agent::journal_worker::JournalWorker::spawn(repository, capacity, limits)
                .map_err(|error| CliError::Http(error.to_string()))?;
        runtime.journal_namespace = Some(delivery_identity.namespace.clone());
        runtime.journal_worker = Some(worker);
    }

    let client = runtime
        .journal_worker
        .as_ref()
        .ok_or_else(|| CliError::Http("agent journal worker is unavailable".to_owned()))?
        .client();
    if !runtime.task_state.busy.load(Ordering::SeqCst) {
        recover_interrupted_agent_execution(&client)?;
    }
    *runtime
        .task_state
        .journal_client
        .lock()
        .map_err(|_| CliError::Http("agent journal client lock poisoned".to_owned()))? =
        Some(client.clone());
    *runtime
        .task_state
        .delivery_identity
        .lock()
        .map_err(|_| CliError::Http("agent delivery identity lock poisoned".to_owned()))? =
        Some(delivery_identity.clone());
    Ok(client)
}

fn ensure_agent_journal_directory(path: &Path) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Http("agent journal path has no parent".to_owned()))?;
    let agent_directory = parent
        .parent()
        .ok_or_else(|| CliError::Http("agent journal path has no owner directory".to_owned()))?;
    fs::create_dir_all(agent_directory)?;
    let owner_metadata = fs::symlink_metadata(agent_directory)?;
    if owner_metadata.file_type().is_symlink() || !owner_metadata.is_dir() {
        return Err(CliError::Http(
            "agent journal owner path is not a directory".to_owned(),
        ));
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliError::Http(
                    "agent journal path is not a directory".to_owned(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CliError::Io(error)),
            }
        }
        Err(error) => return Err(CliError::Io(error)),
    }
    Ok(())
}

fn agent_controller_signing_trust_bundle(
    task_state: &AgentTaskSessionState,
    config: &LocalAgentConfig,
    controller_public_key: &str,
) -> Result<fleet_domain::ControllerSigningTrustBundle, CliError> {
    let runtime_bundle = task_state
        .controller_trust_bundle
        .lock()
        .map_err(|_| CliError::Http("agent controller trust bundle lock poisoned".to_owned()))?
        .clone();
    runtime_bundle
        .map(Ok)
        .unwrap_or_else(|| legacy_controller_signing_trust_bundle(config, controller_public_key))
}

fn verify_agent_task_envelope_once_with_session_trust(
    envelope: &fleet_domain::TaskEnvelope,
    config: &LocalAgentConfig,
    controller_public_key: &str,
    task_state: &AgentTaskSessionState,
    now: SystemTime,
) -> Result<
    Result<fleet_domain::ControllerSigningTrustVerification, fleet_runner::RunnerError>,
    CliError,
> {
    let trust_bundle =
        agent_controller_signing_trust_bundle(task_state, config, controller_public_key)?;
    let verifier = ControllerSignatureVerifier;
    let agent_id = fleet_domain::AgentId::new(config.agent_id.clone())
        .map_err(|error| CliError::Http(error.to_string()))?;
    let mut replay_guard = task_state
        .replay_guard
        .lock()
        .map_err(|_| CliError::Http("agent nonce replay guard lock poisoned".to_owned()))?;
    Ok(
        fleet_runner::verify_signed_envelope_once_with_controller_trust(
            envelope,
            &agent_id,
            now,
            &trust_bundle,
            None,
            &verifier,
            &mut replay_guard,
        ),
    )
}

fn run_agent_session_once(
    config: &LocalAgentConfig,
    options: AgentHeartbeatOptions,
    runtime: &mut AgentSessionRuntime,
) -> Result<AgentSessionEnd, CliError> {
    runtime
        .connection
        .begin_connect()
        .map_err(|_| CliError::Http("invalid agent session connection transition".to_owned()))?;
    let result = run_agent_session_connected_once(config, options, runtime);
    runtime.connection.connection_lost();
    result
}

fn run_agent_session_connected_once(
    config: &LocalAgentConfig,
    options: AgentHeartbeatOptions,
    runtime: &mut AgentSessionRuntime,
) -> Result<AgentSessionEnd, CliError> {
    let identity = controller_identity_via_controller(&config.url, config.tls_ca_cert.as_deref())?;
    validate_pinned_controller_identity(config, &identity)?;
    let endpoint = parse_controller_url(&config.url)?;
    let ws_url = endpoint.websocket_url("/api/agents/ws");
    let (mut socket, _) =
        connect_agent_websocket(&ws_url, &endpoint, config.tls_ca_cert.as_deref())?;
    set_agent_socket_read_timeout(&mut socket, Some(AGENT_SESSION_READ_POLL_INTERVAL))?;
    let correlation_id = prefixed_ulid("corr")?;

    let delivery_identity = perform_agent_session_handshake(&mut socket, config, &correlation_id)?;
    let journal_client = ensure_agent_journal_worker(runtime, config, &delivery_identity)?;
    let mut report_delivery =
        AgentJournalReportDelivery::new(journal_client, delivery_identity.clone());
    runtime.connection.mark_authenticated().map_err(|_| {
        CliError::Http("invalid agent session authentication transition".to_owned())
    })?;

    enqueue_initial_agent_session_messages(
        &runtime.outbound_queue,
        config,
        &correlation_id,
        options,
    )?;

    let mut last_heartbeat = Instant::now();
    let mut last_facts = Instant::now();
    let mut last_metrics = Instant::now();
    let mut last_log = if options.log_upload.enabled {
        Instant::now()
    } else {
        Instant::now() - options.log_upload.interval
    };

    loop {
        report_delivery.drive(&mut socket, config, &correlation_id)?;
        flush_agent_outbound_queue(&mut socket, &runtime.outbound_queue)?;

        match read_agent_session_message(&mut socket)? {
            AgentSessionInbound::Message(message) => {
                let message = *message;
                if let fleet_protocol::WirePayload::ReportReceipt(receipt) = &message.payload {
                    report_delivery.handle_receipt(
                        &message,
                        receipt,
                        config,
                        controller_signing_public_key(&identity),
                        &correlation_id,
                        &runtime.task_state,
                    )?;
                } else {
                    handle_agent_session_message(
                        message,
                        config,
                        controller_signing_public_key(&identity),
                        &correlation_id,
                        &runtime.outbound_queue,
                        &runtime.task_state,
                    )?;
                }
            }
            AgentSessionInbound::Idle => {}
            AgentSessionInbound::Closed => return Ok(AgentSessionEnd::ControllerClosed),
        }

        let now = Instant::now();
        let actions = agent_session_tick_actions(
            now.saturating_duration_since(last_heartbeat),
            now.saturating_duration_since(last_facts),
            now.saturating_duration_since(last_metrics),
            now.saturating_duration_since(last_log),
            options,
        );
        enqueue_agent_session_tick_messages(
            &runtime.outbound_queue,
            config,
            &correlation_id,
            actions,
        )?;
        if actions.heartbeat {
            last_heartbeat = now;
        }
        if actions.facts {
            last_facts = now;
        }
        if actions.metrics {
            last_metrics = now;
        }
        if actions.log {
            last_log = now;
        }
        flush_agent_outbound_queue(&mut socket, &runtime.outbound_queue)?;
        report_delivery.drive(&mut socket, config, &correlation_id)?;
    }
}

fn enqueue_agent_session_tick_messages(
    outbound_sender: &AgentOutboundQueue,
    config: &LocalAgentConfig,
    correlation_id: &str,
    actions: AgentSessionTickActions,
) -> Result<(), CliError> {
    if actions.heartbeat {
        enqueue_wire_message(
            outbound_sender,
            agent_heartbeat_message(config, correlation_id)?,
        )?;
    }
    if actions.facts {
        enqueue_wire_message(
            outbound_sender,
            agent_facts_snapshot_message(config, correlation_id)?,
        )?;
    }
    if actions.metrics {
        enqueue_wire_message(
            outbound_sender,
            agent_metrics_snapshot_message(config, correlation_id)?,
        )?;
    }
    if actions.log {
        enqueue_wire_message(
            outbound_sender,
            agent_log_chunk_message(config, correlation_id, &agent_operational_log_line(config))?,
        )?;
    }
    Ok(())
}

fn perform_agent_session_handshake(
    socket: &mut AgentWebSocket,
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<ControllerDeliveryIdentity, CliError> {
    send_wire_message_to_socket(
        socket,
        &fleet_protocol::WireMessage::new(
            prefixed_ulid("msg")?,
            correlation_id.to_owned(),
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::AgentHello {
                agent_id: config.agent_id.clone(),
                fingerprint: config.fingerprint.clone(),
            },
        ),
    )?;

    let challenge = read_ws_message(socket)?;
    let fleet_protocol::WirePayload::AuthChallenge { nonce } = challenge.payload else {
        return Err(CliError::Http("expected auth challenge".to_owned()));
    };

    send_wire_message_to_socket(
        socket,
        &fleet_protocol::WireMessage::new(
            prefixed_ulid("msg")?,
            correlation_id.to_owned(),
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::AuthResponse {
                nonce: nonce.clone(),
                signature: fleet_core::sign_challenge(&config.private_key, &nonce)?,
            },
        ),
    )?;

    let accepted = read_ws_message(socket)?;
    controller_delivery_identity_from_auth_accepted(accepted, &config.agent_id, correlation_id)
}

fn controller_delivery_identity_from_auth_accepted(
    message: fleet_protocol::WireMessage,
    expected_agent_id: &str,
    expected_correlation_id: &str,
) -> Result<ControllerDeliveryIdentity, CliError> {
    if message.agent_id.as_deref() != Some(expected_agent_id)
        || message.correlation_id.0 != expected_correlation_id
    {
        return Err(CliError::Http(
            "auth accepted session identity mismatch".to_owned(),
        ));
    }
    let fleet_protocol::WirePayload::AuthAccepted {
        controller_namespace,
        store_epoch,
    } = message.payload
    else {
        return Err(CliError::Http("expected auth accepted".to_owned()));
    };
    if !controller_delivery_identity_component_is_valid(&controller_namespace)
        || !controller_delivery_identity_component_is_valid(&store_epoch)
    {
        return Err(CliError::Http(
            "controller delivery identity is invalid".to_owned(),
        ));
    }
    Ok(ControllerDeliveryIdentity {
        namespace: controller_namespace,
        store_epoch,
    })
}

fn controller_delivery_identity_component_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn enqueue_initial_agent_session_messages(
    outbound_sender: &AgentOutboundQueue,
    config: &LocalAgentConfig,
    correlation_id: &str,
    options: AgentHeartbeatOptions,
) -> Result<(), CliError> {
    enqueue_wire_message(
        outbound_sender,
        agent_heartbeat_message(config, correlation_id)?,
    )?;
    enqueue_wire_message(
        outbound_sender,
        agent_capability_snapshot_message(config, correlation_id)?,
    )?;
    enqueue_wire_message(
        outbound_sender,
        agent_facts_snapshot_message(config, correlation_id)?,
    )?;
    enqueue_wire_message(
        outbound_sender,
        agent_metrics_snapshot_message(config, correlation_id)?,
    )?;
    if options.log_upload.enabled {
        enqueue_wire_message(
            outbound_sender,
            agent_log_chunk_message(config, correlation_id, &agent_operational_log_line(config))?,
        )?;
    }
    Ok(())
}

fn flush_agent_outbound_queue(
    socket: &mut AgentWebSocket,
    outbound_queue: &AgentOutboundQueue,
) -> Result<(), CliError> {
    flush_agent_outbound_queue_with(outbound_queue, |message| {
        send_wire_message_to_socket(socket, message)
    })
}

/// Gives the sole socket writer each queued report and removes it only after a successful write.
fn flush_agent_outbound_queue_with<F>(
    outbound_queue: &AgentOutboundQueue,
    mut write_message: F,
) -> Result<(), CliError>
where
    F: FnMut(&fleet_protocol::WireMessage) -> Result<(), CliError>,
{
    loop {
        let message = outbound_queue
            .lock()
            .map_err(|_| CliError::Http("agent outbound queue lock poisoned".to_owned()))?
            .pending_report()
            .cloned();
        let Some(message) = message else {
            return Ok(());
        };
        write_message(&message)?;
        let removed = outbound_queue
            .lock()
            .map_err(|_| CliError::Http("agent outbound queue lock poisoned".to_owned()))?
            .remove_pending_report();
        debug_assert!(removed.is_some());
    }
}

fn read_agent_session_message(
    socket: &mut AgentWebSocket,
) -> Result<AgentSessionInbound, CliError> {
    match socket.read() {
        Ok(message) if message.is_close() => Ok(AgentSessionInbound::Closed),
        Ok(message) => {
            let body = message
                .to_text()
                .map_err(|error| CliError::Http(error.to_string()))?;
            let message = fleet_protocol::decode_message(body)
                .map_err(|error| CliError::Http(error.to_string()))?;
            Ok(AgentSessionInbound::Message(Box::new(message)))
        }
        Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
            Ok(AgentSessionInbound::Closed)
        }
        Err(error) if agent_session_read_error_is_idle(&error) => Ok(AgentSessionInbound::Idle),
        Err(error) => Err(CliError::Http(error.to_string())),
    }
}

/// Classifies recoverable socket read interruptions without ending the Agent session.
fn agent_session_read_error_is_idle(error: &tungstenite::Error) -> bool {
    matches!(
        error,
        tungstenite::Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            )
    )
}

fn handle_agent_session_message(
    message: fleet_protocol::WireMessage,
    config: &LocalAgentConfig,
    controller_public_key: &str,
    correlation_id: &str,
    outbound_sender: &AgentOutboundQueue,
    task_state: &AgentTaskSessionState,
) -> Result<(), CliError> {
    let (envelope, task) = match message.payload {
        fleet_protocol::WirePayload::TaskAssignment { envelope, task } => (envelope, task),
        fleet_protocol::WirePayload::TaskCancel {
            job_id,
            task_id,
            reason,
        } => {
            let _ = job_id;
            let _ = reason;
            let _ = task_state.runtime.request_cancel(&task_id)?;
            return Ok(());
        }
        fleet_protocol::WirePayload::ControllerSigningTrustBundleUpdate { entries } => {
            match apply_agent_controller_signing_trust_bundle_update(
                task_state,
                &entries,
                Some(&config.controller_trust_bundle_path),
            ) {
                Ok(outcome) => {
                    enqueue_wire_message(
                        outbound_sender,
                        agent_controller_signing_trust_bundle_ack_message(
                            config,
                            correlation_id,
                            true,
                            Some(&outcome.current_fingerprint),
                            outcome.entries_count,
                            None,
                        )?,
                    )?;
                    send_agent_security_event_queue(
                        outbound_sender,
                        config,
                        correlation_id,
                        "controller_signing_trust_bundle_update_accepted",
                        "controller signing trust bundle update accepted",
                    )?;
                }
                Err(error) => {
                    enqueue_wire_message(
                        outbound_sender,
                        agent_controller_signing_trust_bundle_ack_message(
                            config,
                            correlation_id,
                            false,
                            None,
                            entries.len(),
                            Some("invalid_trust_bundle"),
                        )?,
                    )?;
                    send_agent_security_event_queue(
                        outbound_sender,
                        config,
                        correlation_id,
                        "controller_signing_trust_bundle_update_rejected",
                        &error.to_string(),
                    )?;
                }
            }
            return Ok(());
        }
        fleet_protocol::WirePayload::AgentCertificateLifecycleUpdate { state, .. } => {
            enqueue_wire_message(
                outbound_sender,
                agent_certificate_lifecycle_ack_message(
                    config,
                    correlation_id,
                    false,
                    state,
                    None,
                    Some(AGENT_CERTIFICATE_LIFECYCLE_RUNTIME_NOT_IMPLEMENTED),
                )?,
            )?;
            send_agent_security_event_queue(
                outbound_sender,
                config,
                correlation_id,
                "agent_certificate_lifecycle_update_rejected",
                "agent certificate lifecycle runtime handling is not implemented",
            )?;
            return Ok(());
        }
        _ => return Ok(()),
    };
    if task_state.busy.swap(true, Ordering::SeqCst) {
        let journal_client = task_state
            .journal_client
            .lock()
            .map_err(|_| CliError::Http("agent journal client lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| CliError::Http("agent journal client is unavailable".to_owned()))?;
        let delivery_identity = task_state
            .delivery_identity
            .lock()
            .map_err(|_| CliError::Http("agent delivery identity lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| CliError::Http("agent delivery identity is unavailable".to_owned()))?;
        persist_agent_task_rejected_report_with_journal(
            &journal_client,
            &delivery_identity.namespace,
            config,
            &envelope.job_id,
            &envelope.task_id,
            fleet_protocol::TaskRejectionReasonCode::AgentBusy,
            "agent is busy",
        )?;
        return Ok(());
    }
    let worker_context = (|| {
        let journal_client = task_state
            .journal_client
            .lock()
            .map_err(|_| CliError::Http("agent journal client lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| CliError::Http("agent journal client is unavailable".to_owned()))?;
        let delivery_identity = task_state
            .delivery_identity
            .lock()
            .map_err(|_| CliError::Http("agent delivery identity lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| CliError::Http("agent delivery identity is unavailable".to_owned()))?;
        Ok::<_, CliError>((journal_client, delivery_identity))
    })();
    let (journal_client, delivery_identity) = match worker_context {
        Ok(context) => context,
        Err(error) => {
            task_state.busy.store(false, Ordering::SeqCst);
            return Err(error);
        }
    };
    if let Err(error) = task_state.runtime.start_task(&envelope.task_id) {
        task_state.busy.store(false, Ordering::SeqCst);
        return Err(error);
    }

    let worker_config = config.clone();
    let worker_public_key = controller_public_key.to_owned();
    let worker_correlation_id = correlation_id.to_owned();
    let worker_sender = outbound_sender.clone();
    let worker_task_state = task_state.clone();
    let worker_journal_client = journal_client.clone();
    let worker_delivery_namespace = delivery_identity.namespace.clone();
    let worker_task_id = envelope.task_id.clone();
    thread::spawn(move || {
        let session = AgentTaskExecutionSession {
            outbound_sender: &worker_sender,
            config: &worker_config,
            controller_public_key: &worker_public_key,
            correlation_id: &worker_correlation_id,
            task_state: &worker_task_state,
            journal_client: &worker_journal_client,
            controller_namespace: &worker_delivery_namespace,
        };
        if let Err(error) = handle_task_assignment_with_queue(&session, envelope, task) {
            let _ = enqueue_wire_message(
                &worker_sender,
                agent_security_event_message(
                    &worker_config,
                    &worker_correlation_id,
                    "task_worker_failed",
                    &error.to_string(),
                )
                .unwrap_or_else(|_| {
                    fleet_protocol::WireMessage::new(
                        "msg-task-worker-failed",
                        worker_correlation_id.clone(),
                        Some(worker_config.agent_id.clone()),
                        epoch_millis() as u64,
                        fleet_protocol::WirePayload::SecurityEvent {
                            agent_id: worker_config.agent_id.clone(),
                            action: "task_worker_failed".to_owned(),
                            detail: "task worker failed".to_owned(),
                        },
                    )
                }),
            );
        }
        worker_task_state.runtime.finish_task(&worker_task_id);
        worker_task_state.busy.store(false, Ordering::SeqCst);
    });
    Ok(())
}

fn set_agent_socket_read_timeout(
    socket: &mut AgentWebSocket,
    timeout: Option<Duration>,
) -> Result<(), CliError> {
    match socket.get_mut() {
        tungstenite::stream::MaybeTlsStream::Plain(stream) => stream.set_read_timeout(timeout)?,
        tungstenite::stream::MaybeTlsStream::Rustls(stream) => {
            stream.get_mut().set_read_timeout(timeout)?
        }
        #[allow(unreachable_patterns)]
        _ => {}
    }
    Ok(())
}

fn send_wire_message_to_socket(
    socket: &mut AgentWebSocket,
    message: &fleet_protocol::WireMessage,
) -> Result<(), CliError> {
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))
}

fn enqueue_wire_message(
    outbound_sender: &AgentOutboundQueue,
    message: fleet_protocol::WireMessage,
) -> Result<(), CliError> {
    outbound_sender
        .lock()
        .map_err(|_| CliError::Http("agent outbound queue lock poisoned".to_owned()))?
        .enqueue_report(message)
        .map_err(|error| match error {
            fleet_agent::AgentSessionSupervisorError::PendingReportsFull => {
                CliError::Http("agent outbound queue is full".to_owned())
            }
            _ => CliError::Http("invalid agent outbound queue transition".to_owned()),
        })
}

fn agent_heartbeat_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::Heartbeat {
            agent_id: config.agent_id.clone(),
            status: "online".to_owned(),
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentCapabilityProbe {
    privilege_level: fleet_protocol::CapabilityPrivilegeLevelWire,
    package_manager: Option<fleet_protocol::PackageManagerWire>,
    service_manager: Option<fleet_protocol::ServiceManagerWire>,
}

fn agent_capability_snapshot_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    let probe = collect_agent_capability_probe();
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::CapabilitySnapshot {
            agent_id: config.agent_id.clone(),
            privilege_level: probe.privilege_level,
            package_manager: probe.package_manager,
            service_manager: probe.service_manager,
            capabilities: agent_capability_names(&probe),
            reported_at_ms: epoch_millis() as u64,
        },
    ))
}

fn collect_agent_capability_probe() -> AgentCapabilityProbe {
    AgentCapabilityProbe {
        privilege_level: fleet_protocol::CapabilityPrivilegeLevelWire::Unprivileged,
        package_manager: fleet_runner::detect_local_linux_package_manager()
            .map(package_manager_to_wire),
        service_manager: detect_local_service_manager(),
    }
}

fn agent_capability_names(probe: &AgentCapabilityProbe) -> Vec<String> {
    let mut capabilities = vec![
        "persistent_session".to_owned(),
        "command_execution".to_owned(),
        "drift_check".to_owned(),
        "runbook_execution".to_owned(),
    ];
    if probe.package_manager.is_some() {
        capabilities.push("package_install".to_owned());
    }
    if probe.service_manager.is_some() {
        capabilities.push("service_control".to_owned());
    }
    capabilities
}

fn package_manager_to_wire(
    manager: fleet_runner::LinuxPackageManager,
) -> fleet_protocol::PackageManagerWire {
    match manager {
        fleet_runner::LinuxPackageManager::Apt => fleet_protocol::PackageManagerWire::Apt,
        fleet_runner::LinuxPackageManager::Dnf => fleet_protocol::PackageManagerWire::Dnf,
        fleet_runner::LinuxPackageManager::Yum => fleet_protocol::PackageManagerWire::Yum,
        fleet_runner::LinuxPackageManager::Apk => fleet_protocol::PackageManagerWire::Apk,
    }
}

fn detect_local_service_manager() -> Option<fleet_protocol::ServiceManagerWire> {
    if Path::new("/run/systemd/system").exists()
        || Path::new("/usr/bin/systemctl").exists()
        || Path::new("/bin/systemctl").exists()
    {
        Some(fleet_protocol::ServiceManagerWire::Systemd)
    } else {
        None
    }
}

fn agent_facts_snapshot_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::FactsSnapshot {
            agent_id: config.agent_id.clone(),
            body: collect_local_facts().to_string(),
        },
    ))
}

fn agent_metrics_snapshot_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::MetricsSnapshot {
            agent_id: config.agent_id.clone(),
            body: collect_local_metrics().to_string(),
        },
    ))
}

fn agent_log_chunk_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    line: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::LogChunk {
            agent_id: config.agent_id.clone(),
            line: redact_and_truncate_log_line(line),
        },
    ))
}

fn agent_controller_signing_trust_bundle_ack_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    accepted: bool,
    current_fingerprint: Option<&str>,
    entries_count: usize,
    reason_code: Option<&str>,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::ControllerSigningTrustBundleAck {
            agent_id: config.agent_id.clone(),
            accepted,
            current_fingerprint: current_fingerprint.map(str::to_owned),
            entries_count,
            reason_code: reason_code.map(str::to_owned),
        },
    ))
}

fn agent_certificate_lifecycle_ack_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    accepted: bool,
    state: fleet_protocol::AgentCertificateLifecycleStateWire,
    current_fingerprint: Option<&str>,
    reason_code: Option<&str>,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::AgentCertificateLifecycleAck {
            agent_id: config.agent_id.clone(),
            accepted,
            state,
            current_fingerprint: current_fingerprint.map(str::to_owned),
            reason_code: reason_code.map(str::to_owned),
        },
    ))
}

fn agent_security_event_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    action: &str,
    detail: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::SecurityEvent {
            agent_id: config.agent_id.clone(),
            action: action.to_owned(),
            detail: detail.to_owned(),
        },
    ))
}

fn send_agent_log_chunk(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    line: &str,
) -> Result<(), CliError> {
    let message = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::LogChunk {
            agent_id: config.agent_id.clone(),
            line: redact_and_truncate_log_line(line),
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

fn agent_operational_log_line(config: &LocalAgentConfig) -> String {
    format!(
        "level=info event=agent_heartbeat_completed agent_id={} status=online",
        config.agent_id
    )
}

fn send_facts_snapshot(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<(), CliError> {
    let body = collect_local_facts().to_string();
    let message = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::FactsSnapshot {
            agent_id: config.agent_id.clone(),
            body,
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

fn send_metrics_snapshot(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<(), CliError> {
    let body = collect_local_metrics().to_string();
    let message = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::MetricsSnapshot {
            agent_id: config.agent_id.clone(),
            body,
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

fn collect_local_facts() -> serde_json::Value {
    let system_time_ms = epoch_millis() as u64;
    let meminfo = read_optional_trimmed("/proc/meminfo");
    let network_body = read_optional_trimmed("/proc/net/dev");
    let network_interfaces = network_body
        .as_deref()
        .map(linux_network_interfaces)
        .unwrap_or_default();
    let memory_total_kb = meminfo
        .as_deref()
        .and_then(|body| linux_meminfo_kb(body, "MemTotal"));
    let memory_modules = collect_memory_module_inventory();
    let root_disk = collect_root_disk_usage();
    let mount_body = read_optional_trimmed("/proc/mounts");
    let mounts = mount_body.as_deref().map(parse_linux_mounts);
    let root_mount = mounts
        .as_ref()
        .and_then(|mounts| mounts.iter().find(|mount| mount.mount_point == "/"));
    let block_devices = collect_linux_block_devices(Path::new("/sys/block"));
    let mut degraded_signals = Vec::new();
    if memory_total_kb.is_none() {
        degraded_signals.push("memory_facts_unavailable");
    }
    if network_body.is_none() {
        degraded_signals.push("network_facts_unavailable");
    }
    if root_disk.is_none() && mounts.is_none() && block_devices.is_none() {
        degraded_signals.push("disk_inventory_unavailable");
    }

    serde_json::json!({
        "system_time_ms": system_time_ms,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "hostname": read_optional_trimmed("/proc/sys/kernel/hostname")
            .or_else(|| read_optional_trimmed("/etc/hostname")),
        "runtime": {
            "pid": std::process::id(),
            "executable": "fleet",
        },
        "cpu": {
            "logical_count": std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(0),
        },
        "memory": {
            "total_kb": memory_total_kb,
            "module_count_known": memory_modules.is_some(),
            "module_count": memory_modules.as_ref().map(|inventory| inventory.count),
            "module_count_source": memory_modules.as_ref().map(|inventory| inventory.source),
        },
        "disk": {
            "device_inventory_known": block_devices.is_some(),
            "device_count": block_devices.as_ref().map(Vec::len),
            "devices": block_devices.unwrap_or_default(),
            "mount_inventory_known": mounts.is_some(),
            "mount_count": mounts.as_ref().map(Vec::len),
            "mounts": mounts.clone().unwrap_or_default(),
            "root_mount_known": root_mount.is_some(),
            "root_source": root_mount.map(|mount| mount.source.as_str()),
            "root_fs_type": root_mount.map(|mount| mount.fs_type.as_str()),
            "root_capacity_known": root_disk.is_some(),
            "root_filesystem": root_disk.as_ref().map(|usage| usage.filesystem.as_str()),
            "root_total_kb": root_disk.as_ref().map(|usage| usage.total_kb),
        },
        "network": {
            "interfaces": network_interfaces,
        },
        "degraded": {
            "status": !degraded_signals.is_empty(),
            "signals": degraded_signals,
        },
    })
}

fn collect_local_metrics() -> serde_json::Value {
    let system_time_ms = epoch_millis() as u64;
    let meminfo = read_optional_trimmed("/proc/meminfo");
    let memory_usage = meminfo.as_deref().and_then(memory_usage_from_meminfo);
    let cpu_usage_percent = collect_cpu_usage_percent();
    let disk_usage = collect_root_disk_usage();
    let service_summary = collect_systemd_service_summary();

    serde_json::json!({
        "system_time_ms": system_time_ms,
        "cpu": {
            "logical_count": std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(0),
            "usage_percent": cpu_usage_percent,
        },
        "memory": {
            "usage_available": memory_usage.is_some(),
            "total_kb": memory_usage.as_ref().map(|usage| usage.total_kb),
            "used_kb": memory_usage.as_ref().map(|usage| usage.used_kb),
            "available_kb": memory_usage.as_ref().map(|usage| usage.available_kb),
            "used_percent": memory_usage.as_ref().map(|usage| usage.used_percent),
        },
        "disk": {
            "usage_available": disk_usage.is_some(),
            "filesystem": disk_usage.as_ref().map(|usage| usage.filesystem.as_str()),
            "total_kb": disk_usage.as_ref().map(|usage| usage.total_kb),
            "used_kb": disk_usage.as_ref().map(|usage| usage.used_kb),
            "available_kb": disk_usage.as_ref().map(|usage| usage.available_kb),
            "used_percent": disk_usage.as_ref().map(|usage| usage.used_percent),
        },
        "process": {
            "pid": std::process::id(),
            "count": linux_proc_process_count("/proc"),
        },
        "service": {
            "status_available": service_summary.status_available,
            "failed_units_count": service_summary.failed_units_count,
            "failed_units": service_summary.failed_units,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskUsage {
    filesystem: String,
    total_kb: u64,
    used_kb: u64,
    available_kb: u64,
    used_percent: u8,
}

fn collect_root_disk_usage() -> Option<DiskUsage> {
    let output = ProcessCommand::new("df").arg("-k").arg("/").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&output.stdout);
    parse_df_root_usage(&body)
}

fn parse_df_root_usage(body: &str) -> Option<DiskUsage> {
    let line = body.lines().find(|line| {
        line.split_whitespace()
            .last()
            .is_some_and(|mount| mount == "/")
    })?;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 6 {
        return None;
    }
    Some(DiskUsage {
        filesystem: parts.first()?.to_string(),
        total_kb: parts.get(1)?.parse().ok()?,
        used_kb: parts.get(2)?.parse().ok()?,
        available_kb: parts.get(3)?.parse().ok()?,
        used_percent: parts.get(4)?.trim_end_matches('%').parse().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct BlockDeviceFact {
    name: String,
    kind: String,
    size_kb: Option<u64>,
    removable: Option<bool>,
    rotational: Option<bool>,
    partitions: Vec<BlockPartitionFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct BlockPartitionFact {
    name: String,
    size_kb: Option<u64>,
}

fn collect_linux_block_devices(path: &Path) -> Option<Vec<BlockDeviceFact>> {
    let entries = fs::read_dir(path).ok()?;
    let mut devices = entries
        .filter_map(Result::ok)
        .filter_map(|entry| linux_block_device_from_sysfs_entry(&entry.path()))
        .collect::<Vec<_>>();
    devices.sort_by(|left, right| left.name.cmp(&right.name));
    Some(devices)
}

fn linux_block_device_from_sysfs_entry(path: &Path) -> Option<BlockDeviceFact> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if is_ignored_linux_block_device(&name) {
        return None;
    }
    Some(BlockDeviceFact {
        kind: linux_block_device_kind(&name).to_owned(),
        size_kb: read_optional_trimmed_path(&path.join("size"))
            .and_then(|value| value.parse::<u64>().ok())
            .map(|sectors| sectors / 2),
        removable: read_linux_bool_file(&path.join("removable")),
        rotational: read_linux_bool_file(&path.join("queue").join("rotational")),
        partitions: linux_block_device_partitions(path, &name),
        name,
    })
}

fn linux_block_device_partitions(path: &Path, device_name: &str) -> Vec<BlockPartitionFact> {
    let mut partitions = fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let partition_path = entry.path();
            let name = partition_path.file_name()?.to_string_lossy().to_string();
            if !linux_partition_name_matches(device_name, &name) {
                return None;
            }
            Some(BlockPartitionFact {
                size_kb: read_optional_trimmed_path(&partition_path.join("size"))
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(|sectors| sectors / 2),
                name,
            })
        })
        .collect::<Vec<_>>();
    partitions.sort_by(|left, right| left.name.cmp(&right.name));
    partitions
}

fn linux_partition_name_matches(device_name: &str, partition_name: &str) -> bool {
    if partition_name == device_name {
        return false;
    }
    let Some(suffix) = partition_name.strip_prefix(device_name) else {
        return false;
    };
    let suffix = if device_name.starts_with("nvme") || device_name.starts_with("mmcblk") {
        suffix.strip_prefix('p').unwrap_or("")
    } else {
        suffix
    };
    !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
}

fn is_ignored_linux_block_device(name: &str) -> bool {
    name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram")
}

fn linux_block_device_kind(name: &str) -> &'static str {
    if name.starts_with("nvme")
        || name.starts_with("sd")
        || name.starts_with("vd")
        || name.starts_with("xvd")
        || name.starts_with("hd")
        || name.starts_with("mmcblk")
    {
        "disk"
    } else {
        "block"
    }
}

fn read_linux_bool_file(path: &Path) -> Option<bool> {
    read_optional_trimmed_path(path).and_then(|value| match value.as_str() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct MountFact {
    source: String,
    mount_point: String,
    fs_type: String,
    read_only: bool,
}

fn parse_linux_mounts(body: &str) -> Vec<MountFact> {
    body.lines()
        .filter_map(parse_linux_mount_line)
        .collect::<Vec<_>>()
}

fn parse_linux_mount_line(line: &str) -> Option<MountFact> {
    let mut parts = line.split_whitespace();
    let source = decode_linux_mount_field(parts.next()?);
    let mount_point = decode_linux_mount_field(parts.next()?);
    let fs_type = decode_linux_mount_field(parts.next()?);
    let options = parts.next().unwrap_or("");
    Some(MountFact {
        source,
        mount_point,
        fs_type,
        read_only: options.split(',').any(|option| option == "ro"),
    })
}

fn decode_linux_mount_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryUsage {
    total_kb: u64,
    used_kb: u64,
    available_kb: u64,
    used_percent: u8,
}

fn memory_usage_from_meminfo(body: &str) -> Option<MemoryUsage> {
    let total_kb = linux_meminfo_kb(body, "MemTotal")?;
    let available_kb = linux_meminfo_kb(body, "MemAvailable")?;
    let used_kb = total_kb.saturating_sub(available_kb);
    let used_percent = used_kb
        .saturating_mul(100)
        .checked_div(total_kb)
        .unwrap_or(0)
        .min(100) as u8;
    Some(MemoryUsage {
        total_kb,
        used_kb,
        available_kb,
        used_percent,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryModuleInventory {
    count: usize,
    source: &'static str,
}

fn collect_memory_module_inventory() -> Option<MemoryModuleInventory> {
    linux_edac_memory_module_count(Path::new("/sys/devices/system/edac/mc"))
        .map(|count| MemoryModuleInventory {
            count,
            source: "linux_edac",
        })
        .or_else(|| {
            linux_dmi_memory_device_count(Path::new("/sys/firmware/dmi/entries")).map(|count| {
                MemoryModuleInventory {
                    count,
                    source: "linux_dmi_type17",
                }
            })
        })
}

fn linux_edac_memory_module_count(path: &Path) -> Option<usize> {
    let mut count = 0usize;
    let controllers = fs::read_dir(path).ok()?;
    for controller in controllers.filter_map(Result::ok) {
        let controller_name = controller.file_name();
        if !controller_name.to_string_lossy().starts_with("mc") {
            continue;
        }
        let Ok(entries) = fs::read_dir(controller.path()) else {
            continue;
        };
        count += entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("dimm"))
            .count();
    }
    (count > 0).then_some(count)
}

fn linux_dmi_memory_device_count(path: &Path) -> Option<usize> {
    let count = fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("17-"))
        .count();
    (count > 0).then_some(count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuSample {
    idle: u64,
    total: u64,
}

fn collect_cpu_usage_percent() -> Option<f64> {
    let first = read_linux_cpu_sample("/proc/stat")?;
    thread::sleep(Duration::from_millis(100));
    let second = read_linux_cpu_sample("/proc/stat")?;
    cpu_usage_percent_between(first, second)
}

fn read_linux_cpu_sample(path: &str) -> Option<CpuSample> {
    let body = fs::read_to_string(path).ok()?;
    parse_linux_cpu_sample(&body)
}

fn parse_linux_cpu_sample(body: &str) -> Option<CpuSample> {
    let line = body.lines().find(|line| line.starts_with("cpu "))?;
    let values = line
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    let total = values.iter().copied().sum();
    Some(CpuSample { idle, total })
}

fn cpu_usage_percent_between(first: CpuSample, second: CpuSample) -> Option<f64> {
    let total_delta = second.total.checked_sub(first.total)?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = second.idle.saturating_sub(first.idle).min(total_delta);
    let busy_delta = total_delta - idle_delta;
    Some(((busy_delta as f64 / total_delta as f64) * 1000.0).round() / 10.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceSummary {
    status_available: bool,
    failed_units_count: Option<usize>,
    failed_units: Vec<String>,
}

fn collect_systemd_service_summary() -> ServiceSummary {
    let output = ProcessCommand::new("systemctl")
        .args([
            "--no-pager",
            "--plain",
            "--state=failed",
            "--type=service",
            "list-units",
        ])
        .output();
    let Ok(output) = output else {
        return systemd_service_summary_unavailable();
    };
    if !output.status.success() {
        return systemd_service_summary_unavailable();
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let failed_units = parse_systemd_failed_services(&body);
    ServiceSummary {
        status_available: true,
        failed_units_count: Some(failed_units.len()),
        failed_units,
    }
}

fn systemd_service_summary_unavailable() -> ServiceSummary {
    ServiceSummary {
        status_available: false,
        failed_units_count: None,
        failed_units: Vec::new(),
    }
}

fn parse_systemd_failed_services(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.ends_with(".service"))
        .map(ToOwned::to_owned)
        .collect()
}

fn read_optional_trimmed(path: &str) -> Option<String> {
    read_optional_trimmed_path(Path::new(path))
}

fn read_optional_trimmed_path(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn linux_meminfo_kb(body: &str, key: &str) -> Option<u64> {
    body.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        if name != key {
            return None;
        }
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn linux_network_interfaces(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let (name, _stats) = line.split_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_owned())
            }
        })
        .collect()
}

fn linux_proc_process_count(path: &str) -> Option<usize> {
    let entries = fs::read_dir(path).ok()?;
    Some(
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .chars()
                    .all(|character| character.is_ascii_digit())
            })
            .count(),
    )
}

fn read_and_handle_task_assignment(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    controller_public_key: &str,
    correlation_id: &str,
) -> Result<(), CliError> {
    let message = match socket.read() {
        Ok(message) => message,
        Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
            return Ok(());
        }
        Err(error) => return Err(CliError::Http(error.to_string())),
    };
    if message.is_close() {
        return Ok(());
    }
    let body = message
        .to_text()
        .map_err(|error| CliError::Http(error.to_string()))?;
    let message =
        fleet_protocol::decode_message(body).map_err(|error| CliError::Http(error.to_string()))?;
    let fleet_protocol::WirePayload::TaskAssignment { envelope, task } = message.payload else {
        return Ok(());
    };
    let envelope = task_envelope_from_wire(envelope)?;
    let trust_bundle = legacy_controller_signing_trust_bundle(config, controller_public_key)?;
    let verifier = ControllerSignatureVerifier;
    let agent_id = fleet_domain::AgentId::new(config.agent_id.clone())
        .map_err(|error| CliError::Http(error.to_string()))?;
    let mut replay_guard = match agent_nonce_replay_guard(config) {
        Ok(replay_guard) => replay_guard,
        Err(error) => {
            send_agent_task_rejected(
                socket,
                config,
                correlation_id,
                &envelope,
                fleet_protocol::TaskRejectionReasonCode::InternalError,
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    if let Err(error) = fleet_runner::verify_signed_envelope_once_with_controller_trust(
        &envelope,
        &agent_id,
        SystemTime::now(),
        &trust_bundle,
        None,
        &verifier,
        &mut replay_guard,
    ) {
        send_agent_task_rejected(
            socket,
            config,
            correlation_id,
            &envelope,
            task_rejection_reason_from_runner_error(&error),
            &error.to_string(),
        )?;
        return Ok(());
    }
    send_agent_task_ack(socket, config, correlation_id, &envelope)?;

    match task {
        fleet_protocol::TaskWire::Command(command) => {
            run_signed_command_task(socket, config, correlation_id, &envelope, command)?;
        }
        fleet_protocol::TaskWire::DriftCheck(task) => {
            run_signed_drift_check_task(socket, config, correlation_id, &envelope, task)?;
        }
        fleet_protocol::TaskWire::RunbookExecution(task) => {
            run_signed_runbook_task(socket, config, correlation_id, &envelope, task)?;
        }
    }
    Ok(())
}

fn handle_task_assignment_with_queue(
    session: &AgentTaskExecutionSession<'_>,
    envelope: fleet_protocol::SignedTaskEnvelopeWire,
    task: fleet_protocol::TaskWire,
) -> Result<(), CliError> {
    let envelope = task_envelope_from_wire(envelope)?;
    let verification = verify_agent_task_envelope_once_with_session_trust(
        &envelope,
        session.config,
        session.controller_public_key,
        session.task_state,
        SystemTime::now(),
    )?;
    if let Err(error) = verification {
        persist_agent_task_rejected_report(
            session,
            &envelope,
            task_rejection_reason_from_runner_error(&error),
            &error.to_string(),
        )?;
        return Ok(());
    }
    recover_interrupted_agent_execution(session.journal_client)?;
    if session
        .task_state
        .runtime
        .should_cancel(envelope.task_id.as_str())
    {
        let canceled = AgentTaskResultReport::new(
            -1,
            fleet_protocol::TaskResultStatus::Canceled,
            "operator requested cancel",
        );
        persist_no_artifact_final_result_report(
            session.journal_client,
            session.controller_namespace,
            session.config,
            &envelope,
            canceled,
        )?;
        return Ok(());
    }
    match task {
        fleet_protocol::TaskWire::Command(command) => {
            run_signed_command_task_queue(session, &envelope, command)?;
        }
        fleet_protocol::TaskWire::DriftCheck(task) => {
            persist_agent_task_ack_report(session, &envelope)?;
            run_signed_drift_check_task_queue(session, &envelope, task)?;
        }
        fleet_protocol::TaskWire::RunbookExecution(task) => {
            run_signed_runbook_task_queue(session, &envelope, task)?;
        }
    }
    Ok(())
}

fn run_signed_command_task_queue(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    command: fleet_protocol::CommandTaskWire,
) -> Result<(), CliError> {
    use fleet_application::delivery::ExecutionAdmission;

    let execution =
        agent_task_execution_record(session.controller_namespace, session.config, envelope)?;
    let admission = session
        .journal_client
        .admit(&execution)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))?;
    if admission == ExecutionAdmission::AlreadyRecorded {
        // The existing execution record owns its durable final report. A new
        // rejection could terminalize a still-dispatched Assignment ahead of
        // that result, so replay the original reports without adding another event.
        return Ok(());
    }
    let final_report_key = &execution.snapshot().final_report_key;
    session
        .journal_client
        .start(final_report_key)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))?;
    persist_agent_task_ack_report(session, envelope)?;
    let mut spec = fleet_runner::CommandSpec::new(
        command.program,
        command.args,
        Duration::from_millis(command.timeout_ms),
    );
    spec.max_output_bytes = command.max_output_bytes;
    persist_agent_task_started_report(session, envelope)?;
    let mut streamed_any = false;
    let mut stdout_chunks = 0u64;
    let mut stderr_chunks = 0u64;
    let mut output_journal_error = None;
    let task_id = envelope.task_id.as_str().to_owned();
    let result = fleet_runner::run_command_streaming_with_cancel(
        spec,
        || session.task_state.runtime.should_cancel(&task_id),
        |chunk| {
            let stream = chunk.stream;
            if let Err(error) = persist_task_output_report(
                session.journal_client,
                session.controller_namespace,
                session.config,
                envelope,
                chunk,
            ) {
                let message = error.to_string();
                output_journal_error = Some(error);
                return Err(fleet_runner::RunnerError::Stream(message));
            }
            streamed_any = true;
            match stream {
                fleet_runner::CommandOutputStream::Stdout => stdout_chunks += 1,
                fleet_runner::CommandOutputStream::Stderr => stderr_chunks += 1,
            }
            Ok(())
        },
    );
    if let Some(error) = output_journal_error {
        // A timed-out wait does not prove that a journal write failed; it may
        // still commit. Without a confirmed count, never append a contradictory final.
        return Err(error);
    }
    let capture_truncated = result.is_err();
    let (output, result_status, reason) = command_execution_result(result);
    if !streamed_any && output.exit_code != 0 && !output.stderr.is_empty() {
        persist_task_output_report(
            session.journal_client,
            session.controller_namespace,
            session.config,
            envelope,
            fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stderr,
                sequence: 0,
                data: output.stderr.clone(),
            },
        )?;
        stderr_chunks = 1;
    }
    let truncated = capture_truncated || output.truncated;
    let status = if truncated && result_status == fleet_protocol::TaskResultStatus::Succeeded {
        fleet_protocol::TaskResultStatus::Failed
    } else {
        result_status
    };
    persist_no_artifact_final_result_report(
        session.journal_client,
        session.controller_namespace,
        session.config,
        envelope,
        AgentTaskResultReport::new(output.exit_code, status, &reason).with_output_summary(
            fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks,
                stderr_chunks,
                truncated,
            },
        ),
    )?;
    Ok(())
}

fn command_execution_result(
    result: Result<fleet_runner::CommandOutput, fleet_runner::RunnerError>,
) -> (
    fleet_runner::CommandOutput,
    fleet_protocol::TaskResultStatus,
    String,
) {
    match result {
        Ok(output) if output.exit_code == 0 => (
            output,
            fleet_protocol::TaskResultStatus::Succeeded,
            String::new(),
        ),
        Ok(output) => {
            let reason = if output.stderr.is_empty() {
                format!("exit_code={}", output.exit_code)
            } else {
                output.stderr.clone()
            };
            (output, fleet_protocol::TaskResultStatus::Failed, reason)
        }
        Err(error @ fleet_runner::RunnerError::Canceled) => (
            fleet_runner::CommandOutput {
                stdout: String::new(),
                stderr: error.to_string(),
                exit_code: -1,
                truncated: false,
            },
            fleet_protocol::TaskResultStatus::Canceled,
            error.to_string(),
        ),
        Err(error @ fleet_runner::RunnerError::Timeout) => (
            fleet_runner::CommandOutput {
                stdout: String::new(),
                stderr: error.to_string(),
                exit_code: -1,
                truncated: false,
            },
            fleet_protocol::TaskResultStatus::TimedOut,
            error.to_string(),
        ),
        Err(error) => (
            fleet_runner::CommandOutput {
                stdout: String::new(),
                stderr: error.to_string(),
                exit_code: -1,
                truncated: false,
            },
            fleet_protocol::TaskResultStatus::Failed,
            error.to_string(),
        ),
    }
}

fn run_signed_drift_check_task_queue(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    task: fleet_protocol::DriftCheckTaskWire,
) -> Result<(), CliError> {
    let config = session.config;
    let policy = match fleet_domain::parse_policy_document(&task.policy_document) {
        Ok(policy) => policy,
        Err(error) => {
            persist_no_artifact_final_result_report(
                session.journal_client,
                session.controller_namespace,
                config,
                envelope,
                AgentTaskResultReport::new(
                    -1,
                    fleet_protocol::TaskResultStatus::Failed,
                    &format!("invalid drift policy: {error}"),
                ),
            )?;
            return Ok(());
        }
    };
    persist_agent_task_started_report(session, envelope)?;
    let report = fleet_runner::evaluate_policy_drift(&policy, &fleet_runner::LocalDriftProbe);
    persist_agent_drift_evidence_report(
        session.journal_client,
        session.controller_namespace,
        config,
        envelope,
        &fleet_protocol::delivery_v2::V2DriftEvidenceReportBody {
            status: drift_status_to_wire(&report.status),
            expected: report.expected,
            actual: report.actual,
        },
    )?;
    persist_no_artifact_final_result_report(
        session.journal_client,
        session.controller_namespace,
        config,
        envelope,
        AgentTaskResultReport::new(0, fleet_protocol::TaskResultStatus::Succeeded, ""),
    )?;
    Ok(())
}

fn persist_agent_drift_evidence_report(
    journal: &fleet_agent::journal_worker::JournalClient,
    controller_namespace: &str,
    config: &LocalAgentConfig,
    envelope: &fleet_domain::TaskEnvelope,
    body: &fleet_protocol::delivery_v2::V2DriftEvidenceReportBody,
) -> Result<(), CliError> {
    use fleet_application::delivery::JournalReport;
    use fleet_domain::delivery::ReportClass;

    let key = lifecycle_report_key(
        controller_namespace,
        config,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        "drift-evidence",
    )?;
    let encoded_body = serde_json::to_vec(body)
        .map_err(|_| CliError::Http("failed to encode drift evidence report".to_owned()))?;
    if encoded_body.len() > fleet_protocol::delivery_v2::MAX_REPORT_BODY_BYTES {
        return Err(CliError::Http(
            "drift evidence report exceeds protocol limit".to_owned(),
        ));
    }
    let report = JournalReport::new(key, ReportClass::DriftEvidence, encoded_body)
        .map_err(|error| CliError::Http(error.to_string()))?;
    journal
        .append(&report)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

fn drift_status_to_wire(
    status: &fleet_domain::DriftStatus,
) -> fleet_protocol::delivery_v2::V2DriftStatusWire {
    match status {
        fleet_domain::DriftStatus::Compliant => {
            fleet_protocol::delivery_v2::V2DriftStatusWire::Compliant
        }
        fleet_domain::DriftStatus::Drifted => {
            fleet_protocol::delivery_v2::V2DriftStatusWire::Drifted
        }
        fleet_domain::DriftStatus::Unknown => {
            fleet_protocol::delivery_v2::V2DriftStatusWire::Unknown
        }
    }
}

fn drift_report_payload_for_envelope(
    agent_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    status: String,
    expected: String,
    actual: String,
) -> fleet_protocol::WirePayload {
    fleet_protocol::WirePayload::DriftReport {
        agent_id: agent_id.to_owned(),
        job_id: Some(envelope.job_id.as_str().to_owned()),
        task_id: Some(envelope.task_id.as_str().to_owned()),
        status,
        expected,
        actual,
    }
}

fn run_signed_runbook_task_queue(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    task: fleet_protocol::RunbookExecutionTaskWire,
) -> Result<(), CliError> {
    run_signed_runbook_task_queue_with_executor(session, envelope, task, |plan, options| {
        fleet_runner::execute_runbook_execution_plan_with_hooks(
            plan,
            options,
            runbook_command_runner,
            fleet_runner::copy_file_atomic,
            fleet_runner::check_tcp_port,
            fleet_runner::check_local_process,
            collect_runbook_snapshot,
        )
    })
}

fn run_signed_runbook_task_queue_with_executor<E>(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    task: fleet_protocol::RunbookExecutionTaskWire,
    execute: E,
) -> Result<(), CliError>
where
    E: FnOnce(
        &fleet_runner::RunbookExecutionPlan,
        fleet_runner::RunbookExecutionOptions,
    ) -> Result<fleet_runner::RunbookExecutionReport, fleet_runner::RunnerError>,
{
    let config = session.config;
    let runbook = match fleet_domain::parse_runbook_document(&task.runbook_document) {
        Ok(runbook) => runbook,
        Err(error) => {
            let reason = error.to_string();
            persist_agent_task_ack_report(session, envelope)?;
            persist_runbook_failure_with_output(
                session,
                envelope,
                &reason,
                format!("invalid runbook: {reason}"),
                false,
            )?;
            return Ok(());
        }
    };
    let package_manager = match local_runbook_package_manager(&runbook) {
        Ok(package_manager) => package_manager,
        Err(error) => {
            persist_agent_task_ack_report(session, envelope)?;
            persist_runbook_failure_with_output(session, envelope, error, error.to_owned(), false)?;
            return Ok(());
        }
    };
    let provider = DisabledSecretProvider;
    let plan = match build_agent_runbook_execution_plan_with_provider(
        &runbook,
        package_manager,
        &provider,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            let reason = error.to_string();
            persist_agent_task_ack_report(session, envelope)?;
            persist_runbook_failure_with_output(
                session,
                envelope,
                &reason,
                format!("invalid runbook primitive: {reason}"),
                false,
            )?;
            return Ok(());
        }
    };
    if !runbook_execution_plan_has_artifact_results(&plan) {
        use fleet_application::delivery::ExecutionAdmission;

        let execution =
            agent_task_execution_record(session.controller_namespace, config, envelope)?;
        let admission = session
            .journal_client
            .admit(&execution)
            .map_err(|error| CliError::Http(error.to_string()))?
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .map_err(|error| CliError::Http(error.to_string()))?;
        if admission == ExecutionAdmission::AlreadyRecorded {
            return Ok(());
        }
        session
            .journal_client
            .start(&execution.snapshot().final_report_key)
            .map_err(|error| CliError::Http(error.to_string()))?
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .map_err(|error| CliError::Http(error.to_string()))?;
    }
    persist_agent_task_ack_report(session, envelope)?;
    persist_agent_task_started_report(session, envelope)?;
    let report = match execute(
        &plan,
        fleet_runner::RunbookExecutionOptions {
            confirmed_high_risk: task.confirmed_high_risk,
            check_mode: runbook.check_mode,
            dry_run: runbook.dry_run,
            command_timeout: Duration::from_millis(task.timeout_ms),
            ..fleet_runner::RunbookExecutionOptions::default()
        },
    ) {
        Ok(report) => report,
        Err(error) => {
            let reason = error.to_string();
            persist_runbook_failure_with_output(session, envelope, &reason, reason.clone(), true)?;
            return Ok(());
        }
    };
    let mut artifacts = Vec::new();
    for outcome in &report.outcomes {
        if let Some(artifact) = &outcome.artifact {
            artifacts.push(fleet_protocol::TaskResultArtifactWire {
                artifact_id: prefixed_ulid("artifact")?,
                step_id: artifact.step_id.clone(),
                destination: artifact.destination.clone(),
                checksum_sha256: artifact.checksum_sha256.clone(),
                size_bytes: artifact.size_bytes,
                retention_class: artifact.retention_class.clone(),
                content_bytes: artifact.content_bytes.clone(),
            });
        }
    }
    let (exit_code, status) = runbook_task_result_summary(&report);
    let final_report = AgentTaskResultReport::with_artifacts(exit_code, status, "", artifacts);
    let has_artifacts = !final_report.artifacts.is_empty();
    let mut stdout_sequence = 0;
    let mut stderr_sequence = 0;
    let mut stdout_chunks = 0;
    let mut stderr_chunks = 0;
    for outcome in report.outcomes {
        let summary_chunk = fleet_runner::CommandOutputChunk {
            stream: fleet_runner::CommandOutputStream::Stdout,
            sequence: stdout_sequence,
            data: format!(
                "runbook_step={} changed={:?} exit_code={:?} {}",
                outcome.id, outcome.changed, outcome.exit_code, outcome.audit_metadata
            ),
        };
        send_or_persist_runbook_output_chunk(session, envelope, summary_chunk, has_artifacts)?;
        stdout_sequence += 1;
        stdout_chunks += 1;
        if !outcome.stdout.is_empty() {
            let chunk = fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stdout,
                sequence: stdout_sequence,
                data: outcome.stdout,
            };
            send_or_persist_runbook_output_chunk(session, envelope, chunk, has_artifacts)?;
            stdout_sequence += 1;
            stdout_chunks += 1;
        }
        if !outcome.stderr.is_empty() {
            let chunk = fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stderr,
                sequence: stderr_sequence,
                data: outcome.stderr,
            };
            send_or_persist_runbook_output_chunk(session, envelope, chunk, has_artifacts)?;
            stderr_sequence += 1;
            stderr_chunks += 1;
        }
    }
    if has_artifacts {
        send_ephemeral_artifact_final_result_report(
            session,
            envelope,
            final_report.with_output_summary(fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks,
                stderr_chunks,
                truncated: false,
            }),
        )?;
    } else {
        persist_no_artifact_final_result_report(
            session.journal_client,
            session.controller_namespace,
            session.config,
            envelope,
            final_report.with_output_summary(fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks,
                stderr_chunks,
                truncated: false,
            }),
        )?;
    }
    Ok(())
}

fn runbook_execution_plan_has_artifact_results(plan: &fleet_runner::RunbookExecutionPlan) -> bool {
    plan.steps.iter().any(|step| {
        matches!(
            &step.action,
            fleet_runner::RunbookExecutionAction::FileCopy(spec)
                if spec.artifact_retention_class.is_some()
        )
    })
}

fn runbook_task_result_summary(
    report: &fleet_runner::RunbookExecutionReport,
) -> (i32, fleet_protocol::TaskResultStatus) {
    match report.aggregate_status() {
        fleet_runner::PrimitiveResultStatus::Success
        | fleet_runner::PrimitiveResultStatus::Changed
        | fleet_runner::PrimitiveResultStatus::Skipped => {
            (0, fleet_protocol::TaskResultStatus::Succeeded)
        }
        fleet_runner::PrimitiveResultStatus::Failed
        | fleet_runner::PrimitiveResultStatus::Rejected => (
            report
                .outcomes
                .iter()
                .find(|outcome| {
                    matches!(
                        outcome.status,
                        fleet_runner::PrimitiveResultStatus::Failed
                            | fleet_runner::PrimitiveResultStatus::Rejected
                    )
                })
                .and_then(|outcome| outcome.exit_code)
                .filter(|exit_code| *exit_code != 0)
                .unwrap_or(-1),
            fleet_protocol::TaskResultStatus::Failed,
        ),
        fleet_runner::PrimitiveResultStatus::Canceled => {
            (-1, fleet_protocol::TaskResultStatus::Canceled)
        }
    }
}

fn persist_runbook_failure_with_output(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    reason: &str,
    output: String,
    truncated: bool,
) -> Result<(), CliError> {
    persist_task_output_report(
        session.journal_client,
        session.controller_namespace,
        session.config,
        envelope,
        fleet_runner::CommandOutputChunk {
            stream: fleet_runner::CommandOutputStream::Stderr,
            sequence: 0,
            data: output,
        },
    )?;
    persist_no_artifact_final_result_report(
        session.journal_client,
        session.controller_namespace,
        session.config,
        envelope,
        AgentTaskResultReport::new(-1, fleet_protocol::TaskResultStatus::Failed, reason)
            .with_output_summary(fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks: 0,
                stderr_chunks: 1,
                truncated,
            }),
    )?;
    Ok(())
}

fn send_or_persist_runbook_output_chunk(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    chunk: fleet_runner::CommandOutputChunk,
    ephemeral_artifact_path: bool,
) -> Result<(), CliError> {
    if ephemeral_artifact_path {
        send_agent_output_chunk_queue(
            session.outbound_sender,
            session.config,
            session.correlation_id,
            envelope,
            chunk,
        )
    } else {
        persist_task_output_report(
            session.journal_client,
            session.controller_namespace,
            session.config,
            envelope,
            chunk,
        )?;
        Ok(())
    }
}

fn send_ephemeral_artifact_final_result_report(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    report: AgentTaskResultReport,
) -> Result<(), CliError> {
    use fleet_domain::delivery::ReportClass;

    if report.artifacts.is_empty() {
        return Err(CliError::Http(
            "artifact final result requires at least one artifact".to_owned(),
        ));
    }
    let key = lifecycle_report_key(
        session.controller_namespace,
        session.config,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        "final-result",
    )?;
    let body = serde_json::to_vec(&report)
        .map_err(|_| CliError::Http("failed to encode artifact final result".to_owned()))?;
    let report =
        fleet_protocol::delivery_v2::V2TaskReportWire::new(&key, ReportClass::FinalResult, &body)
            .map_err(|error| CliError::Http(error.to_string()))?;
    enqueue_wire_message(
        session.outbound_sender,
        fleet_protocol::WireMessage::new(
            prefixed_ulid("msg")?,
            session.correlation_id.to_owned(),
            Some(session.config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::TaskReport(report),
        ),
    )?;
    Ok(())
}

#[cfg(test)]
fn send_or_persist_runbook_final_result(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    report: AgentTaskResultReport,
) -> Result<(), CliError> {
    if report.artifacts.is_empty() {
        persist_no_artifact_final_result_report(
            session.journal_client,
            session.controller_namespace,
            session.config,
            envelope,
            report,
        )?;
    } else {
        send_ephemeral_artifact_final_result_report(session, envelope, report)?;
    }
    Ok(())
}

fn run_signed_command_task(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    command: fleet_protocol::CommandTaskWire,
) -> Result<(), CliError> {
    let mut spec = fleet_runner::CommandSpec::new(
        command.program,
        command.args,
        Duration::from_millis(command.timeout_ms),
    );
    spec.max_output_bytes = command.max_output_bytes;
    send_agent_task_started(socket, config, correlation_id, envelope)?;
    let mut streamed_any = false;
    let result = fleet_runner::run_command_streaming_with_cancel(
        spec,
        || false,
        |chunk| {
            streamed_any = true;
            send_agent_output_chunk(socket, config, correlation_id, envelope, chunk)
                .map_err(|error| fleet_runner::RunnerError::Stream(error.to_string()))
        },
    );
    let (output, result_status, reason) = command_execution_result(result);
    if !streamed_any && output.exit_code != 0 && !output.stderr.is_empty() {
        send_agent_output_chunk(
            socket,
            config,
            correlation_id,
            envelope,
            fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stderr,
                sequence: 0,
                data: output.stderr.clone(),
            },
        )?;
    }
    send_agent_task_result(
        socket,
        config,
        correlation_id,
        envelope,
        output.exit_code,
        result_status,
        &reason,
    )?;
    Ok(())
}

fn run_signed_drift_check_task(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    task: fleet_protocol::DriftCheckTaskWire,
) -> Result<(), CliError> {
    let policy = match fleet_domain::parse_policy_document(&task.policy_document) {
        Ok(policy) => policy,
        Err(error) => {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence: 0,
                    data: format!("invalid drift policy: {error}"),
                },
            )?;
            send_agent_task_result(
                socket,
                config,
                correlation_id,
                envelope,
                -1,
                fleet_protocol::TaskResultStatus::Failed,
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    send_agent_task_started(socket, config, correlation_id, envelope)?;
    let report = fleet_runner::evaluate_policy_drift(&policy, &fleet_runner::LocalDriftProbe);
    let message = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        drift_report_payload_for_envelope(
            &config.agent_id,
            envelope,
            drift_status_to_cli(&report.status).to_owned(),
            report.expected,
            report.actual,
        ),
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;
    send_agent_task_result(
        socket,
        config,
        correlation_id,
        envelope,
        0,
        fleet_protocol::TaskResultStatus::Succeeded,
        "",
    )?;
    Ok(())
}

fn local_runbook_package_manager(
    runbook: &fleet_domain::Runbook,
) -> Result<fleet_runner::LinuxPackageManager, &'static str> {
    if runbook
        .tasks
        .iter()
        .any(|task| matches!(task, fleet_domain::RunbookTask::Package(_)))
    {
        fleet_runner::detect_local_linux_package_manager()
            .ok_or("no supported Linux package manager detected")
    } else {
        Ok(fleet_runner::LinuxPackageManager::Apt)
    }
}

fn runbook_command_runner(
    command: &fleet_runner::PrimitiveCommand,
    spec: &fleet_runner::CommandSpec,
) -> Result<fleet_runner::CommandOutput, fleet_runner::RunnerError> {
    let mut spec = spec.clone();
    spec.program = command.program.clone();
    spec.args = command.args.clone();
    fleet_runner::run_command_with_spec(spec)
}

fn collect_runbook_snapshot(
    spec: &fleet_runner::SnapshotSpec,
) -> Result<fleet_runner::SnapshotResult, fleet_runner::PrimitiveError> {
    let (message, mut body) = match spec.kind {
        fleet_runner::SnapshotKind::Facts => ("facts snapshot collected", collect_local_facts()),
        fleet_runner::SnapshotKind::Metrics => {
            ("metrics snapshot collected", collect_local_metrics())
        }
    };
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "source".to_owned(),
            serde_json::Value::String("runbook".to_owned()),
        );
    }
    Ok(fleet_runner::SnapshotResult {
        message: message.to_owned(),
        body: body.to_string(),
    })
}

fn build_agent_runbook_execution_plan_with_provider<P>(
    runbook: &fleet_domain::Runbook,
    package_manager: fleet_runner::LinuxPackageManager,
    provider: &P,
) -> Result<fleet_runner::RunbookExecutionPlan, fleet_runner::PrimitiveError>
where
    P: SecretProvider,
{
    fleet_runner::build_runbook_execution_plan_with_secret_resolver(
        runbook,
        package_manager,
        |reference| resolve_secret_for_runner(provider, reference),
    )
}

fn resolve_secret_for_runner<P>(
    provider: &P,
    reference: &fleet_domain::SecretRef,
) -> Result<String, fleet_domain::TemplateSecretResolutionFailure>
where
    P: SecretProvider,
{
    provider
        .resolve_secret(reference)
        .map(|secret: ResolvedSecret| secret.expose_secret_for_rendering().to_owned())
        .map_err(|error| match error {
            SecretProviderError::NotFound { .. } => {
                fleet_domain::TemplateSecretResolutionFailure::NotFound
            }
            SecretProviderError::Denied { .. } => {
                fleet_domain::TemplateSecretResolutionFailure::Denied
            }
            SecretProviderError::Provider { .. } => {
                fleet_domain::TemplateSecretResolutionFailure::Provider
            }
        })
}

fn run_signed_runbook_task(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    task: fleet_protocol::RunbookExecutionTaskWire,
) -> Result<(), CliError> {
    let runbook = match fleet_domain::parse_runbook_document(&task.runbook_document) {
        Ok(runbook) => runbook,
        Err(error) => {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence: 0,
                    data: format!("invalid runbook: {error}"),
                },
            )?;
            send_agent_task_result(
                socket,
                config,
                correlation_id,
                envelope,
                -1,
                fleet_protocol::TaskResultStatus::Failed,
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    let package_manager = match local_runbook_package_manager(&runbook) {
        Ok(package_manager) => package_manager,
        Err(error) => {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence: 0,
                    data: error.to_owned(),
                },
            )?;
            send_agent_task_result(
                socket,
                config,
                correlation_id,
                envelope,
                -1,
                fleet_protocol::TaskResultStatus::Failed,
                error,
            )?;
            return Ok(());
        }
    };
    let provider = DisabledSecretProvider;
    let plan = match build_agent_runbook_execution_plan_with_provider(
        &runbook,
        package_manager,
        &provider,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence: 0,
                    data: format!("invalid runbook primitive: {error}"),
                },
            )?;
            send_agent_task_result(
                socket,
                config,
                correlation_id,
                envelope,
                -1,
                fleet_protocol::TaskResultStatus::Failed,
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    send_agent_task_started(socket, config, correlation_id, envelope)?;
    let report = match fleet_runner::execute_runbook_execution_plan_with_hooks(
        &plan,
        fleet_runner::RunbookExecutionOptions {
            confirmed_high_risk: task.confirmed_high_risk,
            check_mode: runbook.check_mode,
            dry_run: runbook.dry_run,
            command_timeout: Duration::from_millis(task.timeout_ms),
            ..fleet_runner::RunbookExecutionOptions::default()
        },
        runbook_command_runner,
        fleet_runner::copy_file_atomic,
        fleet_runner::check_tcp_port,
        fleet_runner::check_local_process,
        collect_runbook_snapshot,
    ) {
        Ok(report) => report,
        Err(error) => {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence: 0,
                    data: error.to_string(),
                },
            )?;
            send_agent_task_result(
                socket,
                config,
                correlation_id,
                envelope,
                -1,
                fleet_protocol::TaskResultStatus::Failed,
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    let mut sequence = 0;
    let mut artifacts = Vec::new();
    for outcome in report.outcomes {
        if let Some(artifact) = &outcome.artifact {
            artifacts.push(fleet_protocol::TaskResultArtifactWire {
                artifact_id: prefixed_ulid("artifact")?,
                step_id: artifact.step_id.clone(),
                destination: artifact.destination.clone(),
                checksum_sha256: artifact.checksum_sha256.clone(),
                size_bytes: artifact.size_bytes,
                retention_class: artifact.retention_class.clone(),
                content_bytes: artifact.content_bytes.clone(),
            });
        }
        let summary = format!(
            "runbook_step={} changed={:?} exit_code={:?} {}",
            outcome.id, outcome.changed, outcome.exit_code, outcome.audit_metadata
        );
        send_agent_output_chunk(
            socket,
            config,
            correlation_id,
            envelope,
            fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stdout,
                sequence,
                data: summary,
            },
        )?;
        sequence += 1;
        if !outcome.stdout.is_empty() {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stdout,
                    sequence,
                    data: outcome.stdout,
                },
            )?;
            sequence += 1;
        }
        if !outcome.stderr.is_empty() {
            send_agent_output_chunk(
                socket,
                config,
                correlation_id,
                envelope,
                fleet_runner::CommandOutputChunk {
                    stream: fleet_runner::CommandOutputStream::Stderr,
                    sequence,
                    data: outcome.stderr,
                },
            )?;
            sequence += 1;
        }
    }
    send_agent_task_result_report(
        socket,
        config,
        correlation_id,
        envelope,
        AgentTaskResultReport::with_artifacts(
            0,
            fleet_protocol::TaskResultStatus::Succeeded,
            "",
            artifacts,
        ),
    )?;
    Ok(())
}

fn send_agent_task_ack(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<(), CliError> {
    send_wire_message_to_socket(
        socket,
        &agent_task_ack_message(config, correlation_id, envelope)?,
    )
}

fn send_agent_task_started(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<(), CliError> {
    send_wire_message_to_socket(
        socket,
        &agent_task_started_message(config, correlation_id, envelope)?,
    )
}

fn send_agent_task_rejected(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    reason_code: fleet_protocol::TaskRejectionReasonCode,
    reason: &str,
) -> Result<(), CliError> {
    send_wire_message_to_socket(
        socket,
        &agent_task_rejected_message(
            config,
            correlation_id,
            envelope.job_id.as_str(),
            envelope.task_id.as_str(),
            reason_code,
            reason,
        )?,
    )
}

fn persist_agent_task_rejected_report(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    reason_code: fleet_protocol::TaskRejectionReasonCode,
    reason: &str,
) -> Result<(), CliError> {
    persist_agent_task_rejected_report_with_journal(
        session.journal_client,
        session.controller_namespace,
        session.config,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        reason_code,
        reason,
    )
}

fn persist_agent_task_rejected_report_with_journal(
    journal: &fleet_agent::journal_worker::JournalClient,
    controller_namespace: &str,
    config: &LocalAgentConfig,
    job_id: &str,
    task_id: &str,
    reason_code: fleet_protocol::TaskRejectionReasonCode,
    reason: &str,
) -> Result<(), CliError> {
    let key = lifecycle_report_key(
        controller_namespace,
        config,
        job_id,
        task_id,
        "task-rejected",
    )?;
    persist_agent_task_lifecycle_report_with_journal(
        journal,
        key,
        fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskRejected {
            reason_code,
            reason: fleet_core::redact_secret(reason),
        },
        "durable task rejection",
    )
}

fn agent_task_ack_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::TaskAck {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
        },
    ))
}

fn agent_task_started_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::TaskStarted {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
        },
    ))
}

fn agent_task_rejected_message(
    config: &LocalAgentConfig,
    correlation_id: &str,
    job_id: &str,
    task_id: &str,
    reason_code: fleet_protocol::TaskRejectionReasonCode,
    reason: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::TaskRejected {
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            reason_code,
            reason: fleet_core::redact_secret(reason),
        },
    ))
}

fn task_rejection_reason_from_runner_error(
    error: &fleet_runner::RunnerError,
) -> fleet_protocol::TaskRejectionReasonCode {
    match error {
        fleet_runner::RunnerError::InvalidSignature
        | fleet_runner::RunnerError::UnknownControllerSigningKey
        | fleet_runner::RunnerError::ExpiredControllerSigningTrust
        | fleet_runner::RunnerError::Job(fleet_domain::JobError::UnsignedTask) => {
            fleet_protocol::TaskRejectionReasonCode::InvalidSignature
        }
        fleet_runner::RunnerError::ReplayedNonce => fleet_protocol::TaskRejectionReasonCode::Replay,
        fleet_runner::RunnerError::Job(fleet_domain::JobError::ExpiredTask) => {
            fleet_protocol::TaskRejectionReasonCode::Expired
        }
        fleet_runner::RunnerError::Job(fleet_domain::JobError::TargetAgentMismatch) => {
            fleet_protocol::TaskRejectionReasonCode::TargetMismatch
        }
        fleet_runner::RunnerError::HighRiskConfirmationRequired(_) => {
            fleet_protocol::TaskRejectionReasonCode::LocalPolicy
        }
        fleet_runner::RunnerError::Primitive(_) => {
            fleet_protocol::TaskRejectionReasonCode::CapabilityUnsupported
        }
        fleet_runner::RunnerError::Job(_) => fleet_protocol::TaskRejectionReasonCode::InvalidTask,
        fleet_runner::RunnerError::Io(_)
        | fleet_runner::RunnerError::ReplayStoreUnavailable(_)
        | fleet_runner::RunnerError::Timeout
        | fleet_runner::RunnerError::Canceled
        | fleet_runner::RunnerError::OutputLimitExceeded
        | fleet_runner::RunnerError::Stream(_) => {
            fleet_protocol::TaskRejectionReasonCode::InternalError
        }
    }
}

#[derive(Serialize)]
struct AgentTaskResultReport {
    exit_code: i32,
    status: fleet_protocol::TaskResultStatus,
    reason: String,
    artifacts: Vec<fleet_protocol::TaskResultArtifactWire>,
    output: fleet_protocol::delivery_v2::V2OutputSummary,
}

impl AgentTaskResultReport {
    fn new(exit_code: i32, status: fleet_protocol::TaskResultStatus, reason: &str) -> Self {
        Self::with_artifacts(exit_code, status, reason, Vec::new())
    }

    fn with_artifacts(
        exit_code: i32,
        status: fleet_protocol::TaskResultStatus,
        reason: &str,
        artifacts: Vec<fleet_protocol::TaskResultArtifactWire>,
    ) -> Self {
        Self {
            exit_code,
            status,
            reason: reason.to_owned(),
            artifacts,
            output: fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks: 0,
                stderr_chunks: 0,
                truncated: false,
            },
        }
    }

    fn with_output_summary(mut self, output: fleet_protocol::delivery_v2::V2OutputSummary) -> Self {
        self.output = output;
        self
    }
}

fn send_agent_task_result(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    exit_code: i32,
    status: fleet_protocol::TaskResultStatus,
    reason: &str,
) -> Result<(), CliError> {
    send_agent_task_result_report(
        socket,
        config,
        correlation_id,
        envelope,
        AgentTaskResultReport::new(exit_code, status, reason),
    )
}

fn send_agent_task_result_report(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    report: AgentTaskResultReport,
) -> Result<(), CliError> {
    let result = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::TaskResult {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            exit_code: report.exit_code,
            status: Some(report.status),
            reason: report.reason,
            artifacts: report.artifacts,
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&result)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
fn send_agent_task_result_queue_report(
    outbound_sender: &AgentOutboundQueue,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    report: AgentTaskResultReport,
) -> Result<(), CliError> {
    enqueue_wire_message(
        outbound_sender,
        fleet_protocol::WireMessage::new(
            prefixed_ulid("msg")?,
            correlation_id.to_owned(),
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::TaskResult {
                job_id: envelope.job_id.as_str().to_owned(),
                task_id: envelope.task_id.as_str().to_owned(),
                exit_code: report.exit_code,
                status: Some(report.status),
                reason: report.reason,
                artifacts: report.artifacts,
            },
        ),
    )
}

fn send_agent_output_chunk(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    chunk: fleet_runner::CommandOutputChunk,
) -> Result<(), CliError> {
    let message = fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::OutputChunk {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            stream: output_stream_to_wire(chunk.stream),
            sequence: chunk.sequence,
            data: chunk.data,
        },
    );
    socket
        .send(Message::Text(
            fleet_protocol::encode_message(&message)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ))
        .map_err(|error| CliError::Http(error.to_string()))
}

fn send_agent_output_chunk_queue(
    outbound_sender: &AgentOutboundQueue,
    config: &LocalAgentConfig,
    correlation_id: &str,
    envelope: &fleet_domain::TaskEnvelope,
    chunk: fleet_runner::CommandOutputChunk,
) -> Result<(), CliError> {
    enqueue_wire_message(
        outbound_sender,
        fleet_protocol::WireMessage::new(
            prefixed_ulid("msg")?,
            correlation_id.to_owned(),
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::OutputChunk {
                job_id: envelope.job_id.as_str().to_owned(),
                task_id: envelope.task_id.as_str().to_owned(),
                stream: output_stream_to_wire(chunk.stream),
                sequence: chunk.sequence,
                data: chunk.data,
            },
        ),
    )
}

fn agent_task_execution_record(
    controller_namespace: &str,
    config: &LocalAgentConfig,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<fleet_domain::delivery::ExecutionRecord, CliError> {
    use fleet_domain::delivery::{ExecutionPhase, ExecutionRecord, ExecutionSnapshot, ReportKey};

    let signature = envelope
        .signature
        .as_ref()
        .ok_or_else(|| CliError::Http("signed task envelope is required".to_owned()))?;
    let final_report_key = ReportKey::new(
        controller_namespace,
        &config.agent_id,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        "final-result",
    )
    .map_err(|error| CliError::Http(error.to_string()))?;
    let issued_at_ms = system_time_to_millis(envelope.issued_at).to_be_bytes();
    let expires_at_ms = system_time_to_millis(envelope.expires_at.as_system_time()).to_be_bytes();
    let nonce = envelope.nonce.as_str().as_bytes();
    let nonce_digest = execution_record_digest(b"fleet:agent-execution-nonce:v1", &[nonce]);
    let envelope_digest = execution_record_digest(
        b"fleet:agent-execution-envelope:v1",
        &[
            envelope.job_id.as_str().as_bytes(),
            envelope.task_id.as_str().as_bytes(),
            envelope.target_agent_id.as_str().as_bytes(),
            &issued_at_ms,
            &expires_at_ms,
            nonce,
            envelope.payload_hash.as_bytes(),
            signature.as_str().as_bytes(),
        ],
    );
    let admitted_at_ms = epoch_millis()
        .try_into()
        .map_err(|_| CliError::Http("invalid journal admission timestamp".to_owned()))?;
    ExecutionRecord::restore(ExecutionSnapshot {
        final_report_key,
        nonce_digest,
        envelope_digest,
        phase: ExecutionPhase::Admitted,
        admitted_at_ms,
        final_max_bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
        stdout_chunks: 0,
        stderr_chunks: 0,
    })
    .map_err(|error| CliError::Http(error.to_string()))
}

fn execution_record_digest(
    domain: &[u8],
    fields: &[&[u8]],
) -> fleet_domain::delivery::ReportDigest {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    fleet_domain::delivery::ReportDigest(digest.finalize().into())
}

#[derive(Serialize)]
struct AgentTaskOutputReportBody {
    stream: fleet_protocol::OutputStream,
    sequence: u64,
    data: String,
}

fn persist_task_output_report(
    journal: &fleet_agent::journal_worker::JournalClient,
    controller_namespace: &str,
    config: &LocalAgentConfig,
    envelope: &fleet_domain::TaskEnvelope,
    chunk: fleet_runner::CommandOutputChunk,
) -> Result<fleet_application::delivery::AppendReportOutcome, CliError> {
    use fleet_application::delivery::JournalReport;
    use fleet_domain::delivery::{ReportClass, ReportKey};

    let (stream, stream_name) = match chunk.stream {
        fleet_runner::CommandOutputStream::Stdout => {
            (fleet_protocol::OutputStream::Stdout, "stdout")
        }
        fleet_runner::CommandOutputStream::Stderr => {
            (fleet_protocol::OutputStream::Stderr, "stderr")
        }
    };
    let report_id = format!("output-{stream_name}-{:020}", chunk.sequence);
    let key = ReportKey::new(
        controller_namespace,
        &config.agent_id,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        &report_id,
    )
    .map_err(|error| CliError::Http(error.to_string()))?;
    let body = serde_json::to_vec(&AgentTaskOutputReportBody {
        stream,
        sequence: chunk.sequence,
        data: chunk.data,
    })
    .map_err(|_| CliError::Http("failed to encode task output report".to_owned()))?;
    if body.len() > fleet_protocol::delivery_v2::MAX_REPORT_BODY_BYTES {
        return Err(CliError::Http(
            "task output report exceeds protocol limit".to_owned(),
        ));
    }
    let report = JournalReport::new(key, ReportClass::Output, body)
        .map_err(|error| CliError::Http(error.to_string()))?;
    journal
        .append(&report)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn persist_no_artifact_final_result_report(
    journal: &fleet_agent::journal_worker::JournalClient,
    controller_namespace: &str,
    config: &LocalAgentConfig,
    envelope: &fleet_domain::TaskEnvelope,
    report: AgentTaskResultReport,
) -> Result<fleet_application::delivery::AppendReportOutcome, CliError> {
    use fleet_domain::delivery::ReportKey;

    let key = ReportKey::new(
        controller_namespace,
        &config.agent_id,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        "final-result",
    )
    .map_err(|error| CliError::Http(error.to_string()))?;
    persist_no_artifact_final_result_report_with_key(journal, key, report)
}

fn persist_agent_task_ack_report(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<(), CliError> {
    persist_agent_task_lifecycle_report(
        session,
        envelope,
        "task-ack",
        fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskAck {},
        "durable task acknowledgement",
    )
}

fn persist_agent_task_started_report(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
) -> Result<(), CliError> {
    persist_agent_task_lifecycle_report(
        session,
        envelope,
        "task-started",
        fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskStarted {},
        "durable task started event",
    )
}

fn persist_agent_task_lifecycle_report(
    session: &AgentTaskExecutionSession<'_>,
    envelope: &fleet_domain::TaskEnvelope,
    report_id: &str,
    body: fleet_protocol::delivery_v2::V2TaskLifecycleReportBody,
    description: &str,
) -> Result<(), CliError> {
    let key = lifecycle_report_key(
        session.controller_namespace,
        session.config,
        envelope.job_id.as_str(),
        envelope.task_id.as_str(),
        report_id,
    )?;
    persist_agent_task_lifecycle_report_with_journal(session.journal_client, key, body, description)
}

fn lifecycle_report_key(
    controller_namespace: &str,
    config: &LocalAgentConfig,
    job_id: &str,
    task_id: &str,
    report_id: &str,
) -> Result<fleet_domain::delivery::ReportKey, CliError> {
    fleet_domain::delivery::ReportKey::new(
        controller_namespace,
        &config.agent_id,
        job_id,
        task_id,
        report_id,
    )
    .map_err(|error| CliError::Http(error.to_string()))
}

fn persist_agent_task_lifecycle_report_with_journal(
    journal: &fleet_agent::journal_worker::JournalClient,
    key: fleet_domain::delivery::ReportKey,
    body: fleet_protocol::delivery_v2::V2TaskLifecycleReportBody,
    description: &str,
) -> Result<(), CliError> {
    use fleet_application::delivery::JournalReport;
    use fleet_domain::delivery::ReportClass;

    let encoded_body = serde_json::to_vec(&body)
        .map_err(|_| CliError::Http(format!("failed to encode {description}")))?;
    if encoded_body.len() > fleet_protocol::delivery_v2::MAX_REPORT_BODY_BYTES {
        return Err(CliError::Http(format!(
            "{description} exceeds protocol limit"
        )));
    }
    let report = JournalReport::new(key, ReportClass::Lifecycle, encoded_body)
        .map_err(|error| CliError::Http(error.to_string()))?;
    journal
        .append(&report)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(())
}

fn persist_no_artifact_final_result_report_with_key(
    journal: &fleet_agent::journal_worker::JournalClient,
    key: fleet_domain::delivery::ReportKey,
    report: AgentTaskResultReport,
) -> Result<fleet_application::delivery::AppendReportOutcome, CliError> {
    use fleet_application::delivery::JournalReport;
    use fleet_domain::delivery::ReportClass;

    if !report.artifacts.is_empty() {
        return Err(CliError::Http(
            "durable final result cannot contain artifacts".to_owned(),
        ));
    }
    let body = serde_json::to_vec(&report)
        .map_err(|_| CliError::Http("failed to encode durable final result".to_owned()))?;
    if body.len() > fleet_protocol::delivery_v2::MAX_REPORT_BODY_BYTES {
        return Err(CliError::Http(
            "durable final result exceeds protocol limit".to_owned(),
        ));
    }
    let report = JournalReport::new(key, ReportClass::FinalResult, body)
        .map_err(|error| CliError::Http(error.to_string()))?;
    journal
        .append(&report)
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))
}

fn recover_interrupted_agent_execution(
    journal: &fleet_agent::journal_worker::JournalClient,
) -> Result<(), CliError> {
    let record = journal
        .interrupted()
        .map_err(|error| CliError::Http(error.to_string()))?
        .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
        .map_err(|error| CliError::Http(error.to_string()))?;
    let Some(record) = record else {
        return Ok(());
    };
    let interruption = record
        .interrupted_after_owner_exit()
        .ok_or_else(|| CliError::Http("journal execution is not interrupted".to_owned()))?;
    let reason = interruption.reason_code();
    persist_no_artifact_final_result_report_with_key(
        journal,
        record.snapshot().final_report_key.clone(),
        AgentTaskResultReport::new(-1, fleet_protocol::TaskResultStatus::Failed, reason)
            .with_output_summary(fleet_protocol::delivery_v2::V2OutputSummary {
                stdout_chunks: record.snapshot().stdout_chunks,
                stderr_chunks: record.snapshot().stderr_chunks,
                truncated: matches!(
                    interruption,
                    fleet_domain::delivery::InterruptedExecution::OutcomeUnknown
                ),
            }),
    )?;
    Ok(())
}

struct AgentPendingJournalReport {
    report: fleet_application::delivery::PendingReport,
    attempts: u32,
    retry_at: Instant,
}

struct AgentJournalReportDelivery {
    client: fleet_agent::journal_worker::JournalClient,
    identity: ControllerDeliveryIdentity,
    pending: HashMap<fleet_domain::delivery::ReportKey, AgentPendingJournalReport>,
    pending_scan: Option<
        fleet_agent::journal_worker::JournalTicket<Vec<fleet_application::delivery::PendingReport>>,
    >,
    acknowledgement_tickets: HashMap<
        fleet_domain::delivery::ReportKey,
        fleet_agent::journal_worker::JournalTicket<bool>,
    >,
    acknowledged_during_pending_scan: HashSet<fleet_domain::delivery::ReportKey>,
    next_scan_at: Instant,
}

impl AgentJournalReportDelivery {
    fn new(
        client: fleet_agent::journal_worker::JournalClient,
        identity: ControllerDeliveryIdentity,
    ) -> Self {
        Self {
            client,
            identity,
            pending: HashMap::new(),
            pending_scan: None,
            acknowledgement_tickets: HashMap::new(),
            acknowledged_during_pending_scan: HashSet::new(),
            next_scan_at: Instant::now(),
        }
    }

    fn drive(
        &mut self,
        socket: &mut AgentWebSocket,
        config: &LocalAgentConfig,
        correlation_id: &str,
    ) -> Result<(), CliError> {
        self.poll_acknowledgements()?;
        self.poll_pending_scan()?;
        self.submit_pending_scan_if_due()?;
        self.poll_pending_scan()?;

        let now = Instant::now();
        let mut due = self
            .pending
            .iter()
            .filter(|(_, report)| report.retry_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        due.sort_by(|left, right| {
            let left_report = &self
                .pending
                .get(left)
                .expect("due report exists in the delivery map")
                .report
                .report;
            let right_report = &self
                .pending
                .get(right)
                .expect("due report exists in the delivery map")
                .report
                .report;
            compare_agent_report_delivery_order(left_report, right_report)
        });
        due.truncate(AGENT_REPORT_SENDS_PER_TICK);
        for key in due {
            let pending = self
                .pending
                .get(&key)
                .ok_or_else(|| CliError::Http("agent report delivery state changed".to_owned()))?;
            let message =
                agent_journal_report_wire_message(&pending.report, config, correlation_id)?;
            send_wire_message_to_socket(socket, &message)?;
            if let Some(pending) = self.pending.get_mut(&key) {
                pending.attempts = pending.attempts.saturating_add(1);
                pending.retry_at = now + agent_report_retry_delay(pending.attempts);
            }
        }
        Ok(())
    }

    fn submit_pending_scan_if_due(&mut self) -> Result<(), CliError> {
        if self.pending_scan.is_some()
            || !self.acknowledgement_tickets.is_empty()
            || self.pending.len() >= AGENT_REPORT_BATCH_SIZE as usize
            || Instant::now() < self.next_scan_at
        {
            return Ok(());
        }
        match self
            .client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
        {
            Ok(ticket) => {
                self.pending_scan = Some(ticket);
                self.next_scan_at = Instant::now() + AGENT_REPORT_SCAN_INTERVAL;
            }
            Err(fleet_agent::journal_worker::JournalWorkerError::Busy) => {
                self.next_scan_at = Instant::now() + Duration::from_millis(50);
            }
            Err(error) => return Err(CliError::Http(error.to_string())),
        }
        Ok(())
    }

    fn poll_pending_scan(&mut self) -> Result<(), CliError> {
        let completed = match self.pending_scan.as_mut() {
            Some(ticket) => ticket
                .poll()
                .map_err(|error| CliError::Http(error.to_string()))?,
            None => None,
        };
        if let Some(reports) = completed {
            self.pending_scan = None;
            let now = Instant::now();
            for report in reports {
                if !matches!(
                    report.report.class,
                    fleet_domain::delivery::ReportClass::Output
                        | fleet_domain::delivery::ReportClass::Lifecycle
                        | fleet_domain::delivery::ReportClass::DriftEvidence
                        | fleet_domain::delivery::ReportClass::FinalResult
                ) {
                    return Err(CliError::Http(
                        "agent journal contains an unsupported report class".to_owned(),
                    ));
                }
                let key = report.report.key.clone();
                if !agent_report_scan_result_is_current(
                    &key,
                    &self.acknowledged_during_pending_scan,
                ) {
                    continue;
                }
                self.pending
                    .entry(key)
                    .or_insert(AgentPendingJournalReport {
                        report,
                        attempts: 0,
                        retry_at: now,
                    });
            }
            self.acknowledged_during_pending_scan.clear();
        }
        Ok(())
    }

    fn handle_receipt(
        &mut self,
        message: &fleet_protocol::WireMessage,
        receipt: &fleet_protocol::receipt::SignedReportReceiptWire,
        config: &LocalAgentConfig,
        controller_public_key: &str,
        correlation_id: &str,
        task_state: &AgentTaskSessionState,
    ) -> Result<(), CliError> {
        if message.agent_id.as_deref() != Some(config.agent_id.as_str())
            || message.correlation_id.0 != correlation_id
        {
            return Err(CliError::Http(
                "report receipt session identity mismatch".to_owned(),
            ));
        }
        let statement = &receipt.statement;
        let key = fleet_domain::delivery::ReportKey::new(
            &statement.controller_namespace,
            &statement.agent_id,
            &statement.job_id,
            &statement.task_id,
            &statement.report_id,
        )
        .map_err(|error| CliError::Http(error.to_string()))?;
        if self.acknowledgement_tickets.contains_key(&key) {
            return Ok(());
        }
        let Some(local) = self.pending.get(&key).map(|state| &state.report) else {
            return Ok(());
        };
        let trust =
            agent_controller_signing_trust_bundle(task_state, config, controller_public_key)?;
        let candidate = fleet_agent::receipt_verifier::verify_stored_receipt(
            receipt,
            local,
            &self.identity.namespace,
            &self.identity.store_epoch,
            &trust,
            SystemTime::now(),
        )
        .map_err(|error| CliError::Http(error.to_string()))?;
        match self.client.acknowledge(&candidate.key, candidate.digest) {
            Ok(ticket) => {
                self.acknowledgement_tickets.insert(candidate.key, ticket);
            }
            Err(fleet_agent::journal_worker::JournalWorkerError::Busy) => {}
            Err(error) => return Err(CliError::Http(error.to_string())),
        }
        Ok(())
    }

    fn poll_acknowledgements(&mut self) -> Result<(), CliError> {
        let keys = self
            .acknowledgement_tickets
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            let outcome = self
                .acknowledgement_tickets
                .get_mut(&key)
                .ok_or_else(|| {
                    CliError::Http("agent report acknowledgement disappeared".to_owned())
                })?
                .poll()
                .map_err(|error| CliError::Http(error.to_string()))?;
            let Some(removed) = outcome else {
                continue;
            };
            self.acknowledgement_tickets.remove(&key);
            if !removed {
                return Err(CliError::Http(
                    "agent report disappeared before receipt cleanup".to_owned(),
                ));
            }
            if self.pending_scan.is_some() {
                self.acknowledged_during_pending_scan.insert(key.clone());
            }
            self.pending.remove(&key);
            self.next_scan_at = Instant::now();
        }
        Ok(())
    }
}

fn agent_report_scan_result_is_current(
    key: &fleet_domain::delivery::ReportKey,
    acknowledged_during_scan: &HashSet<fleet_domain::delivery::ReportKey>,
) -> bool {
    !acknowledged_during_scan.contains(key)
}

fn agent_report_retry_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(5);
    let multiplier = 1_u32 << exponent;
    AGENT_REPORT_RETRY_BASE
        .saturating_mul(multiplier)
        .min(AGENT_REPORT_RETRY_MAX)
}

fn compare_agent_report_delivery_order(
    left: &fleet_application::delivery::JournalReport,
    right: &fleet_application::delivery::JournalReport,
) -> std::cmp::Ordering {
    let class_rank = |class| match class {
        fleet_domain::delivery::ReportClass::Lifecycle => 0_u8,
        fleet_domain::delivery::ReportClass::DriftEvidence => 1,
        fleet_domain::delivery::ReportClass::Output => 2,
        fleet_domain::delivery::ReportClass::FinalResult => 3,
    };
    class_rank(left.class)
        .cmp(&class_rank(right.class))
        .then_with(|| lifecycle_report_rank(left).cmp(&lifecycle_report_rank(right)))
        .then_with(|| left.key.parts().cmp(&right.key.parts()))
}

fn lifecycle_report_rank(report: &fleet_application::delivery::JournalReport) -> u8 {
    if report.class != fleet_domain::delivery::ReportClass::Lifecycle {
        return 0;
    }
    match serde_json::from_slice::<fleet_protocol::delivery_v2::V2TaskLifecycleReportBody>(
        report.body(),
    ) {
        Ok(fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskAck {}) => 0,
        Ok(fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskStarted {}) => 1,
        Ok(fleet_protocol::delivery_v2::V2TaskLifecycleReportBody::TaskRejected { .. }) => 2,
        Err(_) => 3,
    }
}

fn agent_journal_report_wire_message(
    pending: &fleet_application::delivery::PendingReport,
    config: &LocalAgentConfig,
    correlation_id: &str,
) -> Result<fleet_protocol::WireMessage, CliError> {
    let report = fleet_protocol::delivery_v2::V2TaskReportWire::new(
        &pending.report.key,
        pending.report.class,
        pending.report.body(),
    )
    .map_err(|error| CliError::Http(error.to_string()))?;
    Ok(fleet_protocol::WireMessage::new(
        prefixed_ulid("msg")?,
        correlation_id.to_owned(),
        Some(config.agent_id.clone()),
        epoch_millis() as u64,
        fleet_protocol::WirePayload::TaskReport(report),
    ))
}

fn send_agent_security_event_queue(
    outbound_sender: &AgentOutboundQueue,
    config: &LocalAgentConfig,
    correlation_id: &str,
    action: &str,
    detail: &str,
) -> Result<(), CliError> {
    enqueue_wire_message(
        outbound_sender,
        agent_security_event_message(config, correlation_id, action, detail)?,
    )
}

struct ControllerSignatureVerifier;

impl fleet_runner::ControllerSigningMaterialVerifier for ControllerSignatureVerifier {
    fn verify(&self, public_key: &str, payload_hash: &str, signature: &str) -> bool {
        fleet_core::verify_challenge_signature(public_key, payload_hash, signature).unwrap_or(false)
    }
}

fn task_envelope_from_wire(
    envelope: fleet_protocol::SignedTaskEnvelopeWire,
) -> Result<fleet_domain::TaskEnvelope, CliError> {
    Ok(fleet_domain::TaskEnvelope {
        job_id: fleet_domain::JobId::new(envelope.job_id)
            .map_err(|error| CliError::Http(error.to_string()))?,
        task_id: fleet_domain::TaskId::new(envelope.task_id)
            .map_err(|error| CliError::Http(error.to_string()))?,
        target_agent_id: fleet_domain::AgentId::new(envelope.target_agent_id)
            .map_err(|error| CliError::Http(error.to_string()))?,
        issued_at: millis_to_system_time(envelope.issued_at_ms),
        expires_at: fleet_domain::TaskExpiry::new(millis_to_system_time(envelope.expires_at_ms)),
        nonce: fleet_domain::TaskNonce::new(envelope.nonce)
            .map_err(|error| CliError::Http(error.to_string()))?,
        payload_hash: envelope.payload_hash,
        signature: Some(
            fleet_domain::TaskSignature::new(envelope.signature)
                .map_err(|error| CliError::Http(error.to_string()))?,
        ),
    })
}

fn output_stream_to_wire(
    stream: fleet_runner::CommandOutputStream,
) -> fleet_protocol::OutputStream {
    match stream {
        fleet_runner::CommandOutputStream::Stdout => fleet_protocol::OutputStream::Stdout,
        fleet_runner::CommandOutputStream::Stderr => fleet_protocol::OutputStream::Stderr,
    }
}

fn read_ws_message(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
) -> Result<fleet_protocol::WireMessage, CliError> {
    loop {
        match socket.read() {
            Ok(message) => {
                let body = message
                    .to_text()
                    .map_err(|error| CliError::Http(error.to_string()))?;
                return fleet_protocol::decode_message(body)
                    .map_err(|error| CliError::Http(error.to_string()));
            }
            Err(error) if handshake_read_error_is_retryable(&error) => continue,
            Err(error) => return Err(CliError::Http(error.to_string())),
        }
    }
}

/// Retries only an OS-interrupted handshake read; timeouts and protocol failures stay fatal.
fn handshake_read_error_is_retryable(error: &tungstenite::Error) -> bool {
    matches!(
        error,
        tungstenite::Error::Io(error) if error.kind() == std::io::ErrorKind::Interrupted
    )
}

fn prefixed_ulid(prefix: &str) -> Result<String, CliError> {
    fleet_core::generate_prefixed_ulid(prefix).map_err(CliError::from)
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn millis_to_system_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(value)
}

fn system_time_to_millis(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn authenticated_session_requires_valid_controller_delivery_identity() {
        let accepted = fleet_protocol::WireMessage::new(
            "msg-accepted",
            "corr-accepted",
            Some("agent-1".to_owned()),
            1,
            fleet_protocol::WirePayload::AuthAccepted {
                controller_namespace: "a".repeat(64),
                store_epoch: "b".repeat(64),
            },
        );

        assert_eq!(
            controller_delivery_identity_from_auth_accepted(accepted, "agent-1", "corr-accepted",)
                .unwrap(),
            ControllerDeliveryIdentity {
                namespace: "a".repeat(64),
                store_epoch: "b".repeat(64),
            }
        );

        for (controller_namespace, store_epoch) in [
            ("short".to_owned(), "b".repeat(64)),
            ("A".repeat(64), "b".repeat(64)),
            ("g".repeat(64), "b".repeat(64)),
            ("a".repeat(64), "".to_owned()),
        ] {
            let message = fleet_protocol::WireMessage::new(
                "msg-invalid-accepted",
                "corr-invalid-accepted",
                Some("agent-1".to_owned()),
                1,
                fleet_protocol::WirePayload::AuthAccepted {
                    controller_namespace,
                    store_epoch,
                },
            );
            assert!(matches!(
                controller_delivery_identity_from_auth_accepted(
                    message,
                    "agent-1",
                    "corr-invalid-accepted",
                ),
                Err(CliError::Http(message)) if message == "controller delivery identity is invalid"
            ));
        }

        let wrong_payload = fleet_protocol::WireMessage::new(
            "msg-wrong-payload",
            "corr-wrong-payload",
            Some("agent-1".to_owned()),
            1,
            fleet_protocol::WirePayload::Heartbeat {
                agent_id: "agent-1".to_owned(),
                status: "online".to_owned(),
            },
        );
        assert!(matches!(
            controller_delivery_identity_from_auth_accepted(
                wrong_payload,
                "agent-1",
                "corr-wrong-payload",
            ),
            Err(CliError::Http(message)) if message == "expected auth accepted"
        ));

        for (message_agent_id, message_correlation_id) in [
            ("agent-2", "corr-accepted"),
            ("agent-1", "corr-other-session"),
        ] {
            let mismatched_session = fleet_protocol::WireMessage::new(
                "msg-mismatched-session",
                message_correlation_id,
                Some(message_agent_id.to_owned()),
                1,
                fleet_protocol::WirePayload::AuthAccepted {
                    controller_namespace: "a".repeat(64),
                    store_epoch: "b".repeat(64),
                },
            );
            assert!(matches!(
                controller_delivery_identity_from_auth_accepted(
                    mismatched_session,
                    "agent-1",
                    "corr-accepted"
                ),
                Err(CliError::Http(message)) if message == "auth accepted session identity mismatch"
            ));
        }
    }

    fn test_outbound_queue(capacity: usize) -> AgentOutboundQueue {
        Arc::new(Mutex::new(fleet_agent::AgentSessionSupervisor::new(
            capacity,
        )))
    }

    fn take_outbound_message(queue: &AgentOutboundQueue) -> Option<fleet_protocol::WireMessage> {
        queue.lock().unwrap().remove_pending_report()
    }

    struct TestOutboundReceiver(AgentOutboundQueue);

    impl TestOutboundReceiver {
        fn try_recv(&self) -> Result<fleet_protocol::WireMessage, mpsc::TryRecvError> {
            take_outbound_message(&self.0).ok_or(mpsc::TryRecvError::Empty)
        }
    }

    #[derive(Debug)]
    struct OuterHttpTestError {
        source: InnerHttpTestError,
    }

    impl Display for OuterHttpTestError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "outer request failed")
        }
    }

    impl StdError for OuterHttpTestError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.source)
        }
    }

    #[derive(Debug)]
    struct InnerHttpTestError;

    impl Display for InnerHttpTestError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "connection refused")
        }
    }

    impl StdError for InnerHttpTestError {}

    #[test]
    fn parses_controller_init() {
        let cli = Cli::try_parse_from(["fleet", "controller", "init"]).expect("valid command");
        assert!(matches!(
            cli.command,
            Command::Controller(ControllerCommand {
                command: ControllerSubcommand::Init { .. }
            })
        ));
    }

    #[test]
    fn http_request_error_message_includes_source_chain_and_connect_hint() {
        let error = OuterHttpTestError {
            source: InnerHttpTestError,
        };

        let message = http_request_error_message(
            "agent enrollment",
            "http://192.168.10.11:7700/api/agents/enroll",
            &error,
        );

        assert!(message.contains("agent enrollment failed"));
        assert!(message.contains("outer request failed"));
        assert!(message.contains("connection refused"));
        assert!(message.contains("controller is running"));
        assert!(message.contains("0.0.0.0"));
        assert!(message.contains("firewall"));
    }

    #[test]
    fn parses_controller_start_sqlite_db_url() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "start",
            "--db",
            "sqlite:///tmp/fleet.db",
        ])
        .expect("valid command");

        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::Start { db, .. },
        }) = cli.command
        else {
            panic!("expected controller start command");
        };

        assert_eq!(db.as_deref(), Some("sqlite:///tmp/fleet.db"));
        let settings =
            parse_controller_database_settings(db.as_deref(), Path::new("/ignored/data-dir"))
                .unwrap();
        assert_eq!(settings.backend_name(), "sqlite");
        assert_eq!(settings.sqlite_path(), Some(Path::new("/tmp/fleet.db")));
    }

    #[test]
    fn agent_runbook_secret_handoff_disabled_provider_rejects_without_ref_leak() {
        let runbook = fleet_domain::parse_runbook_document(
            r#"
apiVersion: fleet.sponzey.dev/v1alpha1
kind: Runbook
name: secret-template
selector: role=web
steps:
  - id: write-token
    file.template:
      dest: /tmp/fleet-secret.conf
      content: "token={{ api_token }}"
      secretRefs: api_token=secret://app/disabled-token
"#,
        )
        .unwrap();

        let error = build_agent_runbook_execution_plan_with_provider(
            &runbook,
            fleet_runner::LinuxPackageManager::Apt,
            &DisabledSecretProvider,
        )
        .expect_err("disabled provider should reject secret-backed template planning");

        let message = error.to_string();
        assert!(message.contains("template render error"));
        assert!(!message.contains("disabled-token"));
        assert!(!message.contains("secret://app"));
    }

    #[test]
    fn agent_runbook_secret_handoff_static_provider_renders_without_artifact_body() {
        let destination = unique_test_dir("agent-secret-handoff").join("secret.conf");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let runbook = fleet_domain::parse_runbook_document(&format!(
            r#"
apiVersion: fleet.sponzey.dev/v1alpha1
kind: Runbook
name: secret-template
selector: role=web
steps:
  - id: write-token
    file.template:
      dest: {}
      content: "token={{{{ api_token }}}}"
      secretRefs: api_token=secret://app/api-token
"#,
            destination.display()
        ))
        .unwrap();
        let reference = fleet_domain::SecretRef::parse("secret://app/api-token").unwrap();
        let raw_secret = "agent-static-provider-secret";
        let provider =
            fleet_application::StaticSecretProvider::new().with_secret(reference, raw_secret);

        let plan = build_agent_runbook_execution_plan_with_provider(
            &runbook,
            fleet_runner::LinuxPackageManager::Apt,
            &provider,
        )
        .expect("static provider should plan secret-backed template");
        let report = fleet_runner::execute_runbook_execution_plan_with_hooks(
            &plan,
            fleet_runner::RunbookExecutionOptions {
                confirmed_high_risk: true,
                ..fleet_runner::RunbookExecutionOptions::default()
            },
            runbook_command_runner,
            fleet_runner::copy_file_atomic,
            fleet_runner::check_tcp_port,
            fleet_runner::check_local_process,
            collect_runbook_snapshot,
        )
        .expect("secret-backed template should execute");

        let artifact = report.outcomes[0]
            .artifact
            .as_ref()
            .expect("template should report artifact metadata");
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            format!("token={raw_secret}")
        );
        assert_eq!(artifact.content_bytes, None);
        assert!(!format!("{report:?}").contains(raw_secret));
    }

    #[test]
    fn apply_validation_does_not_resolve_secret_backed_templates() {
        let dir = unique_test_dir("apply-secret-validation");
        std::fs::create_dir_all(&dir).unwrap();
        let runbook_path = dir.join("secret-runbook.yml");
        std::fs::write(
            &runbook_path,
            r#"
apiVersion: fleet.sponzey.dev/v1alpha1
kind: Runbook
name: secret-template
selector: role=web
steps:
  - id: write-token
    file.template:
      dest: /tmp/fleet-secret.conf
      content: "token={{ api_token }}"
      secretRefs: api_token=secret://app/apply-token
"#,
        )
        .unwrap();

        let error = execute_apply(ApplyCommand { file: runbook_path })
            .expect_err("apply validation must not resolve secret-backed templates");

        let message = error.to_string();
        assert!(message.contains("invalid runbook primitive"));
        assert!(!message.contains("apply-token"));
        assert!(!message.contains("secret://app"));
    }

    #[test]
    fn parses_controller_start_postgres_db_url_as_typed_backend() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "start",
            "--db",
            "postgresql://fleet:secret@db.example.com/fleet",
        ])
        .expect("valid command");

        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::Start { db, .. },
        }) = cli.command
        else {
            panic!("expected controller start command");
        };

        let settings =
            parse_controller_database_settings(db.as_deref(), Path::new("/ignored/data-dir"))
                .unwrap();
        assert_eq!(settings.backend_name(), "postgres");
        assert_eq!(settings.sqlite_path(), None);
    }

    #[test]
    fn rejects_unsupported_controller_db_url_scheme_without_leaking_secret() {
        let error = parse_controller_database_settings(
            Some("mysql://fleet:secret@db.example.com/fleet"),
            Path::new("/ignored/data-dir"),
        )
        .expect_err("unsupported database scheme should fail");

        let message = error.to_string();
        assert!(message.contains("mysql"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("db.example.com"));
    }

    #[test]
    fn parses_controller_backup_and_restore_commands() {
        let backup = Cli::try_parse_from([
            "fleet",
            "controller",
            "backup",
            "--data-dir",
            "/tmp/fleet",
            "--output",
            "/tmp/fleet.backup.json",
        ])
        .expect("valid backup command");
        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::Backup { data_dir, output },
        }) = backup.command
        else {
            panic!("expected controller backup command");
        };
        assert_eq!(data_dir, PathBuf::from("/tmp/fleet"));
        assert_eq!(output, PathBuf::from("/tmp/fleet.backup.json"));

        let restore = Cli::try_parse_from([
            "fleet",
            "controller",
            "restore",
            "--data-dir",
            "/tmp/fleet-restored",
            "--input",
            "/tmp/fleet.backup.json",
            "--dry-run",
            "--force",
        ])
        .expect("valid restore command");
        let Command::Controller(ControllerCommand {
            command:
                ControllerSubcommand::Restore {
                    data_dir,
                    input,
                    dry_run,
                    force,
                },
        }) = restore.command
        else {
            panic!("expected controller restore command");
        };
        assert_eq!(data_dir, PathBuf::from("/tmp/fleet-restored"));
        assert_eq!(input, PathBuf::from("/tmp/fleet.backup.json"));
        assert!(dry_run);
        assert!(force);
    }

    #[test]
    fn parses_controller_start_external_https_url() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "start",
            "--host",
            "0.0.0.0",
            "--external-url",
            "https://fleet.example.com",
        ])
        .expect("valid command");

        let Command::Controller(ControllerCommand {
            command:
                ControllerSubcommand::Start {
                    host, external_url, ..
                },
        }) = cli.command
        else {
            panic!("expected controller start command");
        };

        assert_eq!(host, "0.0.0.0");
        assert_eq!(external_url.as_deref(), Some("https://fleet.example.com"));
    }

    #[test]
    fn parses_controller_start_builtin_tls_paths() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "start",
            "--external-url",
            "https://fleet.example.com",
            "--tls-cert",
            "/etc/fleet/tls/fullchain.pem",
            "--tls-key",
            "/etc/fleet/tls/privkey.pem",
        ])
        .expect("valid command");

        let Command::Controller(ControllerCommand {
            command:
                ControllerSubcommand::Start {
                    tls_cert, tls_key, ..
                },
        }) = cli.command
        else {
            panic!("expected controller start command");
        };

        assert_eq!(
            tls_cert.as_deref(),
            Some(Path::new("/etc/fleet/tls/fullchain.pem"))
        );
        assert_eq!(
            tls_key.as_deref(),
            Some(Path::new("/etc/fleet/tls/privkey.pem"))
        );
    }

    #[test]
    fn parses_controller_start_agent_client_ca_cert() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "start",
            "--external-url",
            "https://fleet.example.com",
            "--agent-client-ca-cert",
            "/etc/fleet/agent-client-ca.pem",
        ])
        .expect("valid command");

        let Command::Controller(ControllerCommand {
            command:
                ControllerSubcommand::Start {
                    agent_client_ca_cert,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected controller start command");
        };

        assert_eq!(
            agent_client_ca_cert.as_deref(),
            Some(Path::new("/etc/fleet/agent-client-ca.pem"))
        );
    }

    #[test]
    fn controller_start_preflight_explains_missing_init() {
        let data_dir = unique_demo_dir();
        let error = ensure_controller_initialized_for_start(&data_dir)
            .expect_err("missing controller init should be explained");
        let message = error.to_string();

        assert!(matches!(
            error,
            CliError::ControllerNotInitialized { data_dir: _ }
        ));
        assert!(message.contains("controller is not initialized"));
        assert!(message.contains("fleet controller init --data-dir"));
        assert!(message.contains("./scripts/run_controller.sh"));
    }

    #[test]
    fn enroll_token_create_persists_scope_and_audit() {
        let data_dir = unique_test_dir("enroll-token-create");
        let cli = Cli::try_parse_from([
            "fleet",
            "enroll-token",
            "create",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--labels",
            "role=web,env=prod",
            "--max-uses",
            "2",
            "--expires-in-seconds",
            "120",
            "--controller-url",
            "https://fleet.example.com",
            "--name",
            "web-01",
            "--print-init-command",
        ])
        .expect("valid command");

        execute(cli).expect("token create should succeed");

        let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
        let records = store.list_enrollment_tokens().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].default_labels, "role=web,env=prod");
        assert_eq!(records[0].max_uses, 2);
        assert_eq!(records[0].used_count, 0);
        assert!(!records[0].revoked);
        let audits = store
            .list_audit_events_by_category(fleet_domain::AuditCategory::Security, 10)
            .unwrap();
        assert!(
            audits
                .iter()
                .any(|event| event.action == "enrollment_token_created")
        );
        assert!(
            audits
                .iter()
                .all(|event| !format!("{:?}", event.value).contains("enroll-"))
        );
    }

    #[test]
    fn enroll_token_revoke_updates_state_and_audit() {
        let data_dir = unique_test_dir("enroll-token-revoke");
        fs::create_dir_all(controller_dir(&data_dir)).unwrap();
        let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
        store
            .insert_enrollment_token_hash(
                "et-1",
                &fleet_controller::hash_token("raw-token"),
                "role=web",
                SystemTime::now() + Duration::from_secs(60),
                1,
            )
            .unwrap();
        drop(store);

        let cli = Cli::try_parse_from([
            "fleet",
            "enroll-token",
            "revoke",
            "et-1",
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .expect("valid command");
        execute(cli).expect("token revoke should succeed");

        let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
        let records = store.list_enrollment_tokens().unwrap();
        assert!(records[0].revoked);
        let audits = store
            .list_audit_events_by_category(fleet_domain::AuditCategory::Security, 10)
            .unwrap();
        assert!(
            audits
                .iter()
                .any(|event| event.action == "enrollment_token_revoked")
        );
    }

    #[test]
    fn rejects_unsupported_controller_db_url_scheme() {
        assert!(matches!(
            parse_controller_database_settings(
                Some("mysql://localhost/fleet"),
                Path::new("/ignored/data-dir")
            ),
            Err(CliError::Http(_))
        ));
    }

    #[test]
    fn renders_controller_service_unit_with_absolute_binary() {
        let unit = render_service_unit(
            ServiceRole::Controller,
            Path::new("/usr/local/bin/fleet"),
            Path::new("/var/lib/fleet"),
            Some("fleet"),
            Some("fleet"),
        )
        .unwrap();

        assert!(unit.contains("Description=Sponzey Fleet Controller"));
        assert!(
            unit.contains(
                "ExecStart=/usr/local/bin/fleet controller start --data-dir /var/lib/fleet"
            )
        );
        assert!(unit.contains("User=fleet"));
        assert!(unit.contains("Group=fleet"));
    }

    #[test]
    fn renders_agent_service_unit_with_quoted_paths() {
        let unit = render_service_unit(
            ServiceRole::Agent,
            Path::new("/opt/Fleet/bin/fleet"),
            Path::new("/var/lib/fleet path"),
            None,
            None,
        )
        .unwrap();

        assert!(unit.contains("Description=Sponzey Fleet Agent"));
        assert!(unit.contains(
            "ExecStart=/opt/Fleet/bin/fleet agent start --data-dir \"/var/lib/fleet path\""
        ));
    }

    #[test]
    fn service_unit_rejects_relative_binary_path() {
        assert!(matches!(
            render_service_unit(
                ServiceRole::Agent,
                Path::new("target/debug/fleet"),
                Path::new("/var/lib/fleet"),
                None,
                None,
            ),
            Err(CliError::ServiceBinaryMustBeAbsolute(_))
        ));
    }

    #[test]
    fn service_unit_rejects_invalid_user() {
        assert!(matches!(
            render_service_unit(
                ServiceRole::Controller,
                Path::new("/usr/local/bin/fleet"),
                Path::new("/var/lib/fleet"),
                Some("bad user"),
                None,
            ),
            Err(CliError::InvalidServiceAccount(_))
        ));
    }

    #[test]
    fn service_install_guard_message_mentions_systemd_requirements() {
        assert_eq!(
            CliError::ServiceInstallRequiresDryRun.to_string(),
            "service install writes system files and requires Linux root; use --dry-run to inspect the unit first"
        );
    }

    #[test]
    fn agent_start_service_dry_run_renders_systemctl_command() {
        let cli = Cli::try_parse_from(["fleet", "agent", "start-service", "--dry-run"]).unwrap();

        assert!(execute(cli).is_ok());
        assert_eq!(
            render_systemctl_command("start", ServiceRole::Agent),
            "systemctl start fleet-agent.service"
        );
    }

    #[test]
    fn controller_restart_service_dry_run_renders_systemctl_command() {
        let cli =
            Cli::try_parse_from(["fleet", "controller", "restart-service", "--dry-run"]).unwrap();

        assert!(execute(cli).is_ok());
        assert_eq!(
            render_systemctl_command("restart", ServiceRole::Controller),
            "systemctl restart fleet-controller.service"
        );
    }

    #[test]
    fn service_status_and_logs_dry_run_render_commands() {
        let status =
            Cli::try_parse_from(["fleet", "controller", "status-service", "--dry-run"]).unwrap();
        let logs = Cli::try_parse_from([
            "fleet",
            "agent",
            "logs-service",
            "--lines",
            "25",
            "--dry-run",
        ])
        .unwrap();

        assert!(execute(status).is_ok());
        assert!(execute(logs).is_ok());
        assert_eq!(
            render_service_status_command(ServiceRole::Controller),
            "systemctl status fleet-controller.service --no-pager"
        );
        assert_eq!(
            render_service_logs_command(ServiceRole::Agent, 25),
            "journalctl -u fleet-agent.service --no-pager -n 25"
        );
    }

    #[test]
    fn agent_uninstall_service_dry_run_renders_safe_commands() {
        let cli =
            Cli::try_parse_from(["fleet", "agent", "uninstall-service", "--dry-run"]).unwrap();

        assert!(execute(cli).is_ok());
        assert_eq!(
            render_uninstall_service_commands(ServiceRole::Agent),
            vec![
                "systemctl disable --now fleet-agent.service".to_owned(),
                "rm /etc/systemd/system/fleet-agent.service".to_owned(),
                "systemctl daemon-reload".to_owned(),
            ]
        );
    }

    #[test]
    fn controller_service_unit_path_is_systemd_path() {
        assert_eq!(
            systemd_unit_path(ServiceRole::Controller),
            PathBuf::from("/etc/systemd/system/fleet-controller.service")
        );
    }

    #[test]
    fn service_operation_error_mentions_linux_or_root() {
        assert_eq!(
            CliError::ServiceOperationRequiresLinux.to_string(),
            "systemd service operations require Linux"
        );
        assert_eq!(
            CliError::ServiceOperationRequiresRoot.to_string(),
            "systemd service operations require root; rerun with sudo"
        );
    }

    #[test]
    fn parses_upgrade_dry_run_and_rejects_automatic_upgrade() {
        let cli = Cli::try_parse_from([
            "fleet",
            "upgrade",
            "--channel",
            "beta",
            "--version",
            "0.2.0-beta.1",
            "--dry-run",
        ])
        .expect("valid upgrade dry-run command");
        let Command::Upgrade(UpgradeCommand {
            channel,
            version,
            dry_run,
        }) = cli.command
        else {
            panic!("expected upgrade command");
        };
        assert_eq!(channel, UpgradeChannelArg::Beta);
        assert_eq!(version.as_deref(), Some("0.2.0-beta.1"));
        assert!(dry_run);

        let cli = Cli::try_parse_from(["fleet", "upgrade"]).expect("valid upgrade command");
        assert!(matches!(execute(cli), Err(CliError::UpgradeRequiresDryRun)));

        let lines = upgrade_dry_run_lines(&UpgradeCommand {
            channel: UpgradeChannelArg::Beta,
            version: Some("0.2.0-beta.1".to_owned()),
            dry_run: true,
        });
        assert!(
            lines.contains(
                &"artifact_integrity_command=./scripts/verify_standalone_artifacts.sh dist/release"
                    .to_owned()
            )
        );
        assert!(lines.contains(&"artifact_signature_command=./scripts/verify_release_signature.sh dist/release <release-public-key.pem>".to_owned()));
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("recommended_backup_command="))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("recovery_policy="))
        );
        assert!(lines.iter().any(|line| line.starts_with("service_policy=")));
    }

    #[test]
    fn parses_run_command() {
        let cli = Cli::try_parse_from([
            "fleet",
            "run",
            "--selector",
            "role=web",
            "--confirm-risk",
            "uptime",
        ])
        .expect("valid command");

        let Command::Run(command) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(command.selector.as_deref(), Some("role=web"));
        assert!(command.confirm_risk);
        assert_eq!(command.command, ["uptime"]);
    }

    #[test]
    fn parses_remote_run_command_with_explicit_admin_token() {
        let cli = Cli::try_parse_from([
            "fleet",
            "run",
            "--controller-url",
            "http://127.0.0.1:7700",
            "--admin-token",
            "admin-secret",
            "--selector",
            "role=web",
            "--job-id",
            "job-cli-1",
            "--timeout-seconds",
            "45",
            "--confirm-risk",
            "uptime",
            "--",
            "-a",
        ])
        .expect("valid remote run command");

        let Command::Run(command) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(
            command.controller_url.as_deref(),
            Some("http://127.0.0.1:7700")
        );
        assert_eq!(command.admin_token.as_deref(), Some("admin-secret"));
        assert_eq!(command.selector.as_deref(), Some("role=web"));
        assert_eq!(command.job_id.as_deref(), Some("job-cli-1"));
        assert_eq!(command.timeout_seconds, 45);
        assert_eq!(command.command, ["uptime", "-a"]);
    }

    #[test]
    fn parses_login_and_remote_operator_commands() {
        let login = Cli::try_parse_from([
            "fleet",
            "login",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
        ])
        .expect("valid login command");
        let Command::Login(command) = login.command else {
            panic!("expected login command");
        };
        assert_eq!(command.controller_url, "https://fleet.example.com");
        assert_eq!(command.admin_token.as_deref(), Some("admin-secret"));
        assert_eq!(
            command.profile_path,
            PathBuf::from(DEFAULT_CLI_PROFILE_PATH)
        );

        let preview =
            Cli::try_parse_from(["fleet", "selectors", "preview", "--selector", "role=web"])
                .expect("valid selector preview command");
        let Command::Selectors(command) = preview.command else {
            panic!("expected selectors command");
        };
        let SelectorsSubcommand::Preview { selector, api } = command.command;
        assert_eq!(selector, "role=web");
        assert_eq!(api.profile_path, PathBuf::from(DEFAULT_CLI_PROFILE_PATH));

        let jobs =
            Cli::try_parse_from(["fleet", "jobs", "output", "job-1"]).expect("valid jobs command");
        assert!(matches!(
            jobs.command,
            Command::Jobs(JobsCommand {
                command: JobsSubcommand::Output { .. }
            })
        ));

        let remediations = Cli::try_parse_from([
            "fleet",
            "remediations",
            "list",
            "--agent-id",
            "agent-1",
            "--policy-id",
            "nginx-running",
            "--limit",
            "10",
        ])
        .expect("valid remediations list command");
        assert!(matches!(
            remediations.command,
            Command::Remediations(RemediationsCommand {
                command: RemediationsSubcommand::List { .. }
            })
        ));

        let remediation_approve = Cli::try_parse_from([
            "fleet",
            "remediations",
            "approve",
            "rem-1",
            "--approval-id",
            "approval-1",
            "--job-id",
            "job-1",
            "--runbook",
            "runbooks/remediate.yml",
        ])
        .expect("valid remediations approve command");
        assert!(matches!(
            remediation_approve.command,
            Command::Remediations(RemediationsCommand {
                command: RemediationsSubcommand::Approve { .. }
            })
        ));

        let audit = Cli::try_parse_from([
            "fleet",
            "audit",
            "export",
            "--category",
            "security",
            "--limit",
            "10",
            "--before",
            "3:1",
        ])
        .expect("valid audit export command");
        let Command::Audit(command) = audit.command else {
            panic!("expected audit command");
        };
        let AuditSubcommand::Export {
            category,
            limit,
            before,
            ..
        } = command.command;
        assert_eq!(category.as_deref(), Some("security"));
        assert_eq!(limit, 10);
        assert_eq!(before.as_deref(), Some("3:1"));
    }

    #[test]
    fn parses_agent_certificate_issuance_request_command() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agents",
            "request-certificate-issuance",
            "agent-1",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--json",
        ])
        .expect("valid agent certificate issuance request command");

        let Command::Agents(command) = cli.command else {
            panic!("expected agents command");
        };
        let AgentsSubcommand::RequestCertificateIssuance {
            agent_id,
            api,
            json,
        } = command.command
        else {
            panic!("expected request certificate issuance command");
        };

        assert_eq!(agent_id, "agent-1");
        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert!(json);
    }

    #[test]
    fn renders_agent_certificate_issuance_request_without_material() {
        let body = serde_json::json!({
            "agent_id": "agent-1",
            "action": "request_issuance",
            "lifecycle_state": "issuance_requested",
            "dispatch_status": "sent",
            "current_fingerprint_prefix": null,
            "next_fingerprint_prefix": null,
            "audit_event_action": "agent_certificate_issuance_requested",
            "updated_at_ms": 1000
        })
        .to_string();

        let rendered = render_agent_certificate_issuance_request_for_cli(&body)
            .expect("issuance response should render")
            .join("\n");

        assert!(rendered.contains("agent_id=agent-1"));
        assert!(rendered.contains("action=request_issuance"));
        assert!(rendered.contains("state=issuance_requested"));
        assert!(rendered.contains("dispatch_status=sent"));
        assert!(rendered.contains("current_fingerprint_prefix=none"));
        assert!(!rendered.contains("certificate_body"));
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains("ca_path"));
        assert!(!rendered.contains("admin-secret"));
        assert!(!rendered.contains("runtime_env"));
    }

    #[test]
    fn parses_agent_certificate_lifecycle_status_command() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agents",
            "certificate-status",
            "agent-1",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--json",
        ])
        .expect("valid agent certificate lifecycle status command");

        let Command::Agents(command) = cli.command else {
            panic!("expected agents command");
        };
        let AgentsSubcommand::CertificateStatus {
            agent_id,
            api,
            json,
        } = command.command
        else {
            panic!("expected certificate status command");
        };

        assert_eq!(agent_id, "agent-1");
        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert!(json);
    }

    #[test]
    fn renders_agent_certificate_lifecycle_status_without_material() {
        let body = serde_json::json!({
            "agent_id": "agent-1",
            "record_present": true,
            "lifecycle_state": "dual_certificate_active",
            "current_fingerprint_prefix": "0123456789ab",
            "next_fingerprint_prefix": "fedcba987654",
            "grace_until_ms": 2000,
            "revocation_reason": null,
            "updated_at_ms": 1000
        })
        .to_string();

        let rendered = render_agent_certificate_lifecycle_status_for_cli(&body)
            .expect("certificate lifecycle status should render")
            .join("\n");

        assert!(rendered.contains("agent_id=agent-1"));
        assert!(rendered.contains("state=dual_certificate_active"));
        assert!(rendered.contains("record_present=true"));
        assert!(rendered.contains("current_fingerprint_prefix=0123456789ab"));
        assert!(rendered.contains("next_fingerprint_prefix=fedcba987654"));
        assert!(rendered.contains("grace_until_ms=2000"));
        assert!(!rendered.contains("certificate_body"));
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains("ca_path"));
        assert!(!rendered.contains("admin-secret"));
        assert!(!rendered.contains("runtime_env"));
    }

    #[test]
    fn parses_controller_signing_rotation_status_command() {
        let cli = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation-status",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--json",
        ])
        .expect("valid controller signing rotation status command");

        let Command::Controller(command) = cli.command else {
            panic!("expected controller command");
        };
        let ControllerSubcommand::SigningRotationStatus { api, json } = command.command else {
            panic!("expected signing rotation status command");
        };

        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert!(json);
    }

    #[test]
    fn parses_controller_signing_rotation_mutation_commands() {
        let request = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "request",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--new-fingerprint",
            "new-fingerprint",
            "--old-key-verifies-for-seconds",
            "3600",
            "--json",
        ])
        .expect("valid signing rotation request command");
        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::SigningRotation { command },
        }) = request.command
        else {
            panic!("expected signing rotation command");
        };
        let ControllerSigningRotationSubcommand::Request {
            api,
            new_fingerprint,
            old_key_verifies_for_seconds,
            json,
            ..
        } = command
        else {
            panic!("expected request command");
        };
        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert_eq!(new_fingerprint, "new-fingerprint");
        assert_eq!(old_key_verifies_for_seconds, Some(3600));
        assert!(json);

        let validate = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "validate",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--candidate-public-key-path",
            "/var/lib/fleet/controller/candidate_public.key",
            "--candidate-private-key-path",
            "/var/lib/fleet/controller/candidate_private.key",
        ])
        .expect("valid signing rotation validate command");
        assert!(matches!(
            validate.command,
            Command::Controller(ControllerCommand {
                command: ControllerSubcommand::SigningRotation {
                    command: ControllerSigningRotationSubcommand::Validate { .. }
                }
            })
        ));

        for action in ["activate", "retire", "fail"] {
            let parsed = Cli::try_parse_from([
                "fleet",
                "controller",
                "signing-rotation",
                action,
                "--controller-url",
                "https://fleet.example.com",
                "--admin-token",
                "admin-secret",
                "--reason",
                "operator requested state change",
            ])
            .expect("valid signing rotation mutation command");
            assert!(matches!(
                parsed.command,
                Command::Controller(ControllerCommand {
                    command: ControllerSubcommand::SigningRotation { .. }
                })
            ));
        }

        let rollout = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "rollout-trust-bundle",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--previous-public-key-path",
            "/var/lib/fleet/controller/controller_public.key.bak",
            "--agent-id",
            "agent-1",
            "--json",
        ])
        .expect("valid signing rotation rollout command");
        assert!(matches!(
            rollout.command,
            Command::Controller(ControllerCommand {
                command: ControllerSubcommand::SigningRotation {
                    command: ControllerSigningRotationSubcommand::RolloutTrustBundle { .. }
                }
            })
        ));

        let retry = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "retry-trust-bundle",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--previous-public-key-path",
            "/var/lib/fleet/controller/controller_public.key.bak",
            "--agent-id",
            "agent-1",
            "--max-agent-count",
            "25",
            "--json",
        ])
        .expect("valid signing rotation trust bundle retry command");
        assert!(matches!(
            retry.command,
            Command::Controller(ControllerCommand {
                command: ControllerSubcommand::SigningRotation {
                    command: ControllerSigningRotationSubcommand::RetryTrustBundle { .. }
                }
            })
        ));

        let staged = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "staged-trust-bundle",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--previous-public-key-path",
            "/var/lib/fleet/controller/controller_public.key.bak",
            "--agent-id",
            "agent-1",
            "--batch-size",
            "10",
            "--max-failures",
            "1",
            "--ack-timeout-seconds",
            "30",
            "--json",
        ])
        .expect("valid signing rotation staged trust bundle command");
        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::SigningRotation { command },
        }) = staged.command
        else {
            panic!("expected signing rotation command");
        };
        let ControllerSigningRotationSubcommand::StagedTrustBundle {
            api,
            previous_public_key_path,
            agent_ids,
            batch_size,
            max_failures,
            ack_timeout_seconds,
            json,
        } = command
        else {
            panic!("expected staged trust bundle command");
        };
        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert_eq!(
            previous_public_key_path.as_deref(),
            Some(Path::new(
                "/var/lib/fleet/controller/controller_public.key.bak"
            ))
        );
        assert_eq!(agent_ids, ["agent-1"]);
        assert_eq!(batch_size, 10);
        assert_eq!(max_failures, 1);
        assert_eq!(ack_timeout_seconds, 30);
        assert!(json);

        let restart_action = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "restart-action",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--confirm-external-restart",
            "--reason",
            "operator approved service restart",
            "--json",
        ])
        .expect("valid signing rotation restart action command");
        assert!(matches!(
            restart_action.command,
            Command::Controller(ControllerCommand {
                command: ControllerSubcommand::SigningRotation {
                    command: ControllerSigningRotationSubcommand::RestartAction { .. }
                }
            })
        ));
    }

    #[test]
    fn parses_controller_signing_rotation_restart_plan_command() {
        let parsed = Cli::try_parse_from([
            "fleet",
            "controller",
            "signing-rotation",
            "restart-plan",
            "--controller-url",
            "https://fleet.example.com",
            "--admin-token",
            "admin-secret",
            "--json",
        ])
        .expect("valid signing rotation restart-plan command");

        let Command::Controller(ControllerCommand {
            command: ControllerSubcommand::SigningRotation { command },
        }) = parsed.command
        else {
            panic!("expected signing rotation command");
        };
        let ControllerSigningRotationSubcommand::RestartPlan { api, json } = command else {
            panic!("expected restart-plan command");
        };

        assert_eq!(
            api.controller_url.as_deref(),
            Some("https://fleet.example.com")
        );
        assert_eq!(api.admin_token.as_deref(), Some("admin-secret"));
        assert!(json);
    }

    #[test]
    fn controller_signing_rotation_status_renderer_omits_key_material() {
        let body = serde_json::json!({
            "controller_id": "default-controller",
            "persisted_record_present": true,
            "persisted_state": "dual_trust_active",
            "readiness": "dual_trust_active_agents_migrating",
            "active_signing_fingerprint_prefix": "new-fp-12345678",
            "selected_signing_fingerprint_prefix": "new-fp-12345678",
            "old_fingerprint_prefix": "old-fp-12345678",
            "new_fingerprint_prefix": "new-fp-12345678",
            "requested_at_ms": 1710000000000_u64,
            "validated_at_ms": 1710000001000_u64,
            "activated_at_ms": 1710000002000_u64,
            "old_key_verifies_until_ms": 1710003600000_u64,
            "retired_at_ms": null,
            "failed_at_ms": null,
            "bootstrap_guard": "active_matches_selected",
            "agent_trust_rollout": "agents_migrating",
            "controller_private_key_path": "controller_private.key",
            "controller_signing_public_key": "raw-public-key-body",
            "candidate_private_key": "private-key-secret",
            "tls_certificate_path": "tls/fullchain.pem",
            "task_payload_body": "{\"program\":\"uptime\"}"
        })
        .to_string();

        let lines = render_controller_signing_rotation_status_for_cli(&body)
            .expect("status response should render");
        let rendered = lines.join("\n");

        assert!(rendered.contains("controller_id=default-controller"));
        assert!(rendered.contains("state=dual_trust_active"));
        assert!(rendered.contains("readiness=dual_trust_active_agents_migrating"));
        assert!(rendered.contains("active_signing_fingerprint_prefix=new-fp-12345678"));
        assert!(rendered.contains("old_key_verifies_until_ms=1710003600000"));
        for forbidden in [
            "controller_private.key",
            "raw-public-key-body",
            "private-key-secret",
            "tls/fullchain.pem",
            "task_payload_body",
            "uptime",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "renderer must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn controller_signing_rotation_restart_plan_renderer_omits_key_material() {
        let body = serde_json::json!({
            "controller_id": "default-controller",
            "restart_required": true,
            "reload_supported": false,
            "recommended_action": "restart_controller_process",
            "readiness": "dual_trust_active_agents_migrating",
            "bootstrap_guard": "active_mismatch_selected",
            "agent_trust_rollout": "agents_migrating",
            "active_signing_fingerprint_prefix": "old-fp-12345678",
            "selected_signing_fingerprint_prefix": "new-fp-12345678",
            "blocked_reason": "active signer does not match selected signer",
            "verification_commands": [
                "fleet controller signing-rotation-status --controller-url <controller-url>",
                "fleet controller signing-rotation restart-plan --controller-url <controller-url>"
            ],
            "safety_notes": [
                "controller signing reload is not supported by this version",
                "restart the controller process through the service manager and verify status afterwards"
            ],
            "controller_private_key_path": "controller_private.key",
            "candidate_private_key": "private-key-secret",
            "tls_certificate_path": "tls/fullchain.pem",
            "admin_token": "admin-secret",
            "task_payload_body": "{\"program\":\"uptime\"}"
        })
        .to_string();

        let lines = render_controller_signing_rotation_restart_plan_for_cli(&body)
            .expect("restart plan response should render");
        let rendered = lines.join("\n");

        assert!(rendered.contains("controller_id=default-controller"));
        assert!(rendered.contains("restart_required=true"));
        assert!(rendered.contains("reload_supported=false"));
        assert!(rendered.contains("recommended_action=restart_controller_process"));
        assert!(rendered.contains("verification_command=fleet controller signing-rotation-status"));
        for forbidden in [
            "controller_private.key",
            "private-key-secret",
            "tls/fullchain.pem",
            "admin-secret",
            "task_payload_body",
            "uptime",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "renderer must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn controller_signing_rotation_restart_action_renderer_omits_key_material() {
        let body = serde_json::json!({
            "controller_id": "default-controller",
            "action": "external_service_manager_restart",
            "action_status": "audit_recorded_external_restart_required",
            "restart_required": true,
            "reload_supported": false,
            "readiness": "dual_trust_active_agents_migrating",
            "bootstrap_guard": "active_mismatch_selected",
            "active_signing_fingerprint_prefix": "old-fp-12345678",
            "selected_signing_fingerprint_prefix": "new-fp-12345678",
            "service_command": "fleet controller restart-service --dry-run",
            "verification_commands": [
                "fleet controller signing-rotation restart-plan --controller-url <controller-url>"
            ],
            "safety_notes": [
                "restart is executed outside the HTTP handler"
            ],
            "controller_private_key_path": "controller_private.key",
            "candidate_private_key": "private-key-secret",
            "tls_certificate_path": "tls/fullchain.pem",
            "admin_token": "admin-secret",
            "task_payload_body": "{\"program\":\"uptime\"}"
        })
        .to_string();

        let lines = render_controller_signing_rotation_restart_action_for_cli(&body)
            .expect("restart action response should render");
        let rendered = lines.join("\n");

        assert!(rendered.contains("controller_id=default-controller"));
        assert!(rendered.contains("action=external_service_manager_restart"));
        assert!(rendered.contains("action_status=audit_recorded_external_restart_required"));
        assert!(rendered.contains("service_command=fleet controller restart-service --dry-run"));
        for forbidden in [
            "controller_private.key",
            "private-key-secret",
            "tls/fullchain.pem",
            "admin-secret",
            "task_payload_body",
            "uptime",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "renderer must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn controller_signing_trust_bundle_rollout_renderer_omits_key_material() {
        let body = serde_json::json!({
            "controller_id": "default-controller",
            "persisted_state": "dual_trust_active",
            "attempted_count": 2,
            "updated_count": 1,
            "skipped_count": 1,
            "failed_count": 0,
            "entries_count": 2,
            "current_fingerprint_prefix": "new-fp-12345678",
            "previous_fingerprint_prefix": "old-fp-12345678",
            "agent_results": [
                {"agent_id":"agent-1","status":"sent"},
                {"agent_id":"agent-2","status":"skipped_not_connected"}
            ],
            "previous_public_key_path": "old_controller_public.key",
            "current_public_key": "new-public-key-body",
            "previous_public_key": "old-public-key-body",
            "private_key": "private-key-secret",
            "admin_token": "admin-secret"
        })
        .to_string();

        let lines = render_controller_signing_trust_bundle_rollout_for_cli(&body)
            .expect("rollout response should render");
        let rendered = lines.join("\n");

        assert!(rendered.contains("controller_id=default-controller"));
        assert!(rendered.contains("updated_count=1"));
        assert!(rendered.contains("agent_id=agent-1\tstatus=sent"));
        for forbidden in [
            "old_controller_public.key",
            "new-public-key-body",
            "old-public-key-body",
            "private-key-secret",
            "admin-secret",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "renderer must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn controller_signing_trust_bundle_staged_rollout_renderer_omits_key_material() {
        let body = serde_json::json!({
            "controller_id": "default-controller",
            "persisted_state": "dual_trust_active",
            "rollout_state": "waiting_for_ack",
            "target_count": 3,
            "planned_count": 1,
            "attempted_count": 1,
            "updated_count": 1,
            "skipped_count": 1,
            "failed_count": 0,
            "already_current_count": 1,
            "unavailable_count": 0,
            "pending_count": 1,
            "entries_count": 2,
            "current_fingerprint_prefix": "new-fp-12345678",
            "previous_fingerprint_prefix": "old-fp-12345678",
            "agent_results": [
                {"agent_id":"agent-2","status":"sent"}
            ],
            "previous_public_key_path": "old_controller_public.key",
            "current_public_key": "new-public-key-body",
            "previous_public_key": "old-public-key-body",
            "private_key": "private-key-secret",
            "admin_token": "admin-secret",
            "task_payload_body": "{\"program\":\"uptime\"}"
        })
        .to_string();

        let lines = render_controller_signing_trust_bundle_staged_rollout_for_cli(&body)
            .expect("staged rollout response should render");
        let rendered = lines.join("\n");

        assert!(rendered.contains("controller_id=default-controller"));
        assert!(rendered.contains("rollout_state=waiting_for_ack"));
        assert!(rendered.contains("target_count=3"));
        assert!(rendered.contains("planned_count=1"));
        assert!(rendered.contains("already_current_count=1"));
        assert!(rendered.contains("pending_count=1"));
        assert!(rendered.contains("agent_id=agent-2\tstatus=sent"));
        for forbidden in [
            "old_controller_public.key",
            "new-public-key-body",
            "old-public-key-body",
            "private-key-secret",
            "admin-secret",
            "task_payload_body",
            "uptime",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "renderer must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn controller_signing_staged_trust_bundle_request_uses_explicit_body() {
        let body = controller_signing_staged_trust_bundle_request_body(
            Some(PathBuf::from(
                "/var/lib/fleet/controller/controller_public.key.bak",
            )),
            vec!["agent-1".to_owned(), "agent-2".to_owned()],
            10,
            1,
            30,
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            CONTROLLER_SIGNING_STAGED_TRUST_BUNDLE_PATH,
            "/api/controller/signing-rotation/rollout-trust-bundle/staged"
        );
        assert_eq!(
            json["previous_public_key_path"],
            "/var/lib/fleet/controller/controller_public.key.bak"
        );
        assert_eq!(json["agent_ids"], serde_json::json!(["agent-1", "agent-2"]));
        assert_eq!(json["batch_size"], 10);
        assert_eq!(json["max_failures"], 1);
        assert_eq!(json["ack_timeout_seconds"], 30);
        assert!(json.get("private_key").is_none());
        assert!(json.get("admin_token").is_none());
    }

    #[test]
    fn parses_remediation_cli_commands() {
        let remediations = Cli::try_parse_from([
            "fleet",
            "remediations",
            "list",
            "--agent-id",
            "agent-1",
            "--policy-id",
            "nginx-running",
            "--limit",
            "10",
        ])
        .expect("valid remediations list command");
        let Command::Remediations(command) = remediations.command else {
            panic!("expected remediations command");
        };
        let RemediationsSubcommand::List {
            agent_id,
            policy_id,
            limit,
            ..
        } = command.command
        else {
            panic!("expected remediation list command");
        };
        assert_eq!(agent_id.as_deref(), Some("agent-1"));
        assert_eq!(policy_id.as_deref(), Some("nginx-running"));
        assert_eq!(limit, 10);

        let remediation_approve = Cli::try_parse_from([
            "fleet",
            "remediations",
            "approve",
            "rem-1",
            "--approval-id",
            "approval-1",
            "--job-id",
            "job-1",
            "--runbook",
            "runbooks/remediate.yml",
        ])
        .expect("valid remediations approve command");
        assert!(matches!(
            remediation_approve.command,
            Command::Remediations(RemediationsCommand {
                command: RemediationsSubcommand::Approve { .. }
            })
        ));
    }

    #[test]
    fn cli_profile_save_read_roundtrip_uses_secure_permissions() {
        let dir = unique_test_dir("cli-profile");
        let path = dir.join("profile.json");
        let profile = CliProfile {
            controller_url: "https://fleet.example.com".to_owned(),
            admin_token: "admin-secret".to_owned(),
            tls_ca_cert: None,
        };

        save_cli_profile(&path, &profile).unwrap();
        let loaded = read_cli_profile(&path).unwrap();

        assert_eq!(loaded, profile);
        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn cli_profile_rejects_insecure_permissions() {
        let dir = unique_test_dir("cli-profile-insecure");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.json");
        fs::write(
            &path,
            r#"{"controller_url":"https://fleet.example.com","admin_token":"admin-secret"}"#,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(read_cli_profile(&path), Err(CliError::Http(_))));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn protected_api_resolves_profile_and_allows_explicit_override() {
        let dir = unique_test_dir("cli-profile-resolve");
        let path = dir.join("profile.json");
        save_cli_profile(
            &path,
            &CliProfile {
                controller_url: "https://profile.example.com".to_owned(),
                admin_token: "profile-token".to_owned(),
                tls_ca_cert: None,
            },
        )
        .unwrap();

        let from_profile = resolve_protected_api(&ProtectedApiArgs {
            controller_url: None,
            admin_token: None,
            profile_path: path.clone(),
        })
        .unwrap();
        assert_eq!(from_profile.controller_url, "https://profile.example.com");
        assert_eq!(from_profile.admin_token, "profile-token");

        let explicit = resolve_protected_api(&ProtectedApiArgs {
            controller_url: Some("https://explicit.example.com".to_owned()),
            admin_token: Some("explicit-token".to_owned()),
            profile_path: dir.join("missing.json"),
        })
        .unwrap();
        assert_eq!(explicit.controller_url, "https://explicit.example.com");
        assert_eq!(explicit.admin_token, "explicit-token");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn protected_api_client_sends_profile_bearer_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            ready_sender.send(()).unwrap();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = String::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = match stream.read(&mut buffer) {
                        Ok(read) => read,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                        Err(error) => panic!("mock server read failed: {error}"),
                    };
                    if read == 0 {
                        break;
                    }
                    request.push_str(&String::from_utf8_lossy(&buffer[..read]));
                    if request.contains("\r\n\r\n") {
                        break;
                    }
                }
                if request.contains("GET /api/agents HTTP/1.1") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                    sender.send(request).unwrap();
                    return;
                }
            }
            panic!("mock server did not receive protected API request");
        });
        let dir = unique_test_dir("cli-profile-http");
        let path = dir.join("profile.json");
        save_cli_profile(
            &path,
            &CliProfile {
                controller_url: format!("http://127.0.0.1:{port}"),
                admin_token: "profile-token".to_owned(),
                tls_ca_cert: None,
            },
        )
        .unwrap();
        ready_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

        let client = resolve_protected_api(&ProtectedApiArgs {
            controller_url: None,
            admin_token: None,
            profile_path: path.clone(),
        })
        .unwrap();
        let mut last_error = None;
        let mut body = None;
        for _ in 0..3 {
            match client.get("/api/agents") {
                Ok(response) => {
                    body = Some(response);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
        let body = body.unwrap_or_else(|| panic!("protected API request failed: {last_error:?}"));
        let request = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();

        assert_eq!(body, "{}");
        assert!(request.contains("GET /api/agents HTTP/1.1"));
        assert!(request.contains("authorization: Bearer profile-token"));
        assert!(!request.contains("admin-secret"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn api_error_rendering_distinguishes_common_statuses() {
        assert_eq!(
            render_http_status_error(401),
            "unauthorized: credential is missing, invalid, expired or revoked; create a personal token in Settings > My account and run fleet login again"
        );
        assert_eq!(
            render_http_status_error(403),
            "forbidden: your account lacks the required permission"
        );
        assert_eq!(
            render_http_status_error(404),
            "not found: requested resource does not exist"
        );
        assert_eq!(
            render_http_status_error(409),
            "conflict: request conflicts with current state"
        );
    }

    #[test]
    fn selector_preview_renderer_uses_controller_counts() {
        let body = serde_json::json!({
            "matched_count": 2,
            "selected_count": 1,
            "disabled_count": 1,
            "offline_count": 0,
            "warnings": [
                {"code": "disabled_agents_excluded", "message": "1 disabled agent excluded"}
            ],
            "agents": [
                {
                    "agent_id": "agent-1",
                    "name": "web-01",
                    "status": "online",
                    "labels": [],
                    "selected_for_dispatch": true
                }
            ]
        })
        .to_string();

        let lines = render_selector_preview_for_cli(&body).unwrap();

        assert!(lines.contains(&"matched_count=2".to_owned()));
        assert!(lines.contains(&"selected_count=1".to_owned()));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("disabled_agents_excluded"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("agent=agent-1") && line.contains("selected=true"))
        );
    }

    #[test]
    fn audit_export_path_and_jsonl_renderer_use_controller_page() {
        assert_eq!(
            audit_export_path(Some("security"), 10, Some("3:1")),
            "/api/audit/export?category=security&limit=10&before=3%3A1"
        );
        let body = serde_json::json!({
            "items": [
                {
                    "category": "security",
                    "action": "invalid_signature",
                    "actor": "system",
                    "target": "agent-1",
                    "value_kind": "secret_ref",
                    "value": "secret_ref",
                    "occurred_at_ms": 3000,
                    "cursor": "3:2"
                }
            ],
            "next_cursor": null
        })
        .to_string();

        let lines = render_audit_export_jsonl(&body).unwrap();

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"category\":\"security\""));
        assert!(lines[0].contains("\"value\":\"secret_ref\""));
        assert!(!lines[0].contains("raw-secret"));
        assert!(serde_json::from_str::<serde_json::Value>(&lines[0]).is_ok());
    }

    #[test]
    fn remediation_cli_paths_and_renderer_hide_payload_bodies() {
        assert_eq!(
            remediations_list_path(Some("agent/1"), Some("nginx running"), 10),
            "/api/remediations?agent_id=agent%2F1&policy_id=nginx%20running&limit=10"
        );
        let body = serde_json::json!([
            {
                "id": "rem-1",
                "policy_id": "nginx-running",
                "policy_name": "nginx-running",
                "agent_id": "agent-1",
                "runbook_ref": "runbooks/remediate.yml",
                "status": "proposed",
                "job_id": null,
                "lifecycle_source": "persisted",
                "verification_assignment_status": "failed",
                "legacy_state": "legacy_unverified",
                "runbook_document": "kind: Runbook\n# secret-value-should-not-leak",
                "command_output": "secret-value-should-not-leak",
                "rendered_body": "secret-value-should-not-leak"
            }
        ])
        .to_string();

        let lines = render_remediation_api_for_cli(&body).unwrap();

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("remediation_id=rem-1"));
        assert!(lines[0].contains("policy_id=nginx-running"));
        assert!(lines[0].contains("lifecycle_source=persisted"));
        assert!(lines[0].contains("verification_assignment_status=failed"));
        assert!(lines[0].contains("legacy_state=legacy_unverified"));
        assert!(!lines.join("\n").contains("kind: Runbook"));
        assert!(!lines.join("\n").contains("runbook_document"));
        assert!(!lines.join("\n").contains("secret-value-should-not-leak"));
    }

    #[test]
    fn remediation_approve_body_contains_runbook_only_in_request_payload() {
        let body = build_remediation_approve_body(
            "approval-1",
            "job-1",
            "kind: Runbook\n# secret-value-should-not-leak",
            30,
            300,
            Some("nonce-1"),
            "approved",
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json["approval_id"], "approval-1");
        assert_eq!(json["job_id"], "job-1");
        assert_eq!(
            json["runbook_document"],
            "kind: Runbook\n# secret-value-should-not-leak"
        );
        assert_eq!(json["nonce_prefix"], "nonce-1");
    }

    #[test]
    fn remote_run_body_uses_selector_and_omits_admin_token() {
        let command = RunCommand {
            selector: Some("role=web".to_owned()),
            confirm_risk: true,
            controller_url: Some("http://127.0.0.1:7700".to_owned()),
            admin_token: Some("admin-secret".to_owned()),
            profile_path: PathBuf::from(DEFAULT_CLI_PROFILE_PATH),
            remote: true,
            job_id: Some("job-cli-1".to_owned()),
            timeout_seconds: 45,
            command: vec!["uptime".to_owned(), "-a".to_owned()],
        };

        let body =
            remote_run_request_body(&command, "job-cli-1", "uptime", &["-a".to_owned()]).unwrap();

        assert!(body.contains("\"selector\":\"role=web\""));
        assert!(body.contains("\"timeout_seconds\":45"));
        assert!(body.contains("\"expires_in_seconds\":300"));
        assert!(!body.contains("admin-secret"));
    }

    #[test]
    fn remote_run_pending_approval_response_does_not_poll_output() {
        let response = serde_json::json!({
            "job_id": "job-cli-1",
            "target_count": 1,
            "assignment_count": 1,
            "status": "pending_approval",
            "approval_request_id": "approval-1"
        });

        assert_eq!(remote_run_response_status(&response), "pending_approval");
        assert_eq!(
            remote_run_response_approval_request_id(&response),
            Some("approval-1")
        );
        assert!(remote_run_response_needs_approval(&response));
    }

    #[test]
    fn run_without_selector_uses_local_context() {
        let cli = Cli::try_parse_from(["fleet", "run", "--confirm-risk", "uptime"])
            .expect("valid local run command");

        let Command::Run(command) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(command.selector, None);
        assert_eq!(run_context_label(command.selector.as_deref()), "local");
        assert_eq!(
            run_context_label(Some("role=web")),
            "selector:role=web".to_owned()
        );
    }

    #[test]
    fn parses_apply_command() {
        let cli = Cli::try_parse_from(["fleet", "apply", "examples/runbooks/nginx-basic.yml"])
            .expect("valid command");

        let Command::Apply(command) = cli.command else {
            panic!("expected apply command");
        };

        assert_eq!(
            command.file,
            PathBuf::from("examples/runbooks/nginx-basic.yml")
        );
    }

    #[test]
    fn parses_retention_cleanup_command() {
        let cli = Cli::try_parse_from([
            "fleet",
            "retention",
            "cleanup",
            "--data-dir",
            "/tmp/fleet",
            "--older-than-days",
            "7",
            "--dry-run",
        ])
        .expect("valid command");

        let Command::Retention(RetentionCommand {
            command:
                RetentionSubcommand::Cleanup {
                    data_dir,
                    older_than_days,
                    dry_run,
                },
        }) = cli.command
        else {
            panic!("expected retention cleanup command");
        };

        assert_eq!(data_dir, PathBuf::from("/tmp/fleet"));
        assert_eq!(older_than_days, 7);
        assert!(dry_run);
    }

    #[test]
    fn retention_cleanup_execution_writes_audit_event() {
        let data_dir = unique_demo_dir();
        fs::create_dir_all(controller_dir(&data_dir)).unwrap();
        fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();

        let cli = Cli::try_parse_from([
            "fleet",
            "retention",
            "cleanup",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--older-than-days",
            "1",
        ])
        .expect("valid command");

        execute(cli).unwrap();

        let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
        let audits = store
            .list_audit_events_by_category(fleet_domain::AuditCategory::Security, 10)
            .unwrap();
        assert!(
            audits
                .iter()
                .any(|event| event.action == "retention_cleanup")
        );

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn controller_backup_creates_archive_with_metadata() {
        let data_dir = initialized_controller_backup_fixture("backup-metadata");
        let output = unique_test_dir("backup-output").join("controller-backup.json");

        execute_controller_backup(&data_dir, &output).unwrap();

        let archive = read_backup_archive(&output).unwrap();
        validate_backup_archive(&archive).unwrap();
        assert_eq!(archive.format, CONTROLLER_BACKUP_FORMAT);
        assert_eq!(archive.format_version, CONTROLLER_BACKUP_FORMAT_VERSION);
        assert_eq!(archive.schema_version, fleet_store::CURRENT_SCHEMA_VERSION);
        assert_eq!(archive.sqlite_integrity_check, "ok");
        assert_eq!(archive.source_data_dir, data_dir.display().to_string());
        assert!(archive.created_at_ms > 0);
        assert!(
            archive
                .files
                .iter()
                .any(|file| file.path == "controller/fleet.db")
        );
        assert!(
            archive
                .files
                .iter()
                .any(|file| file.path == "controller/controller_private.key")
        );

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn controller_restore_dry_run_does_not_write() {
        let data_dir = initialized_controller_backup_fixture("restore-dry-run-source");
        let output = unique_test_dir("restore-dry-run-output").join("controller-backup.json");
        let restore_dir = unique_test_dir("restore-dry-run-target");
        execute_controller_backup(&data_dir, &output).unwrap();

        execute_controller_restore(&restore_dir, &output, true, false).unwrap();

        assert!(!controller_dir(&restore_dir).exists());

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(restore_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn controller_backup_restore_roundtrip_restores_database_and_keys() {
        use fleet_application::admin_identity::AdminIdentityRead;
        let data_dir = initialized_controller_backup_fixture("restore-roundtrip-source");
        let output = unique_test_dir("restore-roundtrip-output").join("controller-backup.json");
        let restore_dir = unique_test_dir("restore-roundtrip-target");
        let source = fleet_domain::CatalogSource::new(
            fleet_domain::CatalogSourceId::new("public-catalog").unwrap(),
            fleet_domain::PublicCatalogUrl::new("https://example.com/catalog.git").unwrap(),
            fleet_domain::CatalogReference::new("main").unwrap(),
        );
        let commit = fleet_domain::CatalogCommitId::new("a".repeat(40)).unwrap();
        let mut revision = source.begin_sync(commit.clone());
        revision.begin_validation().unwrap();
        revision.mark_ready(1).unwrap();
        let document = fleet_domain::CatalogDocument::new(
            source.id().clone(),
            commit.clone(),
            fleet_domain::CatalogDocumentKind::Runbook,
            "runbooks/nginx.yaml",
            "c".repeat(64),
        )
        .unwrap();
        {
            use fleet_application::CatalogRepository;

            let mut source_store =
                fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
            source_store.save_catalog_source(source.clone()).unwrap();
            source_store
                .save_catalog_revision(revision.clone())
                .unwrap();
            let mut active_source = source.clone();
            active_source.activate(&revision).unwrap();
            source_store
                .activate_catalog_revision(active_source, &revision)
                .unwrap();
            source_store
                .save_catalog_document(
                    document.clone(),
                    "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: nginx\n"
                        .to_owned(),
                )
                .unwrap();
        }
        let source_delivery_identity = {
            let source_store =
                fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
            fleet_application::ControllerDeliveryIdentityRepository::controller_delivery_identity(
                &source_store,
            )
            .unwrap()
        };
        let before_auth = fleet_store::SqliteStore::open(controller_db_path(&data_dir))
            .unwrap()
            .auth_state()
            .unwrap();
        assert!(
            fleet_store::SqliteStore::open(controller_db_path(&data_dir))
                .unwrap()
                .verify_admin_token_hash("backup-admin-hash")
                .unwrap()
        );
        execute_controller_backup(&data_dir, &output).unwrap();

        execute_controller_restore(&restore_dir, &output, false, false).unwrap();

        let restored_store =
            fleet_store::SqliteStore::open(controller_db_path(&restore_dir)).unwrap();
        let restored_delivery_identity =
            fleet_application::ControllerDeliveryIdentityRepository::controller_delivery_identity(
                &restored_store,
            )
            .unwrap();
        assert_eq!(
            restored_delivery_identity.namespace,
            source_delivery_identity.namespace
        );
        assert_ne!(
            restored_delivery_identity.store_epoch,
            source_delivery_identity.store_epoch
        );
        assert!(
            !restored_store
                .verify_admin_token_hash("backup-admin-hash")
                .unwrap()
        );
        let restored_auth = restored_store.auth_state().unwrap();
        assert_eq!(
            restored_auth.mode,
            fleet_domain::AdminAuthMode::LocalSetupRequired
        );
        assert_ne!(restored_auth.epoch, before_auth.epoch);
        assert!(
            controller_dir(&restore_dir)
                .join("controller_private.key")
                .is_file()
        );
        assert!(
            controller_dir(&restore_dir)
                .join("controller_public.key")
                .is_file()
        );
        {
            use fleet_application::CatalogRepository;

            assert_eq!(
                restored_store
                    .find_catalog_source(source.id())
                    .unwrap()
                    .expect("restored catalog source")
                    .active_revision(),
                Some(&commit)
            );
            assert_eq!(
                restored_store
                    .find_catalog_document(source.id(), &commit, document.path())
                    .unwrap()
                    .expect("restored catalog document")
                    .body,
                "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: nginx\n"
            );
        }

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(restore_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn controller_restore_refuses_overwrite_without_force() {
        let data_dir = initialized_controller_backup_fixture("restore-overwrite-source");
        let output = unique_test_dir("restore-overwrite-output").join("controller-backup.json");
        let restore_dir = initialized_controller_backup_fixture("restore-overwrite-target");
        execute_controller_backup(&data_dir, &output).unwrap();

        let result = execute_controller_restore(&restore_dir, &output, false, false);

        assert!(
            matches!(result, Err(CliError::Http(message)) if message.contains("refusing to overwrite"))
        );

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(restore_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn controller_restore_refuses_incompatible_schema_version() {
        let data_dir = initialized_controller_backup_fixture("restore-schema-source");
        let output = unique_test_dir("restore-schema-output").join("controller-backup.json");
        let restore_dir = unique_test_dir("restore-schema-target");
        execute_controller_backup(&data_dir, &output).unwrap();
        let mut archive = read_backup_archive(&output).unwrap();
        archive.schema_version = fleet_store::CURRENT_SCHEMA_VERSION + 1;
        fs::remove_file(&output).unwrap(); // Replace only this owned, intentionally mutated fixture.
        write_backup_archive(&output, &archive).unwrap();

        let result = execute_controller_restore(&restore_dir, &output, true, false);

        assert!(
            matches!(result, Err(CliError::Http(message)) if message.contains("newer than this binary supports"))
        );

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(restore_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn controller_restore_rejects_corrupted_sqlite_archive() {
        let data_dir = initialized_controller_backup_fixture("restore-corrupt-source");
        let output = unique_test_dir("restore-corrupt-output").join("controller-backup.json");
        let restore_dir = unique_test_dir("restore-corrupt-target");
        execute_controller_backup(&data_dir, &output).unwrap();
        let mut archive = read_backup_archive(&output).unwrap();
        let corrupt = b"not a sqlite database";
        let db = archive
            .files
            .iter_mut()
            .find(|file| file.path == "controller/fleet.db")
            .expect("backup must include db");
        db.content_hex = hex_encode(corrupt);
        db.size_bytes = corrupt.len() as u64;
        db.sha256 = sha256_hex(corrupt);
        fs::remove_file(&output).unwrap(); // Replace only this owned, intentionally mutated fixture.
        write_backup_archive(&output, &archive).unwrap();

        let result = execute_controller_restore(&restore_dir, &output, false, false);

        assert!(matches!(
            result,
            Err(CliError::Store(_)) | Err(CliError::Http(_))
        ));
        assert!(!controller_dir(&restore_dir).exists());

        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(restore_dir);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn parses_demo_command() {
        let cli = Cli::try_parse_from(["fleet", "demo", "--keep-temp", "--port", "17700"])
            .expect("valid command");

        let Command::Demo(command) = cli.command else {
            panic!("expected demo command");
        };

        assert!(command.keep_temp);
        assert_eq!(command.port, Some(17700));
    }

    #[test]
    fn demo_rejects_unavailable_port() {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let port = listener.local_addr().unwrap().port();

        assert!(matches!(
            ensure_loopback_port_available(port),
            Err(CliError::Http(_))
        ));
    }

    #[test]
    fn parses_linux_meminfo_fixture() {
        let body = "MemTotal:       16384256 kB\nMemAvailable:   8123456 kB\n";

        assert_eq!(linux_meminfo_kb(body, "MemTotal"), Some(16_384_256));
        assert_eq!(linux_meminfo_kb(body, "MemAvailable"), Some(8_123_456));
        assert_eq!(linux_meminfo_kb(body, "SwapTotal"), None);
    }

    #[test]
    fn parses_linux_network_interfaces_fixture() {
        let body = "Inter-| Receive\n face |bytes\n    lo: 1 0 0\n  eth0: 2 0 0\n";

        assert_eq!(
            linux_network_interfaces(body),
            vec!["lo".to_owned(), "eth0".to_owned()]
        );
    }

    #[test]
    fn parses_df_root_usage_fixture() {
        let body = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 102400 51200 51200 50% /\n";

        assert_eq!(
            parse_df_root_usage(body),
            Some(DiskUsage {
                filesystem: "/dev/root".to_owned(),
                total_kb: 102_400,
                used_kb: 51_200,
                available_kb: 51_200,
                used_percent: 50,
            })
        );
    }

    #[test]
    fn missing_df_root_usage_is_graceful() {
        let body = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 102400 51200 51200 50% /data\n";

        assert_eq!(parse_df_root_usage(body), None);
    }

    #[test]
    fn parses_linux_mounts_without_exposing_options() {
        let body = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/disk\\040with\\040space /mnt/space ext4 ro,nosuid 0 0
server:/export /mnt/nfs nfs4 rw,vers=4.2 0 0
";

        let mounts = parse_linux_mounts(body);

        assert_eq!(
            mounts,
            vec![
                MountFact {
                    source: "/dev/sda1".to_owned(),
                    mount_point: "/".to_owned(),
                    fs_type: "ext4".to_owned(),
                    read_only: false,
                },
                MountFact {
                    source: "/dev/disk with space".to_owned(),
                    mount_point: "/mnt/space".to_owned(),
                    fs_type: "ext4".to_owned(),
                    read_only: true,
                },
                MountFact {
                    source: "server:/export".to_owned(),
                    mount_point: "/mnt/nfs".to_owned(),
                    fs_type: "nfs4".to_owned(),
                    read_only: false,
                },
            ]
        );
    }

    #[test]
    fn collects_linux_block_device_inventory_from_sysfs_fixture() {
        let dir = unique_test_dir("block-devices");
        fs::create_dir_all(dir.join("sda").join("queue")).unwrap();
        fs::write(dir.join("sda").join("size"), "2097152\n").unwrap();
        fs::write(dir.join("sda").join("removable"), "0\n").unwrap();
        fs::write(dir.join("sda").join("queue").join("rotational"), "1\n").unwrap();
        fs::create_dir_all(dir.join("sda").join("sda1")).unwrap();
        fs::write(dir.join("sda").join("sda1").join("size"), "1048576\n").unwrap();
        fs::create_dir_all(dir.join("nvme0n1").join("queue")).unwrap();
        fs::write(dir.join("nvme0n1").join("size"), "4194304\n").unwrap();
        fs::write(dir.join("nvme0n1").join("removable"), "0\n").unwrap();
        fs::write(dir.join("nvme0n1").join("queue").join("rotational"), "0\n").unwrap();
        fs::create_dir_all(dir.join("nvme0n1").join("nvme0n1p1")).unwrap();
        fs::write(
            dir.join("nvme0n1").join("nvme0n1p1").join("size"),
            "2097152\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("loop0")).unwrap();

        let devices = collect_linux_block_devices(&dir).unwrap();

        assert_eq!(
            devices,
            vec![
                BlockDeviceFact {
                    name: "nvme0n1".to_owned(),
                    kind: "disk".to_owned(),
                    size_kb: Some(2_097_152),
                    removable: Some(false),
                    rotational: Some(false),
                    partitions: vec![BlockPartitionFact {
                        name: "nvme0n1p1".to_owned(),
                        size_kb: Some(1_048_576),
                    }],
                },
                BlockDeviceFact {
                    name: "sda".to_owned(),
                    kind: "disk".to_owned(),
                    size_kb: Some(1_048_576),
                    removable: Some(false),
                    rotational: Some(true),
                    partitions: vec![BlockPartitionFact {
                        name: "sda1".to_owned(),
                        size_kb: Some(524_288),
                    }],
                },
            ]
        );
    }

    #[test]
    fn parses_systemd_failed_service_summary_fixture() {
        let body = "\
UNIT LOAD ACTIVE SUB DESCRIPTION
nginx.service loaded failed failed A high performance web server
postgresql.service loaded failed failed PostgreSQL database server

2 loaded units listed.
";

        assert_eq!(
            parse_systemd_failed_services(body),
            vec!["nginx.service".to_owned(), "postgresql.service".to_owned()]
        );
    }

    #[test]
    fn missing_systemd_service_status_is_graceful() {
        assert_eq!(
            systemd_service_summary_unavailable(),
            ServiceSummary {
                status_available: false,
                failed_units_count: None,
                failed_units: Vec::new(),
            }
        );
    }

    #[test]
    fn collect_local_facts_is_structured_and_secret_free() {
        let facts = collect_local_facts();

        assert!(facts.get("os").is_some());
        assert!(
            facts
                .get("system_time_ms")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
        assert!(
            facts
                .get("cpu")
                .and_then(|value| value.get("logical_count"))
                .is_some()
        );
        assert!(facts.get("network").is_some());
        let memory = facts
            .get("memory")
            .expect("facts must include memory inventory");
        assert!(
            memory.get("total_kb").is_some(),
            "facts must include total memory capacity",
        );
        assert!(
            memory.get("module_count_known").is_some(),
            "facts must expose whether memory module count is known",
        );
        assert!(
            memory.get("available_kb").is_none(),
            "facts must not include current memory availability",
        );
        assert!(
            memory.get("used_kb").is_none(),
            "facts must not include current memory usage",
        );
        assert!(
            memory.get("used_percent").is_none(),
            "facts must not include current memory usage percent",
        );
        let disk = facts
            .get("disk")
            .expect("facts must include disk inventory");
        assert!(
            disk.get("root_capacity_known").is_some(),
            "facts must expose whether root disk capacity is known",
        );
        assert!(
            disk.get("device_inventory_known").is_some(),
            "facts must expose whether disk device inventory is known",
        );
        assert!(
            disk.get("device_count").is_some(),
            "facts must include disk device count",
        );
        assert!(
            disk.get("devices")
                .and_then(serde_json::Value::as_array)
                .is_some(),
            "facts must include disk device inventory",
        );
        assert!(
            disk.get("mount_inventory_known").is_some(),
            "facts must expose whether mount inventory is known",
        );
        assert!(
            disk.get("mount_count").is_some(),
            "facts must include mount count",
        );
        assert!(
            disk.get("mounts")
                .and_then(serde_json::Value::as_array)
                .is_some(),
            "facts must include mount layout",
        );
        assert!(
            disk.get("root_total_kb").is_some(),
            "facts must include root disk total capacity",
        );
        assert!(
            disk.get("used_kb").is_none(),
            "facts must not include current disk usage",
        );
        assert!(
            disk.get("available_kb").is_none(),
            "facts must not include current disk availability",
        );
        assert!(
            disk.get("used_percent").is_none(),
            "facts must not include current disk usage percent",
        );
        assert!(
            facts
                .get("degraded")
                .and_then(|value| value.get("status"))
                .is_some()
        );
        let body = facts.to_string();
        assert!(!body.contains("token="));
        assert!(!body.contains("secret="));
    }

    #[test]
    fn collect_local_metrics_is_structured_and_secret_free() {
        let metrics = collect_local_metrics();

        assert!(
            metrics
                .get("system_time_ms")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
        assert!(
            metrics
                .get("cpu")
                .and_then(|value| value.get("logical_count"))
                .is_some()
        );
        assert!(
            metrics
                .get("cpu")
                .and_then(|value| value.get("usage_percent"))
                .is_some(),
            "metrics must include current CPU usage percent",
        );
        let memory = metrics
            .get("memory")
            .expect("metrics must include memory usage");
        assert!(memory.get("usage_available").is_some());
        assert!(memory.get("used_kb").is_some());
        assert!(memory.get("available_kb").is_some());
        assert!(memory.get("used_percent").is_some());
        assert!(metrics.get("process").is_some());
        let disk = metrics
            .get("disk")
            .expect("metrics must include disk usage");
        assert!(disk.get("usage_available").is_some());
        assert!(disk.get("used_kb").is_some());
        assert!(disk.get("available_kb").is_some());
        assert!(disk.get("used_percent").is_some());
        assert!(
            metrics
                .get("service")
                .and_then(|value| value.get("status_available"))
                .is_some()
        );
        let body = metrics.to_string();
        assert!(!body.contains("token="));
        assert!(!body.contains("secret="));
    }

    #[test]
    fn safe_only_runbook_does_not_require_package_manager() {
        let runbook = fleet_domain::parse_runbook_document(
            r#"
apiVersion: fleet.sponzey.dev/v1alpha1
kind: Runbook
name: safe-only
selector: role=web
steps:
  - id: http
    port.check:
      host: 127.0.0.1
      port: 7700
"#,
        )
        .unwrap();

        assert_eq!(
            local_runbook_package_manager(&runbook),
            Ok(fleet_runner::LinuxPackageManager::Apt)
        );
    }

    #[test]
    fn runbook_snapshot_uses_agent_collectors_with_runbook_source() {
        let facts = collect_runbook_snapshot(&fleet_runner::SnapshotSpec {
            kind: fleet_runner::SnapshotKind::Facts,
        })
        .unwrap();
        let metrics = collect_runbook_snapshot(&fleet_runner::SnapshotSpec {
            kind: fleet_runner::SnapshotKind::Metrics,
        })
        .unwrap();
        let facts_body: serde_json::Value = serde_json::from_str(&facts.body).unwrap();
        let metrics_body: serde_json::Value = serde_json::from_str(&metrics.body).unwrap();

        assert_eq!(facts_body["source"], "runbook");
        assert_eq!(metrics_body["source"], "runbook");
        assert!(facts_body.get("os").is_some());
        assert!(metrics_body.get("cpu").is_some());
    }

    #[test]
    fn memory_usage_from_meminfo_calculates_current_usage() {
        let usage = memory_usage_from_meminfo(
            "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\n",
        )
        .unwrap();

        assert_eq!(
            usage,
            MemoryUsage {
                total_kb: 1000,
                used_kb: 750,
                available_kb: 250,
                used_percent: 75,
            }
        );
    }

    #[test]
    fn cpu_usage_percent_uses_proc_stat_delta() {
        let first = parse_linux_cpu_sample("cpu  100 0 50 850 0 0 0 0 0 0\n").unwrap();
        let second = parse_linux_cpu_sample("cpu  130 0 70 900 0 0 0 0 0 0\n").unwrap();

        assert_eq!(first.total, 1000);
        assert_eq!(second.total, 1100);
        assert_eq!(cpu_usage_percent_between(first, second), Some(50.0));
    }

    #[test]
    fn rejects_invalid_command() {
        let error = Cli::try_parse_from(["fleet", "unknown"]).expect_err("invalid command");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn help_includes_mvp_commands() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();

        for expected in [
            "controller",
            "agent",
            "agents",
            "enroll-token",
            "run",
            "facts",
            "metrics",
            "logs",
            "drift",
            "apply",
            "retention",
            "demo",
        ] {
            assert!(help.contains(expected), "missing help entry: {expected}");
        }
    }

    #[test]
    fn version_flag_uses_package_version() {
        let command = Cli::command();
        let version = command.render_version().to_string();

        assert_eq!(
            version.trim(),
            format!("fleet {}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn local_facts_identify_the_fleet_executable() {
        assert_eq!(collect_local_facts()["runtime"]["executable"], "fleet");
    }

    #[test]
    fn agent_start_help_explains_enrollment_and_examples() {
        let mut command = Cli::command();
        let agent = command
            .find_subcommand_mut("agent")
            .expect("agent command should exist");
        let start = agent
            .find_subcommand_mut("start")
            .expect("agent start command should exist");
        let help = start.render_long_help().to_string();

        for expected in [
            "Start the enrolled local agent persistent session loop",
            "agent/agent.conf",
            "pinned controller fingerprint",
            "heartbeat liveness ticks",
            "static facts inventory",
            "metrics snapshots",
            "Heartbeat is only a liveness signal",
            "controller-signed tasks",
            "one outbound writer queue",
            "product-safe agent operational logs",
            "Connection failures are retried indefinitely by default",
            "The agent must be enrolled before this command can run",
            "Examples:",
            "Local development flow:",
            "--heartbeat-interval-seconds",
            "--facts-interval-seconds",
            "--metrics-interval-seconds",
            "--disable-log-upload",
            "--log-upload-interval-seconds",
            "0 means retry indefinitely",
        ] {
            assert!(help.contains(expected), "missing help entry: {expected}");
        }
    }

    #[test]
    fn agent_start_parses_log_upload_options() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agent",
            "start",
            "--data-dir",
            ".fleet",
            "--facts-interval-seconds",
            "600",
            "--metrics-interval-seconds",
            "15",
            "--disable-log-upload",
            "--log-upload-interval-seconds",
            "45",
        ])
        .expect("agent start should parse");

        assert!(matches!(
            cli.command,
            Command::Agent(AgentCommand {
                command: AgentSubcommand::Start {
                    facts_interval_seconds: 600,
                    metrics_interval_seconds: 15,
                    disable_log_upload: true,
                    log_upload_interval_seconds: 45,
                    ..
                }
            })
        ));
    }

    #[test]
    fn agent_init_parses_enrollment() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agent",
            "init",
            "--url",
            "http://127.0.0.1:7700",
            "--token",
            "token-1",
            "--name",
            "web-01",
            "--labels",
            "role=web,env=dev",
        ])
        .expect("agent init should parse");

        assert!(matches!(
            cli.command,
            Command::Agent(AgentCommand {
                command: AgentSubcommand::Init {
                    url,
                    token,
                    name,
                    labels,
                    ..
                }
            }) if url == "http://127.0.0.1:7700"
                && token == "token-1"
                && name == "web-01"
                && labels == "role=web,env=dev"
        ));
    }

    #[test]
    fn agent_init_parses_tls_ca_cert() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agent",
            "init",
            "--url",
            "https://fleet.example.com",
            "--tls-ca-cert",
            "/etc/fleet/tls/ca.pem",
            "--token",
            "token-1",
            "--name",
            "web-01",
        ])
        .expect("agent init should parse");

        let Command::Agent(AgentCommand {
            command: AgentSubcommand::Init { tls_ca_cert, .. },
        }) = cli.command
        else {
            panic!("expected agent init command");
        };

        assert_eq!(
            tls_ca_cert.as_deref(),
            Some(Path::new("/etc/fleet/tls/ca.pem"))
        );
    }

    #[test]
    fn agent_enroll_remains_alias_for_init() {
        let cli = Cli::try_parse_from([
            "fleet",
            "agent",
            "enroll",
            "--url",
            "http://127.0.0.1:7700",
            "--token",
            "token-1",
            "--name",
            "web-01",
        ])
        .expect("agent enroll alias should parse");

        assert!(matches!(
            cli.command,
            Command::Agent(AgentCommand {
                command: AgentSubcommand::Init { name, .. }
            }) if name == "web-01"
        ));
    }

    #[test]
    fn high_risk_run_requires_confirmation() {
        let cli = Cli::try_parse_from(["fleet", "run", "uptime"]).expect("valid command");
        assert!(matches!(
            execute(cli),
            Err(CliError::HighRiskConfirmationRequired)
        ));
    }

    #[test]
    fn command_output_is_redacted_before_rendering() {
        let output = fleet_runner::CommandOutput {
            stdout: "token=abc123\n".to_owned(),
            stderr: "secret=def456\n".to_owned(),
            exit_code: 0,
            truncated: false,
        };

        let (stdout, stderr) = render_command_output(&output);

        assert_eq!(stdout, "token=[REDACTED]\n");
        assert_eq!(stderr, "secret=[REDACTED]\n");
    }

    #[test]
    fn job_output_renderer_prefixes_agent_stream_and_sequence() {
        let lines = render_job_output_api_for_cli(
            r#"[
                {"job_id":"job-1","agent_id":"agent-a","stream":"stdout","sequence":0,"data":"ok\n"},
                {"job_id":"job-1","agent_id":"agent-b","stream":"stderr","sequence":1,"data":"token=abc\n"}
            ]"#,
        )
        .unwrap();

        assert_eq!(lines[0], "[agent-a stdout #0] ok\n");
        assert_eq!(lines[1], "[agent-b stderr #1] token=[REDACTED]\n");
    }

    #[test]
    fn log_tail_keeps_last_lines_in_order() {
        let body = (0..60)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");

        let lines = render_log_tail(&body);

        assert_eq!(lines.len(), LOG_TAIL_MAX_LINES);
        assert_eq!(lines.first().unwrap(), "line-10");
        assert_eq!(lines.last().unwrap(), "line-59");
    }

    #[test]
    fn log_tail_redacts_secret_like_values() {
        let lines = render_log_tail("ok\ntoken=abc123 password=p1\n");

        assert_eq!(lines, ["ok", "token=[REDACTED] password=[REDACTED]"]);
    }

    #[test]
    fn log_tail_truncates_oversized_lines() {
        let body = "x".repeat(LOG_TAIL_MAX_LINE_BYTES + 20);
        let lines = render_log_tail(&body);

        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("...[truncated]"));
        assert!(lines[0].len() < body.len());
    }

    #[test]
    fn log_follow_streams_appended_lines() {
        let dir = unique_test_dir("log-follow");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        fs::write(&path, "initial\n").unwrap();
        let append_path = path.clone();
        let appender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let mut file = OpenOptions::new().append(true).open(append_path).unwrap();
            writeln!(file, "token=abc").unwrap();
        });
        let mut lines = Vec::new();

        stream_log_file(
            &path,
            LogStreamOptions {
                follow: true,
                max_duration: Some(Duration::from_millis(120)),
                poll_interval: Duration::from_millis(10),
            },
            |line| lines.push(line),
            || false,
        )
        .unwrap();
        appender.join().unwrap();

        assert_eq!(lines, ["initial", "token=[REDACTED]"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn log_follow_can_be_canceled() {
        let dir = unique_test_dir("log-cancel");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        fs::write(&path, "initial\n").unwrap();
        let mut polls = 0;
        let mut lines = Vec::new();

        stream_log_file(
            &path,
            LogStreamOptions {
                follow: true,
                max_duration: None,
                poll_interval: Duration::from_millis(1),
            },
            |line| lines.push(line),
            || {
                polls += 1;
                polls > 1
            },
        )
        .unwrap();

        assert_eq!(lines, ["initial"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn log_follow_respects_max_duration() {
        let dir = unique_test_dir("log-max-duration");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        fs::write(&path, "initial\n").unwrap();
        let started_at = Instant::now();

        stream_log_file(
            &path,
            LogStreamOptions {
                follow: true,
                max_duration: Some(Duration::from_millis(20)),
                poll_interval: Duration::from_millis(5),
            },
            |_line| {},
            || false,
        )
        .unwrap();

        assert!(started_at.elapsed() >= Duration::from_millis(20));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn builds_journald_service_shortcut_command() {
        let command = journald_command_for_service("nginx.service").unwrap();

        assert_eq!(command.program, "journalctl");
        assert_eq!(
            command.args,
            ["-u", "nginx.service", "--no-pager", "-n", "50"]
        );
        assert!(journald_command_for_service("nginx;reboot").is_none());
    }

    #[test]
    fn missing_log_file_is_reported_as_io_error() {
        let cli = Cli::try_parse_from([
            "fleet",
            "logs",
            "web-01",
            "--file",
            "/definitely/missing/fleet.log",
        ])
        .unwrap();

        assert!(matches!(execute(cli), Err(CliError::Io(_))));
    }

    #[test]
    fn parses_http_controller_url_for_remote_agent_with_warning_policy() {
        let endpoint = parse_controller_url("http://10.0.0.5:7700").unwrap();

        assert_eq!(endpoint.scheme, ControllerUrlScheme::Http);
        assert_eq!(endpoint.host, "10.0.0.5");
        assert_eq!(endpoint.port, 7700);
        assert_eq!(
            endpoint.api_url("/api/controller/identity"),
            "http://10.0.0.5:7700/api/controller/identity"
        );
        assert_eq!(
            endpoint.websocket_url("/api/agents/ws"),
            "ws://10.0.0.5:7700/api/agents/ws"
        );
    }

    #[test]
    fn parses_https_controller_url_for_remote_agent() {
        let endpoint = parse_controller_url("https://fleet.example.com").unwrap();

        assert_eq!(endpoint.scheme, ControllerUrlScheme::Https);
        assert_eq!(endpoint.host, "fleet.example.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(
            endpoint.api_url("/api/controller/identity"),
            "https://fleet.example.com:443/api/controller/identity"
        );
        assert_eq!(
            endpoint.websocket_url("/api/agents/ws"),
            "wss://fleet.example.com:443/api/agents/ws"
        );
    }

    #[test]
    fn rejects_wildcard_host_as_agent_controller_url() {
        assert!(matches!(
            parse_controller_url("http://0.0.0.0:7700"),
            Err(CliError::Http(_))
        ));
    }

    #[test]
    fn reconnect_backoff_is_capped() {
        assert_eq!(reconnect_backoff(1), Duration::from_secs(2));
        assert_eq!(reconnect_backoff(10), Duration::from_secs(32));
    }

    #[test]
    fn agent_report_retry_delay_is_bounded_exponential() {
        assert_eq!(agent_report_retry_delay(1), Duration::from_secs(1));
        assert_eq!(agent_report_retry_delay(2), Duration::from_secs(2));
        assert_eq!(agent_report_retry_delay(3), Duration::from_secs(4));
        assert_eq!(agent_report_retry_delay(6), Duration::from_secs(30));
        assert_eq!(agent_report_retry_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn agent_report_delivery_orders_task_ack_started_then_rejected_before_final_result() {
        use fleet_application::delivery::JournalReport;
        use fleet_domain::delivery::{ReportClass, ReportKey};

        let lifecycle = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "task-ack").unwrap(),
            ReportClass::Lifecycle,
            br#"{"event":"task_ack"}"#.to_vec(),
        )
        .unwrap();
        let final_result = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "final-result").unwrap(),
            ReportClass::FinalResult,
            br#"{"status":"failed"}"#.to_vec(),
        )
        .unwrap();
        let task_started = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "task-started").unwrap(),
            ReportClass::Lifecycle,
            br#"{"event":"task_started"}"#.to_vec(),
        )
        .unwrap();
        let task_rejected = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "task-rejected").unwrap(),
            ReportClass::Lifecycle,
            br#"{"event":"task_rejected","reason_code":"local_policy","reason":"blocked"}"#
                .to_vec(),
        )
        .unwrap();

        assert_eq!(
            compare_agent_report_delivery_order(&lifecycle, &final_result),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_agent_report_delivery_order(&lifecycle, &task_started),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_agent_report_delivery_order(&task_started, &final_result),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_agent_report_delivery_order(&task_started, &task_rejected),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_agent_report_delivery_order(&task_rejected, &final_result),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn agent_report_scan_does_not_resurrect_a_receipt_acknowledged_row() {
        use fleet_domain::delivery::ReportKey;

        let acknowledged =
            ReportKey::new("controller", "agent", "job", "task", "task-ack").unwrap();
        let stale_scan_snapshot = HashSet::from([acknowledged.clone()]);
        let unrelated = ReportKey::new("controller", "agent", "job", "other", "task-ack").unwrap();

        assert!(!agent_report_scan_result_is_current(
            &acknowledged,
            &stale_scan_snapshot
        ));
        assert!(agent_report_scan_result_is_current(
            &unrelated,
            &stale_scan_snapshot
        ));
    }

    #[test]
    fn agent_log_upload_due_respects_disable_and_interval() {
        let enabled = AgentLogUploadOptions {
            enabled: true,
            interval: Duration::from_secs(30),
        };
        let disabled = AgentLogUploadOptions {
            enabled: false,
            interval: Duration::from_secs(30),
        };

        assert!(should_upload_agent_log(enabled, Duration::from_secs(30)));
        assert!(!should_upload_agent_log(enabled, Duration::from_secs(29)));
        assert!(!should_upload_agent_log(disabled, Duration::from_secs(30)));
    }

    #[test]
    fn agent_heartbeat_loop_uploads_log_immediately_by_default() {
        let mut upload_flags = Vec::new();

        let result = run_agent_heartbeat_loop_with(
            AgentHeartbeatOptions {
                once: true,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 0,
            },
            |upload_log| {
                upload_flags.push(upload_log);
                Ok(())
            },
            |_| panic!("once mode must not sleep after success"),
        );

        assert!(result.is_ok());
        assert_eq!(upload_flags, vec![true]);
    }

    #[test]
    fn agent_heartbeat_loop_respects_disabled_log_upload() {
        let mut upload_flags = Vec::new();

        let result = run_agent_heartbeat_loop_with(
            AgentHeartbeatOptions {
                once: true,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: false,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 0,
            },
            |upload_log| {
                upload_flags.push(upload_log);
                Ok(())
            },
            |_| panic!("once mode must not sleep after success"),
        );

        assert!(result.is_ok());
        assert_eq!(upload_flags, vec![false]);
    }

    #[test]
    fn agent_session_loop_preserves_runtime_state_across_reconnect() {
        let mut attempts = 0;
        let mut runtime_markers = Vec::new();
        let mut shared_runtime = 0_u8;

        run_agent_session_loop_with_state_for_test(
            &mut shared_runtime,
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: false,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 1,
            },
            |runtime| {
                *runtime += 1;
                runtime_markers.push(*runtime);
                attempts += 1;
                if attempts == 1 {
                    Err(CliError::Http("temporary socket failure".to_owned()))
                } else {
                    Err(CliError::Http(
                        "controller signing fingerprint changed".to_owned(),
                    ))
                }
            },
            |_| {},
        )
        .unwrap_err();

        assert_eq!(runtime_markers, [1, 2]);
    }

    #[test]
    fn agent_heartbeat_loop_retries_connection_failures_until_configured_cap() {
        let mut attempts = 0;
        let mut sleeps = Vec::new();

        let result = run_agent_heartbeat_loop_with(
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 2,
            },
            |_| {
                attempts += 1;
                Err(CliError::Http(format!("connection refused #{attempts}")))
            },
            |duration| sleeps.push(duration),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 3);
        assert_eq!(sleeps, vec![Duration::from_secs(2), Duration::from_secs(4)]);
    }

    #[test]
    fn agent_heartbeat_loop_current_lifecycle_sleeps_between_successful_heartbeats() {
        let mut attempts = 0;
        let mut sleeps = Vec::new();

        let result = run_agent_heartbeat_loop_with(
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 1,
            },
            |_| {
                attempts += 1;
                if attempts == 1 {
                    Ok(())
                } else {
                    Err(CliError::Http(format!("connection refused #{attempts}")))
                }
            },
            |duration| sleeps.push(duration),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 3);
        assert_eq!(
            sleeps,
            vec![Duration::from_secs(30), Duration::from_secs(2)]
        );
    }

    #[test]
    fn agent_heartbeat_loop_once_exits_on_first_failure() {
        let mut attempts = 0;

        let result = run_agent_heartbeat_loop_with(
            AgentHeartbeatOptions {
                once: true,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 0,
            },
            |_| {
                attempts += 1;
                Err(CliError::Http("connection refused".to_owned()))
            },
            |_| panic!("once mode must not sleep after a failed heartbeat"),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn agent_session_loop_retries_connection_failures_until_configured_cap() {
        let mut attempts = 0;
        let mut sleeps = Vec::new();

        let result = run_agent_session_loop_with(
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 2,
            },
            || {
                attempts += 1;
                Err(CliError::Http(format!("connection refused #{attempts}")))
            },
            |duration| sleeps.push(duration),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 3);
        assert_eq!(sleeps, vec![Duration::from_secs(2), Duration::from_secs(4)]);
    }

    #[test]
    fn agent_session_loop_reconnects_after_controller_close() {
        let mut attempts = 0;
        let mut sleeps = Vec::new();

        let result = run_agent_session_loop_with(
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 1,
            },
            || {
                attempts += 1;
                if attempts == 1 {
                    Ok(AgentSessionEnd::ControllerClosed)
                } else {
                    Err(CliError::Http(format!("connection refused #{attempts}")))
                }
            },
            |duration| sleeps.push(duration),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 3);
        assert_eq!(
            sleeps,
            vec![Duration::from_secs(30), Duration::from_secs(2)]
        );
    }

    #[test]
    fn agent_session_loop_once_exits_after_controller_close() {
        let mut attempts = 0;

        let result = run_agent_session_loop_with(
            AgentHeartbeatOptions {
                once: true,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 0,
            },
            || {
                attempts += 1;
                Ok(AgentSessionEnd::ControllerClosed)
            },
            |_| panic!("once mode must not sleep after controller close"),
        );

        assert!(result.is_ok());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn agent_session_loop_treats_fingerprint_mismatch_as_fatal() {
        let mut attempts = 0;

        let result = run_agent_session_loop_with(
            AgentHeartbeatOptions {
                once: false,
                heartbeat_interval: Duration::from_secs(30),
                facts_interval: Duration::from_secs(300),
                metrics_interval: Duration::from_secs(30),
                log_upload: AgentLogUploadOptions {
                    enabled: true,
                    interval: Duration::from_secs(30),
                },
                max_reconnect_attempts: 0,
            },
            || {
                attempts += 1;
                Err(CliError::Http(
                    "controller signing fingerprint changed from a to b; re-enroll the agent"
                        .to_owned(),
                ))
            },
            |_| panic!("fatal fingerprint mismatch must not sleep or retry"),
        );

        assert!(matches!(result, Err(CliError::Http(_))));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn agent_session_heartbeat_interval_controls_liveness_ticks() {
        let options = AgentHeartbeatOptions {
            once: false,
            heartbeat_interval: Duration::from_secs(30),
            facts_interval: Duration::from_secs(300),
            metrics_interval: Duration::from_secs(30),
            log_upload: AgentLogUploadOptions {
                enabled: true,
                interval: Duration::from_secs(45),
            },
            max_reconnect_attempts: 0,
        };

        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(29),
                Duration::from_secs(29),
                Duration::from_secs(29),
                Duration::from_secs(44),
                options,
            ),
            AgentSessionTickActions::default()
        );
        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(44),
                options,
            ),
            AgentSessionTickActions {
                heartbeat: true,
                facts: false,
                metrics: true,
                log: false,
            }
        );
    }

    #[test]
    fn agent_session_facts_do_not_send_on_every_heartbeat() {
        let options = AgentHeartbeatOptions {
            once: false,
            heartbeat_interval: Duration::from_secs(30),
            facts_interval: Duration::from_secs(300),
            metrics_interval: Duration::from_secs(30),
            log_upload: AgentLogUploadOptions {
                enabled: true,
                interval: Duration::from_secs(30),
            },
            max_reconnect_attempts: 0,
        };

        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(30),
                Duration::from_secs(299),
                Duration::from_secs(30),
                Duration::from_secs(30),
                options,
            ),
            AgentSessionTickActions {
                heartbeat: true,
                facts: false,
                metrics: true,
                log: true,
            }
        );
        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(30),
                Duration::from_secs(300),
                Duration::from_secs(29),
                Duration::from_secs(29),
                options,
            ),
            AgentSessionTickActions {
                heartbeat: true,
                facts: true,
                metrics: false,
                log: false,
            }
        );
    }

    #[test]
    fn agent_session_metrics_respect_configured_interval() {
        let options = AgentHeartbeatOptions {
            once: false,
            heartbeat_interval: Duration::from_secs(10),
            facts_interval: Duration::from_secs(300),
            metrics_interval: Duration::from_secs(45),
            log_upload: AgentLogUploadOptions {
                enabled: true,
                interval: Duration::from_secs(30),
            },
            max_reconnect_attempts: 0,
        };

        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(10),
                Duration::from_secs(299),
                Duration::from_secs(44),
                Duration::from_secs(30),
                options,
            ),
            AgentSessionTickActions {
                heartbeat: true,
                facts: false,
                metrics: false,
                log: true,
            }
        );
        assert_eq!(
            agent_session_tick_actions(
                Duration::from_secs(9),
                Duration::from_secs(299),
                Duration::from_secs(45),
                Duration::from_secs(29),
                options,
            ),
            AgentSessionTickActions {
                heartbeat: false,
                facts: false,
                metrics: true,
                log: false,
            }
        );
    }

    #[test]
    fn agent_session_outbound_queue_full_is_bounded() {
        let sender = test_outbound_queue(1);
        let config = test_agent_config();

        enqueue_wire_message(
            &sender,
            agent_heartbeat_message(&config, "corr-test").unwrap(),
        )
        .unwrap();
        let result = enqueue_wire_message(
            &sender,
            agent_metrics_snapshot_message(&config, "corr-test").unwrap(),
        );

        assert!(
            matches!(result, Err(CliError::Http(message)) if message.contains("queue is full"))
        );
    }

    #[test]
    fn failed_outbound_write_keeps_front_report_for_reconnect() {
        let queue = test_outbound_queue(1);
        let config = test_agent_config();
        enqueue_wire_message(
            &queue,
            agent_heartbeat_message(&config, "corr-test").unwrap(),
        )
        .unwrap();

        let failed = flush_agent_outbound_queue_with(&queue, |_| {
            Err(CliError::Http("socket write failed".to_owned()))
        });

        assert!(failed.is_err());
        assert!(queue.lock().unwrap().pending_report().is_some());

        let mut replayed_message_ids = Vec::new();
        flush_agent_outbound_queue_with(&queue, |message| {
            replayed_message_ids.push(message.message_id.clone());
            Ok(())
        })
        .unwrap();

        assert_eq!(replayed_message_ids.len(), 1);
        assert!(queue.lock().unwrap().pending_report().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn command_output_is_committed_to_agent_journal_with_stable_exact_report_identity() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::AppendReportOutcome;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let root = unique_test_dir("command-output-journal");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 4096,
                bytes: 64 * 1024 * 1024,
            },
            JournalUsage {
                reports: 4,
                bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, 64 * 1024 * 1024, 8 * 1024 * 1024).unwrap();
        let repository = SqliteAgentJournal::open(&path, &namespace, "agent-web-01").unwrap();
        let worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        let client = worker.client();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let chunk = fleet_runner::CommandOutputChunk {
            stream: fleet_runner::CommandOutputStream::Stdout,
            sequence: 7,
            data: "hello output".to_owned(),
        };

        let inserted =
            persist_task_output_report(&client, &namespace, &config, &envelope, chunk.clone())
                .unwrap();
        assert_eq!(inserted, AppendReportOutcome::Inserted);
        let pending = client
            .pending(16, 8 * 1024 * 1024)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].report.key.parts(),
            [
                namespace.as_str(),
                "agent-web-01",
                "job-queue",
                "task-queue",
                "output-stdout-00000000000000000007",
            ]
        );
        assert_eq!(
            pending[0].report.body(),
            br#"{"stream":"stdout","sequence":7,"data":"hello output"}"#
        );

        let duplicate =
            persist_task_output_report(&client, &namespace, &config, &envelope, chunk).unwrap();
        assert_eq!(duplicate, AppendReportOutcome::Duplicate);
        assert_eq!(
            client
                .pending(16, 8 * 1024 * 1024)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .len(),
            1
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn command_output_journal_failure_never_commits_a_final_summary() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let root = unique_test_dir("command-output-journal-failure");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 3,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: 1,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-output-journal-failure",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        assert!(
            run_signed_command_task_queue(
                &session,
                &envelope,
                fleet_protocol::CommandTaskWire {
                    program: "sh".to_owned(),
                    args: vec!["-c".to_owned(), "printf output".to_owned()],
                    timeout_ms: 5_000,
                    max_output_bytes: 1024,
                },
            )
            .is_err()
        );
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-ack")
        );
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-started")
        );
        assert!(
            !pending
                .iter()
                .any(|entry| entry.report.class == ReportClass::FinalResult)
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_command_final_result_replays_after_reopen_and_exact_receipt_cleans_it() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::PendingReport;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_protocol::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let store_epoch = "b".repeat(64);
        let root = unique_test_dir("command-final-result-reconnect-replay");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let first_client = worker.client();
        let outbound = test_outbound_queue(8);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-command-final",
            task_state: &task_state,
            journal_client: &first_client,
            controller_namespace: &namespace,
        };

        run_signed_command_task_queue(
            &session,
            &envelope,
            fleet_protocol::CommandTaskWire {
                program: "sh".to_owned(),
                args: vec!["-c".to_owned(), "printf out; printf err >&2".to_owned()],
                timeout_ms: 5_000,
                max_output_bytes: 1024,
            },
        )
        .unwrap();
        assert!(outbound.lock().unwrap().pending_report().is_none());
        let first_pending = first_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(first_pending.len(), 5);
        let ack = first_pending
            .iter()
            .find(|entry| entry.report.key.parts()[4] == "task-ack")
            .expect("task acknowledgement is journaled");
        assert_eq!(ack.report.key.parts()[4], "task-ack");
        let started = first_pending
            .iter()
            .find(|entry| entry.report.key.parts()[4] == "task-started")
            .expect("TaskStarted is journaled");
        assert_eq!(started.report.body(), br#"{"event":"task_started"}"#);
        let final_report = first_pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("final result remains journaled");
        assert_eq!(
            final_report.report.key.parts(),
            [
                namespace.as_str(),
                config.agent_id.as_str(),
                "job-queue",
                "task-queue",
                "final-result",
            ]
        );
        let final_body: serde_json::Value =
            serde_json::from_slice(final_report.report.body()).unwrap();
        assert_eq!(final_body["output"]["stdout_chunks"], 1);
        assert_eq!(final_body["output"]["stderr_chunks"], 1);
        assert_eq!(final_body["output"]["truncated"], false);
        let output_reports: Vec<_> = first_pending
            .iter()
            .filter(|entry| entry.report.class == ReportClass::Output)
            .collect();
        assert_eq!(output_reports.len(), 2);
        for output in output_reports {
            let body: serde_json::Value = serde_json::from_slice(output.report.body()).unwrap();
            assert_eq!(body["sequence"], 0);
        }
        let old_session_message =
            agent_journal_report_wire_message(final_report, &config, "corr-before-reconnect")
                .unwrap();
        drop(first_pending);
        drop(first_client);
        worker.shutdown().unwrap();

        let reopened_worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = reopened_worker.client();
        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 5);
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-ack")
        );
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-started")
        );
        let pending: PendingReport = pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("final result survives reopen")
            .clone();
        let key = pending.report.key.clone();
        let new_session_message =
            agent_journal_report_wire_message(&pending, &config, "corr-after-reconnect").unwrap();
        assert_ne!(
            old_session_message.message_id,
            new_session_message.message_id
        );
        let fleet_protocol::WirePayload::TaskReport(old_report) = old_session_message.payload
        else {
            panic!("expected v2 task report before reconnect");
        };
        let fleet_protocol::WirePayload::TaskReport(new_report) = new_session_message.payload
        else {
            panic!("expected v2 task report after reconnect");
        };
        assert_eq!(old_report, new_report);
        assert_eq!(
            new_report.class,
            fleet_protocol::delivery_v2::V2ReportClassWire::FinalResult
        );

        let mut delivery = AgentJournalReportDelivery::new(
            client.clone(),
            ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: store_epoch.clone(),
            },
        );
        delivery.pending_scan = Some(
            client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap(),
        );
        let scan_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending_scan.is_some() && Instant::now() < scan_deadline {
            delivery.poll_pending_scan().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(delivery.pending.contains_key(&key));

        let keys = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = config;
        config.controller_fingerprint = keys.fingerprint.clone();
        let [_, agent_id, job_id, task_id, report_id] = pending.report.key.parts();
        let digest_hex = pending
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let statement = ReportReceiptStatementWire {
            controller_namespace: namespace,
            store_epoch,
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let signature_hex = fleet_core::sign_challenge(
            &keys.private_key_hex,
            &statement.signing_preimage().unwrap(),
        )
        .unwrap();
        let receipt = SignedReportReceiptWire {
            statement,
            signature_hex,
        };
        let receipt_message = fleet_protocol::WireMessage::new(
            "msg-final-receipt",
            "corr-after-reconnect",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        delivery
            .handle_receipt(
                &receipt_message,
                &receipt,
                &config,
                &keys.public_key_hex,
                "corr-after-reconnect",
                &task_state,
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&key) && Instant::now() < deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&key));
        let remaining = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(remaining.len(), 4);
        assert!(
            remaining
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-ack")
        );
        assert!(
            remaining
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-started")
        );
        assert_eq!(
            remaining
                .iter()
                .filter(|entry| entry.report.class == ReportClass::Output)
                .count(),
            2
        );
        reopened_worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_no_artifact_runbook_executor_observes_durable_start_intent() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{ExecutionPhase, JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let root = unique_test_dir("runbook-execution-start-intent");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = worker.client();
        let outbound = test_outbound_queue(8);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-runbook-start-intent",
            task_state: &task_state,
            journal_client: &client,
            controller_namespace: &namespace,
        };
        let observed_phase = Arc::new(Mutex::new(None));
        let observed_phase_by_executor = observed_phase.clone();
        let executor_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executor_calls_by_executor = executor_calls.clone();
        let executor_journal = client.clone();
        let runbook_task = || {
            fleet_protocol::RunbookExecutionTaskWire {
            runbook_document: "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: local-facts\nselector: role=web\nsteps:\n  - id: facts\n    facts.collect:\n      scope: local".to_owned(),
            timeout_ms: 5_000,
            confirmed_high_risk: false,
        }
        };

        let result = run_signed_runbook_task_queue_with_executor(
            &session,
            &envelope,
            runbook_task(),
            move |_, _| {
                executor_calls_by_executor.fetch_add(1, Ordering::SeqCst);
                let record = executor_journal
                    .interrupted()
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap();
                *observed_phase_by_executor.lock().unwrap() =
                    record.map(|record| record.snapshot().phase);
                Ok(fleet_runner::RunbookExecutionReport {
                    runbook_name: "local-facts".to_owned(),
                    outcomes: Vec::new(),
                })
            },
        );
        let duplicate_executor_calls = executor_calls.clone();
        let duplicate_result = run_signed_runbook_task_queue_with_executor(
            &session,
            &envelope,
            runbook_task(),
            move |_, _| {
                duplicate_executor_calls.fetch_add(1, Ordering::SeqCst);
                Ok(fleet_runner::RunbookExecutionReport {
                    runbook_name: "local-facts".to_owned(),
                    outcomes: Vec::new(),
                })
            },
        );
        let interrupted_after_completion = client
            .interrupted()
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();
        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();

        result.unwrap();
        duplicate_result.unwrap();
        assert_eq!(executor_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *observed_phase.lock().unwrap(),
            Some(ExecutionPhase::StartIntent),
            "Runbook execution must not enter its executor before StartIntent is durable"
        );
        assert!(pending.iter().any(|entry| {
            entry.report.key.parts()[4] == "task-started"
                && entry.report.body() == br#"{"event":"task_started"}"#
        }));
        assert!(pending.iter().any(|entry| {
            entry.report.key.parts()[4] == "task-ack"
                && entry.report.body() == br#"{"event":"task_ack"}"#
        }));
        let ack_position = pending
            .iter()
            .position(|entry| entry.report.key.parts()[4] == "task-ack")
            .unwrap();
        let started_position = pending
            .iter()
            .position(|entry| entry.report.key.parts()[4] == "task-started")
            .unwrap();
        assert!(ack_position < started_position);
        assert!(interrupted_after_completion.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn runbook_execution_admission_failure_prevents_ack_and_file_side_effect() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "b".repeat(64);
        let root = unique_test_dir("runbook-admission-fail-closed");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let destination = root.join("runbook-side-effect.conf");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, AGENT_JOURNAL_MAX_BYTES, 1).unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = worker.client();
        let outbound = test_outbound_queue(8);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-runbook-admission-failure",
            task_state: &task_state,
            journal_client: &client,
            controller_namespace: &namespace,
        };
        let runbook_document = format!(
            "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nmetadata:\n  name: write-config\nspec:\n  targets:\n    selector: role=web\n  tasks:\n    - id: config\n      file.copy:\n        dest: {}\n        content: marker\n",
            destination.display()
        );

        let result = run_signed_runbook_task_queue(
            &session,
            &envelope,
            fleet_protocol::RunbookExecutionTaskWire {
                runbook_document,
                timeout_ms: 5_000,
                confirmed_high_risk: true,
            },
        );
        let side_effect_exists = destination.exists();
        drop(client);
        worker.shutdown().unwrap();

        let reopen_limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let reopened = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            reopen_limits,
        )
        .unwrap();
        let reopened_client = reopened.client();
        let pending = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();
        reopened.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();

        assert!(
            result.is_err(),
            "admission exceeds the journal request limit"
        );
        assert!(
            !side_effect_exists,
            "file.copy must not run before admission"
        );
        assert!(
            pending.is_empty(),
            "failed admission must not report TaskAck"
        );
        assert!(TestOutboundReceiver(outbound).try_recv().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn persistent_runbook_no_artifact_final_result_is_journaled_and_replays_after_reopen() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_protocol::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let root = unique_test_dir("runbook-final-result-reconnect-replay");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let mut config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = worker.client();
        let outbound = test_outbound_queue(8);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-runbook-final",
            task_state: &task_state,
            journal_client: &client,
            controller_namespace: &namespace,
        };

        run_signed_runbook_task_queue(
            &session,
            &envelope,
            fleet_protocol::RunbookExecutionTaskWire {
                runbook_document: "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: local-facts\nselector: role=web\nsteps:\n  - id: facts\n    facts.collect:\n      scope: local".to_owned(),
                timeout_ms: 5_000,
                confirmed_high_risk: false,
            },
        )
        .unwrap();

        let mut queued = outbound.lock().unwrap();
        let mut output_chunks = 0;
        while let Some(message) = queued.remove_pending_report() {
            match message.payload {
                fleet_protocol::WirePayload::OutputChunk { .. } => output_chunks += 1,
                fleet_protocol::WirePayload::TaskStarted { .. } => {
                    panic!("persistent TaskStarted must use the journal report path")
                }
                fleet_protocol::WirePayload::TaskResult { .. } => {
                    panic!("no-artifact Runbook result must use the durable report path")
                }
                payload => panic!("unexpected Runbook event: {payload:?}"),
            }
        }
        assert_eq!(
            output_chunks, 0,
            "durable Runbook output must not use the ephemeral queue"
        );
        drop(queued);

        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        let output_reports = pending
            .iter()
            .filter(|entry| entry.report.class == ReportClass::Output)
            .collect::<Vec<_>>();
        assert!(
            !output_reports.is_empty(),
            "no-artifact Runbook output chunks must be journaled"
        );
        let output_report_count = output_reports.len();
        let mut stdout_sequences = Vec::new();
        let mut stderr_sequences = Vec::new();
        for entry in &output_reports {
            let body: serde_json::Value = serde_json::from_slice(entry.report.body()).unwrap();
            let sequence = body["sequence"].as_u64().unwrap();
            match body["stream"].as_str().unwrap() {
                "stdout" => stdout_sequences.push(sequence),
                "stderr" => stderr_sequences.push(sequence),
                stream => panic!("unexpected Runbook output stream: {stream}"),
            }
        }
        assert_eq!(
            stdout_sequences,
            (0..stdout_sequences.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(
            stderr_sequences,
            (0..stderr_sequences.len() as u64).collect::<Vec<_>>()
        );
        let started = pending
            .iter()
            .find(|entry| entry.report.key.parts()[4] == "task-started")
            .expect("TaskStarted is retained in the journal");
        assert_eq!(started.report.class, ReportClass::Lifecycle);
        assert_eq!(started.report.body(), br#"{"event":"task_started"}"#);
        let started_key = started.report.key.clone();
        let final_report = pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("Runbook final result is retained in the journal");
        assert_eq!(
            final_report.report.key.parts(),
            [
                namespace.as_str(),
                config.agent_id.as_str(),
                "job-queue",
                "task-queue",
                "final-result",
            ]
        );
        let body: serde_json::Value = serde_json::from_slice(final_report.report.body()).unwrap();
        assert_eq!(body["exit_code"], 0);
        assert_eq!(body["status"], "succeeded");
        assert_eq!(body["reason"], "");
        assert_eq!(body["artifacts"], serde_json::json!([]));
        assert_eq!(
            body["output"]["stdout_chunks"].as_u64(),
            Some(output_report_count as u64)
        );
        assert_eq!(body["output"]["stderr_chunks"], 0);
        assert_eq!(body["output"]["truncated"], false);
        let first_body = final_report.report.body().to_vec();
        drop(pending);
        drop(client);
        worker.shutdown().unwrap();

        let reopened = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let reopened_client = reopened.client();
        let replay = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(replay.len(), output_report_count + 3);
        let replayed_started = replay
            .iter()
            .find(|entry| entry.report.key.parts()[4] == "task-started")
            .expect("TaskStarted replays after journal reopen");
        assert_eq!(
            replayed_started.report.body(),
            br#"{"event":"task_started"}"#
        );
        assert_eq!(replayed_started.report.key, started_key);
        let pending_report = replay
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("final result replays after journal reopen")
            .clone();
        assert_eq!(pending_report.report.body(), first_body);
        let key = pending_report.report.key.clone();
        let digest_hex = pending_report
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        drop(replay);

        let mut delivery = AgentJournalReportDelivery::new(
            reopened_client.clone(),
            ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: "b".repeat(64),
            },
        );
        delivery.pending_scan = Some(
            reopened_client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap(),
        );
        let scan_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending_scan.is_some() && Instant::now() < scan_deadline {
            delivery.poll_pending_scan().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(delivery.pending.contains_key(&key));
        assert!(delivery.pending.contains_key(&started_key));

        let keys = fleet_core::generate_agent_key_pair().unwrap();
        config.controller_fingerprint = keys.fingerprint.clone();
        let [_, agent_id, job_id, task_id, report_id] = pending_report.report.key.parts();
        let statement = ReportReceiptStatementWire {
            controller_namespace: namespace.clone(),
            store_epoch: "b".repeat(64),
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let receipt = SignedReportReceiptWire {
            signature_hex: fleet_core::sign_challenge(
                &keys.private_key_hex,
                &statement.signing_preimage().unwrap(),
            )
            .unwrap(),
            statement,
        };
        let receipt_message = fleet_protocol::WireMessage::new(
            "msg-runbook-final-receipt",
            "corr-runbook-reconnected",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        delivery
            .handle_receipt(
                &receipt_message,
                &receipt,
                &config,
                &keys.public_key_hex,
                "corr-runbook-reconnected",
                &task_state,
            )
            .unwrap();
        let ack_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&key) && Instant::now() < ack_deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&key));
        let remaining = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(remaining.len(), output_report_count + 2);
        assert!(
            remaining
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-started")
        );
        assert_eq!(
            remaining
                .iter()
                .filter(|entry| entry.report.class == ReportClass::Output)
                .count(),
            output_report_count
        );

        let artifact = fleet_protocol::TaskResultArtifactWire {
            artifact_id: "artifact-runbook".to_owned(),
            step_id: "template:config".to_owned(),
            destination: "/etc/example.conf".to_owned(),
            checksum_sha256: "c".repeat(64),
            size_bytes: 3,
            retention_class: "rendered_template".to_owned(),
            content_bytes: Some(b"cfg".to_vec()),
        };
        let reopened_session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: &keys.public_key_hex,
            correlation_id: "corr-runbook-artifact",
            task_state: &task_state,
            journal_client: &reopened_client,
            controller_namespace: &namespace,
        };
        send_or_persist_runbook_final_result(
            &reopened_session,
            &envelope,
            AgentTaskResultReport::with_artifacts(
                0,
                fleet_protocol::TaskResultStatus::Succeeded,
                "",
                vec![artifact.clone()],
            ),
        )
        .unwrap();
        let artifact_result = outbound.lock().unwrap().remove_pending_report().unwrap();
        let fleet_protocol::WirePayload::TaskReport(artifact_result) = artifact_result.payload
        else {
            panic!("artifact-producing Runbook must use the v2 final-result report");
        };
        assert_eq!(
            artifact_result.class,
            fleet_protocol::delivery_v2::V2ReportClassWire::FinalResult
        );
        let report_body = artifact_result.body_bytes().unwrap();
        let report_body: fleet_protocol::delivery_v2::V2FinalResultReportBody =
            serde_json::from_slice(&report_body).unwrap();
        assert_eq!(report_body.artifacts, vec![artifact]);
        let remaining = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(remaining.len(), output_report_count + 2);
        assert!(
            remaining
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-started")
        );
        reopened.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_runbook_final_result_is_journaled_even_when_output_queue_is_full() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "f".repeat(64);
        let root = unique_test_dir("runbook-final-output-queue-full");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = worker.client();
        let outbound = test_outbound_queue(0);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-runbook-output-full",
            task_state: &task_state,
            journal_client: &client,
            controller_namespace: &namespace,
        };

        assert!(
            run_signed_runbook_task_queue(
                &session,
                &envelope,
                fleet_protocol::RunbookExecutionTaskWire {
                    runbook_document: "apiVersion: [invalid".to_owned(),
                    timeout_ms: 5_000,
                    confirmed_high_risk: false,
                },
            )
            .is_ok(),
            "durable Runbook output must not depend on ephemeral queue capacity"
        );
        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 3);
        let output = pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::Output)
            .expect("Runbook failure output is journaled");
        assert!(output.report.key.parts()[4].starts_with("output-stderr-"));
        let final_report = pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("Runbook failure final is journaled after output");
        let body: serde_json::Value = serde_json::from_slice(final_report.report.body()).unwrap();
        assert_eq!(body["status"], "failed");
        assert_eq!(body["output"]["stderr_chunks"], 1);
        assert_eq!(body["output"]["truncated"], false);
        drop(pending);
        drop(client);
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runbook_final_status_reflects_failed_or_canceled_step_outcomes() {
        let outcome = |status, exit_code| fleet_runner::RunbookStepOutcome {
            id: "step".to_owned(),
            status,
            changed: None,
            message: "step outcome".to_owned(),
            diff: None,
            started_at_ms: 1,
            completed_at_ms: 2,
            duration_ms: 1,
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
            audit_metadata: "primitive=test".to_owned(),
            artifact: None,
        };
        let failed = fleet_runner::RunbookExecutionReport {
            runbook_name: "failure".to_owned(),
            outcomes: vec![outcome(
                fleet_runner::PrimitiveResultStatus::Failed,
                Some(7),
            )],
        };
        assert_eq!(
            runbook_task_result_summary(&failed),
            (7, fleet_protocol::TaskResultStatus::Failed)
        );
        let canceled = fleet_runner::RunbookExecutionReport {
            runbook_name: "canceled".to_owned(),
            outcomes: vec![outcome(fleet_runner::PrimitiveResultStatus::Canceled, None)],
        };
        assert_eq!(
            runbook_task_result_summary(&canceled),
            (-1, fleet_protocol::TaskResultStatus::Canceled)
        );
    }

    #[cfg(unix)]
    #[test]
    fn persistent_command_commits_start_intent_before_child_and_completes_record_with_result() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{ExecutionPhase, JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "e".repeat(64);
        let root = unique_test_dir("command-execution-intent");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let keys = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = test_agent_config();
        config.controller_fingerprint = keys.fingerprint.clone();
        let now = SystemTime::now();
        let issued_at = now - Duration::from_secs(1);
        let expires_at = now + Duration::from_secs(60);
        let envelope = signed_test_task_envelope(
            &config.agent_id,
            "nonce-command-start-intent",
            "payload-command-start-intent",
            &keys.private_key_hex,
            issued_at,
            expires_at,
        );
        let wire_envelope = fleet_protocol::SignedTaskEnvelopeWire {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            target_agent_id: envelope.target_agent_id.as_str().to_owned(),
            issued_at_ms: issued_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            expires_at_ms: expires_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            nonce: envelope.nonce.as_str().to_owned(),
            payload_hash: envelope.payload_hash.clone(),
            signature: envelope.signature.as_ref().unwrap().as_str().to_owned(),
        };
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: &keys.public_key_hex,
            correlation_id: "corr-command-execution-intent",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        std::thread::scope(|scope| {
            let execution = scope.spawn(|| {
                handle_task_assignment_with_queue(
                    &session,
                    wire_envelope,
                    fleet_protocol::TaskWire::Command(fleet_protocol::CommandTaskWire {
                        program: "sleep".to_owned(),
                        args: vec!["2".to_owned()],
                        timeout_ms: 5_000,
                        max_output_bytes: 1024,
                    }),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(1);
            let record = loop {
                if let Some(record) = journal
                    .interrupted()
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap()
                    .filter(|record| record.snapshot().phase == ExecutionPhase::StartIntent)
                {
                    break record;
                }
                assert!(
                    Instant::now() < deadline,
                    "Command did not persist StartIntent"
                );
                std::thread::sleep(Duration::from_millis(2));
            };
            assert_eq!(record.snapshot().phase, ExecutionPhase::StartIntent);
            let pending_deadline = Instant::now() + Duration::from_secs(1);
            let pending = loop {
                let pending = journal
                    .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap();
                if pending
                    .iter()
                    .any(|entry| entry.report.key.parts()[4] == "task-started")
                {
                    break pending;
                }
                assert!(
                    Instant::now() < pending_deadline,
                    "Command did not persist TaskStarted before execution"
                );
                std::thread::sleep(Duration::from_millis(2));
            };
            assert!(pending.iter().any(|entry| {
                entry.report.key.parts()[4] == "task-started"
                    && entry.report.body() == br#"{"event":"task_started"}"#
            }));
            assert!(pending.iter().all(|entry| {
                entry.report.class != fleet_domain::delivery::ReportClass::FinalResult
            }));
            assert!(TestOutboundReceiver(outbound.clone()).try_recv().is_err());
            execution.join().unwrap().unwrap();
        });

        assert!(
            journal
                .interrupted()
                .unwrap()
                .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                .unwrap()
                .is_none()
        );
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();
        assert_eq!(pending.len(), 3);
        assert_eq!(
            pending[0].report.class,
            fleet_domain::delivery::ReportClass::Lifecycle
        );
        assert_eq!(pending[0].report.key.parts()[4], "task-ack");
        let ack_body: serde_json::Value = serde_json::from_slice(pending[0].report.body()).unwrap();
        assert_eq!(ack_body["event"], "task_ack");
        assert_eq!(pending[1].report.key.parts()[4], "task-started");
        assert_eq!(
            pending[2].report.class,
            fleet_domain::delivery::ReportClass::FinalResult
        );
        let ack_report = pending[0].clone();
        let ack_key = ack_report.report.key.clone();
        let ack_digest_hex = ack_report
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let started_report = pending
            .iter()
            .find(|entry| entry.report.key.parts()[4] == "task-started")
            .expect("TaskStarted remains journaled")
            .clone();
        assert_eq!(
            started_report.report.class,
            fleet_domain::delivery::ReportClass::Lifecycle
        );
        assert_eq!(started_report.report.body(), br#"{"event":"task_started"}"#);
        let started_key = started_report.report.key.clone();
        let started_digest_hex = started_report
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        drop(pending);
        worker.shutdown().unwrap();

        let reopened = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let reopened_client = reopened.client();
        let mut delivery = AgentJournalReportDelivery::new(
            reopened_client.clone(),
            ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: "d".repeat(64),
            },
        );
        delivery.pending_scan = Some(
            reopened_client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap(),
        );
        let scan_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending_scan.is_some() && Instant::now() < scan_deadline {
            delivery.poll_pending_scan().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(delivery.pending.contains_key(&ack_key));
        assert!(delivery.pending.contains_key(&started_key));

        let receipt_keys = fleet_core::generate_agent_key_pair().unwrap();
        config.controller_fingerprint = receipt_keys.fingerprint.clone();
        let [_, agent_id, job_id, task_id, report_id] = ack_report.report.key.parts();
        let statement = fleet_protocol::receipt::ReportReceiptStatementWire {
            controller_namespace: namespace.clone(),
            store_epoch: "d".repeat(64),
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex: ack_digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: fleet_protocol::receipt::ReportDispositionWire::Stored,
            signing_key_fingerprint: receipt_keys.fingerprint.clone(),
        };
        let receipt = fleet_protocol::receipt::SignedReportReceiptWire {
            signature_hex: fleet_core::sign_challenge(
                &receipt_keys.private_key_hex,
                &statement.signing_preimage().unwrap(),
            )
            .unwrap(),
            statement,
        };
        let receipt_message = fleet_protocol::WireMessage::new(
            "msg-task-ack-receipt",
            "corr-task-ack-receipt",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        delivery
            .handle_receipt(
                &receipt_message,
                &receipt,
                &config,
                &receipt_keys.public_key_hex,
                "corr-task-ack-receipt",
                &task_state,
            )
            .unwrap();
        let ack_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&ack_key) && Instant::now() < ack_deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&ack_key));
        let [_, agent_id, job_id, task_id, report_id] = started_report.report.key.parts();
        let statement = fleet_protocol::receipt::ReportReceiptStatementWire {
            controller_namespace: namespace.clone(),
            store_epoch: "d".repeat(64),
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex: started_digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: fleet_protocol::receipt::ReportDispositionWire::Stored,
            signing_key_fingerprint: receipt_keys.fingerprint.clone(),
        };
        let started_receipt = fleet_protocol::receipt::SignedReportReceiptWire {
            signature_hex: fleet_core::sign_challenge(
                &receipt_keys.private_key_hex,
                &statement.signing_preimage().unwrap(),
            )
            .unwrap(),
            statement,
        };
        let started_receipt_message = fleet_protocol::WireMessage::new(
            "msg-task-started-receipt",
            "corr-task-started-receipt",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(started_receipt.clone()),
        );
        delivery
            .handle_receipt(
                &started_receipt_message,
                &started_receipt,
                &config,
                &receipt_keys.public_key_hex,
                "corr-task-started-receipt",
                &task_state,
            )
            .unwrap();
        let started_deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&started_key) && Instant::now() < started_deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&started_key));
        let remaining = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].report.class,
            fleet_domain::delivery::ReportClass::FinalResult
        );
        reopened.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_admission_failure_prevents_task_ack_and_command_side_effect() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "7".repeat(64);
        let root = unique_test_dir("command-admission-fail-closed");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, 1024, 1).unwrap();
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, "agent-web-01").unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-command-admission-failure",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };
        let marker = root.join("command-ran");

        assert!(
            run_signed_command_task_queue(
                &session,
                &envelope,
                fleet_protocol::CommandTaskWire {
                    program: "touch".to_owned(),
                    args: vec![marker.to_string_lossy().into_owned()],
                    timeout_ms: 1_000,
                    max_output_bytes: 1024,
                },
            )
            .is_err()
        );
        assert!(!marker.exists());
        assert!(TestOutboundReceiver(outbound).try_recv().is_err());
        drop(journal);
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_agent_process_converts_interrupted_admission_and_start_to_typed_final_reports() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{ExecutionPhase, JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("agent-execution-restart-recovery");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let namespace = "f".repeat(64);
        let identity = ControllerDeliveryIdentity {
            namespace: namespace.clone(),
            store_epoch: "1".repeat(64),
        };
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();

        for (phase, expected_reason, expected_stdout_chunks, expected_truncated) in [
            (
                ExecutionPhase::Admitted,
                "agent_interrupted_before_start",
                0,
                false,
            ),
            (
                ExecutionPhase::StartIntent,
                "execution_outcome_unknown",
                1,
                true,
            ),
        ] {
            let phase_name = match phase {
                ExecutionPhase::Admitted => "admitted",
                ExecutionPhase::StartIntent => "started",
                ExecutionPhase::ResultCommitted => unreachable!(),
            };
            let phase_root = root.join(phase_name);
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&phase_root)
                .unwrap();
            let path = phase_root.join("journal.sqlite3");
            let config = test_agent_config();
            let envelope = test_task_envelope(&config.agent_id);
            let execution = agent_task_execution_record(&namespace, &config, &envelope).unwrap();
            let final_key = execution.snapshot().final_report_key.clone();
            let old_worker = JournalWorker::spawn(
                SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
                capacity,
                limits,
            )
            .unwrap();
            let old_client = old_worker.client();
            assert_eq!(
                old_client
                    .admit(&execution)
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap(),
                fleet_application::delivery::ExecutionAdmission::New
            );
            if phase == ExecutionPhase::StartIntent {
                old_client
                    .start(&final_key)
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap();
                persist_task_output_report(
                    &old_client,
                    &namespace,
                    &config,
                    &envelope,
                    fleet_runner::CommandOutputChunk {
                        stream: fleet_runner::CommandOutputStream::Stdout,
                        sequence: 0,
                        data: "already acknowledged before simulated crash".to_owned(),
                    },
                )
                .unwrap();
                let output = old_client
                    .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap()
                    .into_iter()
                    .find(|entry| entry.report.class == ReportClass::Output)
                    .unwrap();
                old_client
                    .acknowledge(&output.report.key, output.digest)
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap();
            }
            drop(old_client);
            old_worker.shutdown().unwrap();

            let mut config = config;
            config.delivery_journal_path = path;
            let mut runtime = AgentSessionRuntime {
                task_state: test_task_session_state(),
                connection: fleet_agent::AgentSessionSupervisor::new(0),
                outbound_queue: test_outbound_queue(8),
                journal_worker: None,
                journal_namespace: None,
            };
            let journal = ensure_agent_journal_worker(&mut runtime, &config, &identity).unwrap();
            let pending = journal
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                .unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].report.key, final_key);
            assert_eq!(pending[0].report.class, ReportClass::FinalResult);
            let body: serde_json::Value = serde_json::from_slice(pending[0].report.body()).unwrap();
            assert_eq!(body["exit_code"], -1);
            assert_eq!(body["status"], "failed");
            assert_eq!(body["reason"], expected_reason);
            assert_eq!(body["output"]["stdout_chunks"], expected_stdout_chunks);
            assert_eq!(body["output"]["stderr_chunks"], 0);
            assert_eq!(body["output"]["truncated"], expected_truncated);
            assert!(
                journal
                    .interrupted()
                    .unwrap()
                    .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                    .unwrap()
                    .is_none()
            );
            runtime.journal_worker.take().unwrap().shutdown().unwrap();
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn same_process_reconnect_skips_live_owner_then_reconciles_after_owner_ends() {
        use fleet_domain::delivery::ExecutionPhase;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("agent-live-execution-reconnect");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let namespace = "9".repeat(64);
        let identity = ControllerDeliveryIdentity {
            namespace: namespace.clone(),
            store_epoch: "8".repeat(64),
        };
        let mut config = test_agent_config();
        config.delivery_journal_path = root.join("journal.sqlite3");
        let mut runtime = AgentSessionRuntime {
            task_state: test_task_session_state(),
            connection: fleet_agent::AgentSessionSupervisor::new(0),
            outbound_queue: test_outbound_queue(8),
            journal_worker: None,
            journal_namespace: None,
        };
        let journal = ensure_agent_journal_worker(&mut runtime, &config, &identity).unwrap();
        let envelope = test_task_envelope(&config.agent_id);
        let execution = agent_task_execution_record(&namespace, &config, &envelope).unwrap();
        let final_key = execution.snapshot().final_report_key.clone();
        runtime
            .task_state
            .runtime
            .start_task(envelope.task_id.as_str())
            .unwrap();
        runtime.task_state.busy.store(true, Ordering::SeqCst);
        assert_eq!(
            journal
                .admit(&execution)
                .unwrap()
                .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                .unwrap(),
            fleet_application::delivery::ExecutionAdmission::New
        );
        journal
            .start(&final_key)
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();

        let reconnected = ensure_agent_journal_worker(&mut runtime, &config, &identity).unwrap();
        let record = reconnected
            .interrupted()
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap()
            .expect("the still-live task remains marked as active");
        assert_eq!(record.snapshot().phase, ExecutionPhase::StartIntent);
        assert_eq!(
            reconnected
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                .unwrap()
                .len(),
            0
        );
        drop(reconnected);
        runtime
            .task_state
            .runtime
            .finish_task(envelope.task_id.as_str());
        runtime.task_state.busy.store(false, Ordering::SeqCst);
        let after_owner_exit =
            ensure_agent_journal_worker(&mut runtime, &config, &identity).unwrap();
        let recovered = after_owner_exit
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
            .unwrap();
        assert_eq!(recovered.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(recovered[0].report.body()).unwrap();
        assert_eq!(body["reason"], "execution_outcome_unknown");
        assert!(
            after_owner_exit
                .interrupted()
                .unwrap()
                .wait(AGENT_JOURNAL_COMMIT_TIMEOUT)
                .unwrap()
                .is_none()
        );
        drop(after_owner_exit);
        drop(journal);
        runtime.journal_worker.take().unwrap().shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn canceled_before_start_command_final_result_is_journaled_without_legacy_event() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "c".repeat(64);
        let root = unique_test_dir("command-canceled-before-start");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let keys = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = test_agent_config();
        config.controller_fingerprint = keys.fingerprint.clone();
        let now = SystemTime::now();
        let issued_at = now - Duration::from_secs(1);
        let expires_at = now + Duration::from_secs(60);
        let envelope = signed_test_task_envelope(
            &config.agent_id,
            "nonce-canceled-before-start",
            "payload-canceled-before-start",
            &keys.private_key_hex,
            issued_at,
            expires_at,
        );
        let wire_envelope = fleet_protocol::SignedTaskEnvelopeWire {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            target_agent_id: envelope.target_agent_id.as_str().to_owned(),
            issued_at_ms: issued_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            expires_at_ms: expires_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            nonce: envelope.nonce.as_str().to_owned(),
            payload_hash: envelope.payload_hash.clone(),
            signature: envelope.signature.as_ref().unwrap().as_str().to_owned(),
        };
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        task_state
            .runtime
            .start_task(envelope.task_id.as_str())
            .unwrap();
        assert!(
            task_state
                .runtime
                .request_cancel(envelope.task_id.as_str())
                .unwrap()
        );
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: &keys.public_key_hex,
            correlation_id: "corr-canceled-before-start",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        handle_task_assignment_with_queue(
            &session,
            wire_envelope,
            fleet_protocol::TaskWire::Command(fleet_protocol::CommandTaskWire {
                program: "must-not-run".to_owned(),
                args: Vec::new(),
                timeout_ms: 1_000,
                max_output_bytes: 1024,
            }),
        )
        .unwrap();

        assert!(TestOutboundReceiver(outbound.clone()).try_recv().is_err());
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report.class, ReportClass::FinalResult);
        assert_eq!(pending[0].report.key.parts()[4], "final-result");
        assert_eq!(
            pending[0].report.body(),
            br#"{"exit_code":-1,"status":"canceled","reason":"operator requested cancel","artifacts":[],"output":{"stdout_chunks":0,"stderr_chunks":0,"truncated":false}}"#
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn canceled_before_start_runbook_final_result_is_journaled_without_legacy_event() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "g".repeat(64);
        let root = unique_test_dir("runbook-canceled-before-start");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let keys = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = test_agent_config();
        config.controller_fingerprint = keys.fingerprint.clone();
        let now = SystemTime::now();
        let issued_at = now - Duration::from_secs(1);
        let expires_at = now + Duration::from_secs(60);
        let envelope = signed_test_task_envelope(
            &config.agent_id,
            "nonce-runbook-canceled-before-start",
            "payload-runbook-canceled-before-start",
            &keys.private_key_hex,
            issued_at,
            expires_at,
        );
        let wire_envelope = fleet_protocol::SignedTaskEnvelopeWire {
            job_id: envelope.job_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            target_agent_id: envelope.target_agent_id.as_str().to_owned(),
            issued_at_ms: issued_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            expires_at_ms: expires_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            nonce: envelope.nonce.as_str().to_owned(),
            payload_hash: envelope.payload_hash.clone(),
            signature: envelope.signature.as_ref().unwrap().as_str().to_owned(),
        };
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        task_state
            .runtime
            .start_task(envelope.task_id.as_str())
            .unwrap();
        assert!(
            task_state
                .runtime
                .request_cancel(envelope.task_id.as_str())
                .unwrap()
        );
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: &keys.public_key_hex,
            correlation_id: "corr-runbook-canceled-before-start",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        handle_task_assignment_with_queue(
            &session,
            wire_envelope,
            fleet_protocol::TaskWire::RunbookExecution(fleet_protocol::RunbookExecutionTaskWire {
                runbook_document: "apiVersion: [invalid".to_owned(),
                timeout_ms: 1_000,
                confirmed_high_risk: false,
            }),
        )
        .unwrap();

        assert!(TestOutboundReceiver(outbound.clone()).try_recv().is_err());
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report.class, ReportClass::FinalResult);
        assert_eq!(
            pending[0].report.body(),
            br#"{"exit_code":-1,"status":"canceled","reason":"operator requested cancel","artifacts":[],"output":{"stdout_chunks":0,"stderr_chunks":0,"truncated":false}}"#
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn timed_out_persistent_command_journals_final_result_instead_of_legacy_event() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "d".repeat(64);
        let root = unique_test_dir("command-timeout-final-result");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let outbound = test_outbound_queue(4);
        let task_state = test_task_session_state();
        let session = AgentTaskExecutionSession {
            outbound_sender: &outbound,
            config: &config,
            controller_public_key: "unused-in-this-test",
            correlation_id: "corr-timeout-final-result",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        run_signed_command_task_queue(
            &session,
            &envelope,
            fleet_protocol::CommandTaskWire {
                program: "sleep".to_owned(),
                args: vec!["2".to_owned()],
                timeout_ms: 25,
                max_output_bytes: 1024,
            },
        )
        .unwrap();

        let receiver = TestOutboundReceiver(outbound);
        assert!(receiver.try_recv().is_err());
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-ack")
        );
        assert!(pending.iter().any(|entry| {
            entry.report.key.parts()[4] == "task-started"
                && entry.report.body() == br#"{"event":"task_started"}"#
        }));
        let final_result = pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("timed-out command result is committed to the journal");
        let body: serde_json::Value = serde_json::from_slice(final_result.report.body()).unwrap();
        assert_eq!(body["exit_code"], -1);
        assert_eq!(body["status"], "timed_out");
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journaled_command_output_replays_after_reopen_and_stale_restore_epoch_receipt_cannot_clean_it()
     {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::PendingReport;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_protocol::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let namespace = "a".repeat(64);
        let store_epoch = "b".repeat(64);
        let restored_store_epoch = "c".repeat(64);
        let root = unique_test_dir("command-output-reconnect-replay");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let first_client = worker.client();
        persist_task_output_report(
            &first_client,
            &namespace,
            &config,
            &envelope,
            fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stdout,
                sequence: 0,
                data: "durable across disconnect".to_owned(),
            },
        )
        .unwrap();
        let first_pending = first_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(first_pending.len(), 1);
        let old_session_message =
            agent_journal_report_wire_message(&first_pending[0], &config, "corr-before-reconnect")
                .unwrap();
        drop(first_pending);
        drop(first_client);
        worker.shutdown().unwrap();

        let mut config = config;
        let reopened_worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = reopened_worker.client();
        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        let new_session_message =
            agent_journal_report_wire_message(&pending[0], &config, "corr-after-reconnect")
                .unwrap();
        assert_eq!(
            old_session_message.correlation_id.0,
            "corr-before-reconnect"
        );
        assert_eq!(new_session_message.correlation_id.0, "corr-after-reconnect");
        assert_ne!(
            old_session_message.message_id,
            new_session_message.message_id
        );
        let fleet_protocol::WirePayload::TaskReport(old_report) = old_session_message.payload
        else {
            panic!("expected v2 task report");
        };
        let fleet_protocol::WirePayload::TaskReport(new_report) = new_session_message.payload
        else {
            panic!("expected v2 task report");
        };
        assert_eq!(old_report, new_report);
        assert_eq!(
            new_report.body_bytes().unwrap(),
            br#"{"stream":"stdout","sequence":0,"data":"durable across disconnect"}"#
        );

        let pending: PendingReport = pending[0].clone();
        let key = pending.report.key.clone();
        let mut delivery = AgentJournalReportDelivery::new(
            client.clone(),
            ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: restored_store_epoch.clone(),
            },
        );
        delivery.pending.insert(
            key.clone(),
            AgentPendingJournalReport {
                report: pending.clone(),
                attempts: 1,
                retry_at: Instant::now() + Duration::from_secs(30),
            },
        );

        let keys = fleet_core::generate_agent_key_pair().unwrap();
        config.controller_fingerprint = keys.fingerprint.clone();
        let [_, agent_id, job_id, task_id, report_id] = pending.report.key.parts();
        let digest_hex = pending
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let stale_statement = ReportReceiptStatementWire {
            controller_namespace: namespace.clone(),
            store_epoch: store_epoch.clone(),
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let stale_signature_hex = fleet_core::sign_challenge(
            &keys.private_key_hex,
            &stale_statement.signing_preimage().unwrap(),
        )
        .unwrap();
        let stale_receipt = SignedReportReceiptWire {
            statement: stale_statement,
            signature_hex: stale_signature_hex,
        };
        let task_state = test_task_session_state();

        let stale_message = fleet_protocol::WireMessage::new(
            "msg-stale-restore-receipt",
            "corr-after-reconnect",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(stale_receipt.clone()),
        );
        assert!(
            delivery
                .handle_receipt(
                    &stale_message,
                    &stale_receipt,
                    &config,
                    &keys.public_key_hex,
                    "corr-after-reconnect",
                    &task_state,
                )
                .is_err(),
            "a receipt from the pre-restore epoch cannot authorize local cleanup"
        );
        assert!(delivery.pending.contains_key(&key));
        assert_eq!(
            client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .len(),
            1,
            "the exact report remains durable for replay in the restored epoch"
        );

        let statement = ReportReceiptStatementWire {
            controller_namespace: namespace,
            store_epoch: restored_store_epoch,
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex: pending
                .digest
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            signed_at_ms: epoch_millis() as u64,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let signature_hex = fleet_core::sign_challenge(
            &keys.private_key_hex,
            &statement.signing_preimage().unwrap(),
        )
        .unwrap();
        let receipt = SignedReportReceiptWire {
            statement,
            signature_hex,
        };

        let wrong_correlation = fleet_protocol::WireMessage::new(
            "msg-wrong-correlation",
            "corr-not-current",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        assert!(
            delivery
                .handle_receipt(
                    &wrong_correlation,
                    &receipt,
                    &config,
                    &keys.public_key_hex,
                    "corr-after-reconnect",
                    &task_state,
                )
                .is_err()
        );

        let mut forged = receipt.clone();
        forged.signature_hex = "0".repeat(128);
        let forged_message = fleet_protocol::WireMessage::new(
            "msg-forged-receipt",
            "corr-after-reconnect",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(forged.clone()),
        );
        assert!(
            delivery
                .handle_receipt(
                    &forged_message,
                    &forged,
                    &config,
                    &keys.public_key_hex,
                    "corr-after-reconnect",
                    &task_state,
                )
                .is_err()
        );
        assert_eq!(
            client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .len(),
            1
        );

        let valid_message = fleet_protocol::WireMessage::new(
            "msg-valid-receipt",
            "corr-after-reconnect",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        delivery
            .handle_receipt(
                &valid_message,
                &receipt,
                &config,
                &keys.public_key_hex,
                "corr-after-reconnect",
                &task_state,
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&key) && Instant::now() < deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&key));
        assert!(
            client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        reopened_worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn agent_journal_worker_commits_reopens_and_confirms_real_sqlite_reports() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::JournalReport;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass, ReportKey};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("journal-worker-integration");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 4096,
                bytes: 64 * 1024 * 1024,
            },
            JournalUsage {
                reports: 4,
                bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, 64 * 1024 * 1024, 8 * 1024 * 1024).unwrap();
        let report = JournalReport::new(
            ReportKey::new(
                "controller-fixture",
                "agent-fixture",
                "job-fixture",
                "task-fixture",
                "report-fixture",
            )
            .unwrap(),
            ReportClass::Output,
            vec![b'x'; 4096],
        )
        .unwrap();
        let repository =
            SqliteAgentJournal::open(&path, "controller-fixture", "agent-fixture").unwrap();
        let worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        worker
            .client()
            .append(&report)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        worker.shutdown().unwrap();

        let repository =
            SqliteAgentJournal::open(&path, "controller-fixture", "agent-fixture").unwrap();
        let worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        let client = worker.client();
        let pending = client
            .pending(16, 1024 * 1024)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report, report);
        assert!(
            client
                .acknowledge(&report.key, pending[0].digest)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
        );
        assert!(
            client
                .pending(16, 1024 * 1024)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_drift_evidence_report_is_journaled_and_replays_exactly_after_reopen() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_protocol::delivery_v2::{V2DriftEvidenceReportBody, V2DriftStatusWire};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("drift-evidence-journal-reopen");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let namespace = "a".repeat(64);
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let body = V2DriftEvidenceReportBody {
            status: V2DriftStatusWire::Drifted,
            expected: "nginx=running".to_owned(),
            actual: "nginx=stopped".to_owned(),
        };
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let client = worker.client();
        persist_agent_drift_evidence_report(&client, &namespace, &config, &envelope, &body)
            .unwrap();
        let first_pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(first_pending.len(), 1);
        let first = &first_pending[0];
        assert_eq!(first.report.class, ReportClass::DriftEvidence);
        assert_eq!(first.report.key.parts()[4], "drift-evidence");
        assert_eq!(
            first.report.body(),
            br#"{"status":"drifted","expected":"nginx=running","actual":"nginx=stopped"}"#
        );
        let before_reopen =
            agent_journal_report_wire_message(&first_pending[0], &config, "before").unwrap();
        worker.shutdown().unwrap();

        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let pending = worker
            .client()
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending, first_pending);
        let after_reopen =
            agent_journal_report_wire_message(&pending[0], &config, "after").unwrap();
        assert_ne!(before_reopen.message_id, after_reopen.message_id);
        let fleet_protocol::WirePayload::TaskReport(before) = before_reopen.payload else {
            panic!("expected durable task report before reopen");
        };
        let fleet_protocol::WirePayload::TaskReport(after) = after_reopen.payload else {
            panic!("expected durable task report after reopen");
        };
        assert_eq!(before, after);
        assert_eq!(
            after.class,
            fleet_protocol::delivery_v2::V2ReportClassWire::DriftEvidence
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_drift_check_terminal_result_is_journaled_and_replays_after_reopen() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass};
        use fleet_protocol::delivery_v2::V2FinalResultReportBody;
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("drift-final-result-journal-reopen");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("journal.sqlite3");
        let namespace = "c".repeat(64);
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let policy_document = r#"
apiVersion: fleet.sponzey.dev/v1alpha1
kind: Policy
metadata:
  name: nginx-running
spec:
  selector:
    matchLabels:
      role: web
  checks:
    - id: nginx-service
      service:
        name: nginx
        state: running
"#;
        let worker = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let journal = worker.client();
        let sender = test_outbound_queue(8);
        let session = AgentTaskExecutionSession {
            outbound_sender: &sender,
            config: &config,
            controller_public_key: "controller-public-key",
            correlation_id: "corr-drift-final",
            task_state: &test_task_session_state(),
            journal_client: &journal,
            controller_namespace: &namespace,
        };
        persist_agent_task_ack_report(&session, &envelope).unwrap();
        run_signed_drift_check_task_queue(
            &session,
            &envelope,
            fleet_protocol::DriftCheckTaskWire {
                policy_document: policy_document.to_owned(),
            },
        )
        .unwrap();

        assert!(TestOutboundReceiver(sender).try_recv().is_err());
        let first_pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        let final_result = first_pending
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .expect("terminal DriftCheck result is durable");
        assert_eq!(final_result.report.key.parts()[4], "final-result");
        let parsed: V2FinalResultReportBody =
            serde_json::from_slice(final_result.report.body()).unwrap();
        assert_eq!(parsed.status, fleet_protocol::TaskResultStatus::Succeeded);
        assert_eq!(parsed.output.stdout_chunks, 0);
        assert_eq!(parsed.output.stderr_chunks, 0);
        assert!(!parsed.output.truncated);
        let first_wire =
            agent_journal_report_wire_message(final_result, &config, "before").unwrap();
        worker.shutdown().unwrap();

        let reopened = JournalWorker::spawn(
            SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap(),
            capacity,
            limits,
        )
        .unwrap();
        let replayed = reopened
            .client()
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(replayed, first_pending);
        let replayed_final = replayed
            .iter()
            .find(|entry| entry.report.class == ReportClass::FinalResult)
            .unwrap();
        let replayed_wire =
            agent_journal_report_wire_message(replayed_final, &config, "after").unwrap();
        let fleet_protocol::WirePayload::TaskReport(first_wire_report) = first_wire.payload else {
            panic!("expected v2 final-result report");
        };
        let fleet_protocol::WirePayload::TaskReport(replayed_wire_report) = replayed_wire.payload
        else {
            panic!("expected replayed v2 final-result report");
        };
        assert_eq!(first_wire_report, replayed_wire_report);
        assert_eq!(
            replayed_wire_report.class,
            fleet_protocol::delivery_v2::V2ReportClassWire::FinalResult
        );
        let reopened_client = reopened.client();
        let mut invalid_envelope = envelope.clone();
        invalid_envelope.job_id = fleet_domain::JobId::new("job-drift-invalid").unwrap();
        invalid_envelope.task_id = fleet_domain::TaskId::new("task-drift-invalid").unwrap();
        let invalid_sender = test_outbound_queue(4);
        let invalid_task_state = test_task_session_state();
        let invalid_session = AgentTaskExecutionSession {
            outbound_sender: &invalid_sender,
            config: &config,
            controller_public_key: "controller-public-key",
            correlation_id: "corr-drift-invalid",
            task_state: &invalid_task_state,
            journal_client: &reopened_client,
            controller_namespace: &namespace,
        };
        persist_agent_task_ack_report(&invalid_session, &invalid_envelope).unwrap();
        run_signed_drift_check_task_queue(
            &invalid_session,
            &invalid_envelope,
            fleet_protocol::DriftCheckTaskWire {
                policy_document: "kind: invalid-policy".to_owned(),
            },
        )
        .unwrap();
        assert!(TestOutboundReceiver(invalid_sender).try_recv().is_err());
        let after_invalid = reopened_client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        let failed_result = after_invalid
            .iter()
            .find(|entry| {
                entry.report.key.parts()[1..4]
                    == [
                        config.agent_id.as_str(),
                        "job-drift-invalid",
                        "task-drift-invalid",
                    ]
                    && entry.report.class == ReportClass::FinalResult
            })
            .expect("invalid DriftCheck policy also has a durable final result");
        let failed_body: V2FinalResultReportBody =
            serde_json::from_slice(failed_result.report.body()).unwrap();
        assert_eq!(failed_body.status, fleet_protocol::TaskResultStatus::Failed);
        assert_eq!(failed_body.output.stdout_chunks, 0);
        assert_eq!(failed_body.output.stderr_chunks, 0);
        reopened.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "manual seven-sample durable journal/worker baseline"]
    fn durable_output_delivery_baseline() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::JournalReport;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage, ReportClass, ReportKey};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir("durable-output-baseline");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 4096,
                bytes: 64 * 1024 * 1024,
            },
            JournalUsage {
                reports: 4,
                bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, 64 * 1024 * 1024, 8 * 1024 * 1024).unwrap();
        let body = "x".repeat(4096);
        for sample in 0..7 {
            let path = root.join(format!("sample-{sample}.sqlite3"));
            let worker = JournalWorker::spawn(
                SqliteAgentJournal::open(&path, "controller-baseline", "agent-1").unwrap(),
                capacity,
                limits,
            )
            .unwrap();
            let client = worker.client();
            let mut tickets = Vec::new();
            let mut wire_bytes = 0;
            let started = std::time::Instant::now();
            for sequence in 0..256 {
                let message_id = format!("msg-output-{sequence}");
                let message = fleet_protocol::WireMessage::new(
                    message_id.clone(),
                    "corr-baseline",
                    Some("agent-1".to_owned()),
                    1,
                    fleet_protocol::WirePayload::OutputChunk {
                        job_id: "job-baseline".to_owned(),
                        task_id: "task-baseline".to_owned(),
                        stream: fleet_protocol::OutputStream::Stdout,
                        sequence,
                        data: body.clone(),
                    },
                );
                let encoded = fleet_protocol::encode_message(&message)
                    .unwrap()
                    .into_bytes();
                wire_bytes += encoded.len();
                let report = JournalReport::new(
                    ReportKey::new(
                        "controller-baseline",
                        "agent-1",
                        "job-baseline",
                        "task-baseline",
                        &message_id,
                    )
                    .unwrap(),
                    ReportClass::Output,
                    encoded,
                )
                .unwrap();
                tickets.push(client.append(&report).unwrap());
                if tickets.len() == 16 {
                    for ticket in tickets.drain(..) {
                        ticket.wait(Duration::from_secs(5)).unwrap();
                    }
                }
            }
            let commit_us = started.elapsed().as_micros();
            assert!(tickets.is_empty());
            worker.shutdown().unwrap();
            let reopened = std::time::Instant::now();
            let worker = JournalWorker::spawn(
                SqliteAgentJournal::open(&path, "controller-baseline", "agent-1").unwrap(),
                capacity,
                limits,
            )
            .unwrap();
            let client = worker.client();
            let pending = client
                .pending(256, 8 * 1024 * 1024)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap();
            let reopen_replay_us = reopened.elapsed().as_micros();
            assert_eq!(pending.len(), 256);
            assert_eq!(
                pending
                    .iter()
                    .map(|report| report.report.body().len())
                    .sum::<usize>(),
                wire_bytes
            );
            let started = std::time::Instant::now();
            let mut acknowledgements = Vec::new();
            for report in &pending {
                acknowledgements.push(
                    client
                        .acknowledge(&report.report.key, report.digest)
                        .unwrap(),
                );
                if acknowledgements.len() == 16 {
                    for ticket in acknowledgements.drain(..) {
                        assert!(ticket.wait(Duration::from_secs(5)).unwrap());
                    }
                }
            }
            let ack_us = started.elapsed().as_micros();
            assert!(
                client
                    .pending(1, 8 * 1024 * 1024)
                    .unwrap()
                    .wait(Duration::from_secs(5))
                    .unwrap()
                    .is_empty()
            );
            worker.shutdown().unwrap();
            println!(
                "durable_journal_baseline sample={sample} frames=256 payload_bytes=1048576 wire_bytes={wire_bytes} worker_requests=16 commit_us={commit_us} reopen_replay_us={reopen_replay_us} ack_us={ack_us}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "manual seven-sample legacy queue/serialization baseline"]
    fn legacy_output_delivery_baseline() {
        let body = "x".repeat(4096);
        for sample in 0..7 {
            let queue = test_outbound_queue(32);
            let mut frames = 0;
            let mut wire_bytes = 0;
            let started = std::time::Instant::now();
            for sequence in 0..256 {
                enqueue_wire_message(
                    &queue,
                    fleet_protocol::WireMessage::new(
                        format!("msg-output-{sequence}"),
                        "corr-baseline",
                        Some("agent-1".to_owned()),
                        1,
                        fleet_protocol::WirePayload::OutputChunk {
                            job_id: "job-baseline".to_owned(),
                            task_id: "task-baseline".to_owned(),
                            stream: fleet_protocol::OutputStream::Stdout,
                            sequence,
                            data: body.clone(),
                        },
                    ),
                )
                .unwrap();
                if sequence % 32 == 31 {
                    flush_agent_outbound_queue_with(&queue, |message| {
                        wire_bytes += fleet_protocol::encode_message(message).unwrap().len();
                        frames += 1;
                        Ok(())
                    })
                    .unwrap();
                }
            }
            let elapsed_us = started.elapsed().as_micros();
            assert_eq!(frames, 256);
            assert!(wire_bytes > 1024 * 1024);
            assert!(queue.lock().unwrap().pending_report().is_none());
            println!(
                "legacy_queue_baseline sample={sample} frames={frames} payload_bytes=1048576 wire_bytes={wire_bytes} capacity=32 elapsed_us={elapsed_us}"
            );
        }
    }

    #[test]
    fn legacy_successful_outbound_write_removes_result_without_storage_receipt() {
        let queue = test_outbound_queue(1);
        let result = fleet_protocol::WireMessage::new(
            "msg-result-before-receipt",
            "corr-result",
            Some("agent-1".to_owned()),
            1,
            fleet_protocol::WirePayload::TaskResult {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
                exit_code: 0,
                status: Some(fleet_protocol::TaskResultStatus::Succeeded),
                reason: String::new(),
                artifacts: Vec::new(),
            },
        );
        enqueue_wire_message(&queue, result.clone()).unwrap();

        // A local socket handoff is the only success signal on the legacy path.
        let mut handed_off = Vec::new();
        flush_agent_outbound_queue_with(&queue, |message| {
            handed_off.push(message.clone());
            Ok(())
        })
        .unwrap();

        assert_eq!(handed_off, vec![result]);
        assert!(queue.lock().unwrap().pending_report().is_none());
        let mut replay_count = 0;
        flush_agent_outbound_queue_with(&queue, |_| {
            replay_count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(replay_count, 0);
    }

    #[test]
    fn agent_session_read_interrupt_is_idle_not_a_session_failure() {
        let interrupted =
            tungstenite::Error::Io(std::io::Error::from(std::io::ErrorKind::Interrupted));

        assert!(agent_session_read_error_is_idle(&interrupted));
    }

    #[test]
    fn handshake_read_interrupt_is_retryable_but_timeout_is_not() {
        let interrupted =
            tungstenite::Error::Io(std::io::Error::from(std::io::ErrorKind::Interrupted));
        let timed_out = tungstenite::Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));

        assert!(handshake_read_error_is_retryable(&interrupted));
        assert!(!handshake_read_error_is_retryable(&timed_out));
    }

    #[test]
    fn agent_capability_names_use_explicit_probe_input() {
        let probe = AgentCapabilityProbe {
            privilege_level: fleet_protocol::CapabilityPrivilegeLevelWire::SudoAvailable,
            package_manager: Some(fleet_protocol::PackageManagerWire::Apt),
            service_manager: Some(fleet_protocol::ServiceManagerWire::Systemd),
        };

        let capabilities = agent_capability_names(&probe);

        assert!(capabilities.contains(&"persistent_session".to_owned()));
        assert!(capabilities.contains(&"command_execution".to_owned()));
        assert!(capabilities.contains(&"drift_check".to_owned()));
        assert!(capabilities.contains(&"runbook_execution".to_owned()));
        assert!(capabilities.contains(&"package_install".to_owned()));
        assert!(capabilities.contains(&"service_control".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn agent_session_busy_task_rejects_new_assignment() {
        let config = test_agent_config();
        let (root, namespace, worker) = test_agent_journal("busy-rejection", &config);
        let journal_client = worker.client();
        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let task_state = AgentTaskSessionState {
            busy: Arc::new(AtomicBool::new(true)),
            runtime: Arc::new(AgentTaskRuntimeState::default()),
            replay_guard: Arc::new(Mutex::new(fleet_runner::NonceReplayGuard::default())),
            controller_trust_bundle: Arc::new(Mutex::new(None)),
            journal_client: Arc::new(Mutex::new(Some(journal_client.clone()))),
            delivery_identity: Arc::new(Mutex::new(Some(ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: "e".repeat(64),
            }))),
        };

        handle_agent_session_message(
            test_task_assignment_message(&config.agent_id),
            &config,
            "controller-public-key",
            "corr-test",
            &sender,
            &task_state,
        )
        .unwrap();

        assert!(
            receiver.try_recv().is_err(),
            "rejection must not use control queue"
        );
        let pending = journal_client
            .pending(16, 8 * 1024 * 1024)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].report.key.parts(),
            [
                namespace.as_str(),
                "agent-web-01",
                "job-test",
                "task-test",
                "task-rejected"
            ]
        );
        assert_eq!(
            pending[0].report.body(),
            br#"{"event":"task_rejected","reason_code":"agent_busy","reason":"agent is busy"}"#
        );
        assert!(task_state.busy.load(Ordering::SeqCst));
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_task_rejection_replays_after_reopen_and_cleans_only_after_signed_receipt() {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_application::delivery::PendingReport;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_protocol::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };
        use fleet_store::agent_journal::SqliteAgentJournal;

        let config = test_agent_config();
        let (root, namespace, worker) = test_agent_journal("rejected-replay", &config);
        let client = worker.client();
        let envelope = test_task_envelope(&config.agent_id);
        persist_agent_task_rejected_report_with_journal(
            &client,
            &namespace,
            &config,
            envelope.job_id.as_str(),
            envelope.task_id.as_str(),
            fleet_protocol::TaskRejectionReasonCode::LocalPolicy,
            "local policy blocked token=topsecret",
        )
        .unwrap();
        worker.shutdown().unwrap();
        drop(client);

        let limits = JournalWorkerLimits::new(16, 64 * 1024 * 1024, 8 * 1024 * 1024).unwrap();
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 4096,
                bytes: 64 * 1024 * 1024,
            },
            JournalUsage {
                reports: 4,
                bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        let repository =
            SqliteAgentJournal::open(&root.join("journal.sqlite3"), &namespace, &config.agent_id)
                .unwrap();
        let reopened_worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        let client = reopened_worker.client();
        let pending = client
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report.key.parts()[4], "task-rejected");
        assert_eq!(
            pending[0].report.body(),
            br#"{"event":"task_rejected","reason_code":"local_policy","reason":"local policy blocked token=[REDACTED]"}"#
        );

        let pending: PendingReport = pending[0].clone();
        let key = pending.report.key.clone();
        let mut delivery = AgentJournalReportDelivery::new(
            client.clone(),
            ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: "e".repeat(64),
            },
        );
        delivery.pending.insert(
            key.clone(),
            AgentPendingJournalReport {
                report: pending.clone(),
                attempts: 0,
                retry_at: Instant::now(),
            },
        );
        let keys = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = config;
        config.controller_fingerprint = keys.fingerprint.clone();
        let [_, agent_id, job_id, task_id, report_id] = pending.report.key.parts();
        let digest_hex = pending
            .digest
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let statement = ReportReceiptStatementWire {
            controller_namespace: namespace,
            store_epoch: "e".repeat(64),
            agent_id: agent_id.to_owned(),
            job_id: job_id.to_owned(),
            task_id: task_id.to_owned(),
            report_id: report_id.to_owned(),
            digest_hex,
            signed_at_ms: epoch_millis() as u64,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let signature_hex = fleet_core::sign_challenge(
            &keys.private_key_hex,
            &statement.signing_preimage().unwrap(),
        )
        .unwrap();
        let receipt = SignedReportReceiptWire {
            statement,
            signature_hex,
        };
        let message = fleet_protocol::WireMessage::new(
            "msg-task-rejected-receipt",
            "corr-task-rejected-reconnect",
            Some(config.agent_id.clone()),
            epoch_millis() as u64,
            fleet_protocol::WirePayload::ReportReceipt(receipt.clone()),
        );
        delivery
            .handle_receipt(
                &message,
                &receipt,
                &config,
                &keys.public_key_hex,
                "corr-task-rejected-reconnect",
                &test_task_session_state(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while delivery.pending.contains_key(&key) && Instant::now() < deadline {
            delivery.poll_acknowledgements().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!delivery.pending.contains_key(&key));
        assert!(
            client
                .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
                .unwrap()
                .wait(Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        reopened_worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_task_runtime_cancel_only_matches_current_task() {
        let runtime = AgentTaskRuntimeState::default();

        runtime.start_task("task-current").unwrap();

        assert!(!runtime.request_cancel("task-other").unwrap());
        assert!(!runtime.should_cancel("task-current"));
        assert!(runtime.request_cancel("task-current").unwrap());
        assert!(runtime.should_cancel("task-current"));
        assert!(!runtime.should_cancel("task-other"));

        runtime.finish_task("task-current");

        assert!(!runtime.should_cancel("task-current"));
    }

    #[test]
    fn command_execution_result_maps_cancel_timeout_and_failure() {
        let (_, canceled_status, _) =
            command_execution_result(Err(fleet_runner::RunnerError::Canceled));
        let (_, timeout_status, _) =
            command_execution_result(Err(fleet_runner::RunnerError::Timeout));
        let (_, failed_status, _) = command_execution_result(Ok(fleet_runner::CommandOutput {
            stdout: String::new(),
            stderr: "failed".to_owned(),
            exit_code: 2,
            truncated: false,
        }));

        assert_eq!(canceled_status, fleet_protocol::TaskResultStatus::Canceled);
        assert_eq!(timeout_status, fleet_protocol::TaskResultStatus::TimedOut);
        assert_eq!(failed_status, fleet_protocol::TaskResultStatus::Failed);
    }

    #[test]
    fn command_execution_result_preserves_program_start_failure_for_agent_output() {
        let (output, status, reason) = command_execution_result(Err(
            fleet_runner::RunnerError::Io("No such file or directory (os error 2)".to_owned()),
        ));

        assert_eq!(status, fleet_protocol::TaskResultStatus::Failed);
        assert_eq!(output.exit_code, -1);
        assert_eq!(
            output.stderr,
            "runner io error: No such file or directory (os error 2)"
        );
        assert_eq!(reason, output.stderr);
    }

    #[cfg(unix)]
    #[test]
    fn agent_session_due_telemetry_does_not_precede_inbound_task_handling() {
        let config = test_agent_config();
        let (root, namespace, worker) = test_agent_journal("rejection-telemetry", &config);
        let journal_client = worker.client();
        let sender = test_outbound_queue(8);
        let receiver = TestOutboundReceiver(sender.clone());
        let task_state = AgentTaskSessionState {
            busy: Arc::new(AtomicBool::new(true)),
            runtime: Arc::new(AgentTaskRuntimeState::default()),
            replay_guard: Arc::new(Mutex::new(fleet_runner::NonceReplayGuard::default())),
            controller_trust_bundle: Arc::new(Mutex::new(None)),
            journal_client: Arc::new(Mutex::new(Some(journal_client.clone()))),
            delivery_identity: Arc::new(Mutex::new(Some(ControllerDeliveryIdentity {
                namespace: namespace.clone(),
                store_epoch: "e".repeat(64),
            }))),
        };

        handle_agent_session_message(
            test_task_assignment_message(&config.agent_id),
            &config,
            "controller-public-key",
            "corr-test",
            &sender,
            &task_state,
        )
        .unwrap();
        enqueue_agent_session_tick_messages(
            &sender,
            &config,
            "corr-test",
            AgentSessionTickActions {
                heartbeat: true,
                facts: true,
                metrics: true,
                log: true,
            },
        )
        .unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::Heartbeat { .. }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::FactsSnapshot { .. }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::MetricsSnapshot { .. }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::LogChunk { ref line, .. }
            if line.contains("agent_heartbeat_completed")
        ));
        let pending = journal_client
            .pending(16, 8 * 1024 * 1024)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report.key.parts()[4], "task-rejected");
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_session_task_worker_output_uses_outbound_queue() {
        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);

        send_agent_output_chunk_queue(
            &sender,
            &config,
            "corr-test",
            &envelope,
            fleet_runner::CommandOutputChunk {
                stream: fleet_runner::CommandOutputStream::Stdout,
                sequence: 7,
                data: "hello".to_owned(),
            },
        )
        .unwrap();
        send_agent_task_result_queue_report(
            &sender,
            &config,
            "corr-test",
            &envelope,
            AgentTaskResultReport::new(0, fleet_protocol::TaskResultStatus::Succeeded, ""),
        )
        .unwrap();
        send_agent_security_event_queue(&sender, &config, "corr-test", "task_checked", "ok")
            .unwrap();

        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::OutputChunk { sequence: 7, .. }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::TaskResult { exit_code: 0, .. }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            fleet_protocol::WirePayload::SecurityEvent { ref action, .. } if action == "task_checked"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn missing_program_task_commits_stderr_and_final_result_before_delivery() {
        use fleet_agent::journal_worker::JournalWorker;
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);
        let task_state = test_task_session_state();
        let namespace = "b".repeat(64);
        let root = unique_test_dir("missing-command-journal");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let repository =
            SqliteAgentJournal::open(&root.join("journal.sqlite3"), &namespace, &config.agent_id)
                .unwrap();
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: AGENT_JOURNAL_MAX_REPORTS,
                bytes: AGENT_JOURNAL_MAX_BYTES,
            },
            JournalUsage {
                reports: AGENT_JOURNAL_FINAL_RESERVE_REPORTS,
                bytes: AGENT_JOURNAL_FINAL_RESERVE_BYTES,
            },
        )
        .unwrap();
        let limits = fleet_agent::journal_worker::JournalWorkerLimits::new(
            AGENT_JOURNAL_WORKER_REQUESTS,
            AGENT_JOURNAL_MAX_BYTES,
            AGENT_JOURNAL_WORKER_REQUEST_BYTES,
        )
        .unwrap();
        let worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        let journal = worker.client();
        let session = AgentTaskExecutionSession {
            outbound_sender: &sender,
            config: &config,
            controller_public_key: "controller-public-key",
            correlation_id: "corr-test",
            task_state: &task_state,
            journal_client: &journal,
            controller_namespace: &namespace,
        };

        run_signed_command_task_queue(
            &session,
            &envelope,
            fleet_protocol::CommandTaskWire {
                program: "fleet-program-that-does-not-exist".to_owned(),
                args: Vec::new(),
                timeout_ms: 1_000,
                max_output_bytes: 1_024,
            },
        )
        .expect("failed program should report a task result");

        assert!(receiver.try_recv().is_err());
        let pending = journal
            .pending(AGENT_REPORT_BATCH_SIZE, AGENT_REPORT_BATCH_BYTES)
            .unwrap()
            .wait(Duration::from_secs(5))
            .unwrap();
        assert_eq!(pending.len(), 4);
        assert!(
            pending
                .iter()
                .any(|entry| entry.report.key.parts()[4] == "task-ack")
        );
        assert!(pending.iter().any(|entry| {
            entry.report.key.parts()[4] == "task-started"
                && entry.report.body() == br#"{"event":"task_started"}"#
        }));
        let output = pending
            .iter()
            .find(|entry| entry.report.class == fleet_domain::delivery::ReportClass::Output)
            .expect("stderr output is committed before final result");
        let output_body: serde_json::Value = serde_json::from_slice(output.report.body()).unwrap();
        assert_eq!(output_body["stream"], "stderr");
        assert_eq!(output_body["sequence"], 0);
        assert!(
            output_body["data"]
                .as_str()
                .unwrap()
                .contains("runner io error")
        );
        let final_result = pending
            .iter()
            .find(|entry| entry.report.class == fleet_domain::delivery::ReportClass::FinalResult)
            .expect("failed result is committed to the journal");
        let final_body: serde_json::Value =
            serde_json::from_slice(final_result.report.body()).unwrap();
        assert_eq!(final_body["exit_code"], -1);
        assert_eq!(final_body["status"], "failed");
        assert!(
            final_body["reason"]
                .as_str()
                .unwrap()
                .contains("runner io error")
        );
        worker.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trust_bundle_update_wire_maps_to_domain_current_previous_bundle() {
        let entries = vec![
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-new".to_owned(),
                public_key: "controller-public-new".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-old".to_owned(),
                public_key: "controller-public-old".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Previous,
                valid_from_ms: 10_000,
                valid_until_ms: Some(20_000),
            },
        ];

        let bundle = controller_signing_trust_bundle_from_wire(&entries).unwrap();

        assert_eq!(bundle.entries().len(), 2);
        assert_eq!(
            bundle.entries()[0].role(),
            fleet_domain::ControllerSigningTrustRole::Current
        );
        assert_eq!(
            bundle.entries()[1].role(),
            fleet_domain::ControllerSigningTrustRole::Previous
        );
    }

    #[test]
    fn trust_bundle_update_rejects_duplicate_fingerprint_without_key_leak() {
        let entries = vec![
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-duplicate".to_owned(),
                public_key: "private-material-like-public-a".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-duplicate".to_owned(),
                public_key: "private-material-like-public-b".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Previous,
                valid_from_ms: 10_000,
                valid_until_ms: Some(20_000),
            },
        ];

        let error = controller_signing_trust_bundle_from_wire(&entries)
            .expect_err("duplicate fingerprint should fail")
            .to_string();

        assert!(error.contains("duplicate"));
        assert!(!error.contains("private-material-like-public"));
    }

    #[test]
    fn trust_bundle_update_rejects_invalid_previous_window_without_key_leak() {
        let entries = vec![
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-new".to_owned(),
                public_key: "controller-public-new".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-old".to_owned(),
                public_key: "private-material-like-public-old".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Previous,
                valid_from_ms: 20_000,
                valid_until_ms: Some(10_000),
            },
        ];

        let error = controller_signing_trust_bundle_from_wire(&entries)
            .expect_err("invalid previous trust window should fail")
            .to_string();

        assert!(error.contains("time window"));
        assert!(!error.contains("private-material-like-public-old"));
    }

    #[test]
    fn trust_bundle_update_rejects_previous_entry_without_expiry() {
        let entries = vec![
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-new".to_owned(),
                public_key: "controller-public-new".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-old".to_owned(),
                public_key: "controller-public-old".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Previous,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
        ];

        let error = controller_signing_trust_bundle_from_wire(&entries)
            .expect_err("previous trust entry without expiry should fail")
            .to_string();

        assert!(error.contains("previous controller signing trust entry requires an expiry"));
    }

    #[test]
    fn agent_controller_signing_trust_bundle_update_applies_in_memory_without_env() {
        let task_state = test_task_session_state();
        let entries = vec![fleet_protocol::ControllerSigningTrustEntryWire {
            fingerprint: "controller-fp-new".to_owned(),
            public_key: "controller-public-new".to_owned(),
            role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
            valid_from_ms: 10_000,
            valid_until_ms: None,
        }];

        apply_agent_controller_signing_trust_bundle_update(&task_state, &entries, None).unwrap();
        let bundle = agent_controller_signing_trust_bundle(
            &task_state,
            &test_agent_config(),
            "legacy-controller-public",
        )
        .unwrap();

        assert_eq!(bundle.entries().len(), 1);
        assert_eq!(
            bundle.entries()[0].fingerprint().as_str(),
            "controller-fp-new"
        );
        assert_eq!(
            bundle.entries()[0].public_key().as_str(),
            "controller-public-new"
        );
    }

    #[test]
    fn agent_controller_signing_trust_bundle_update_emits_ack_without_material() {
        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let config = test_agent_config();
        fs::create_dir_all(config.controller_trust_bundle_path.parent().unwrap()).unwrap();
        let task_state = test_task_session_state();
        let entries = vec![fleet_protocol::ControllerSigningTrustEntryWire {
            fingerprint: "controller-fp-new".to_owned(),
            public_key: "controller-public-new".to_owned(),
            role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
            valid_from_ms: 10_000,
            valid_until_ms: None,
        }];
        let message = fleet_protocol::WireMessage::new(
            "msg-trust-update",
            "corr-trust-update",
            Some(config.agent_id.clone()),
            10_000,
            fleet_protocol::WirePayload::ControllerSigningTrustBundleUpdate { entries },
        );

        handle_agent_session_message(
            message,
            &config,
            "legacy-controller-public",
            "corr-test",
            &sender,
            &task_state,
        )
        .unwrap();

        let ack = receiver.try_recv().expect("ack should be enqueued first");
        let event = receiver
            .try_recv()
            .expect("security event should remain enqueued");
        let encoded_ack = fleet_protocol::encode_message(&ack).unwrap();
        let fleet_protocol::WirePayload::ControllerSigningTrustBundleAck {
            agent_id,
            accepted,
            current_fingerprint,
            entries_count,
            reason_code,
        } = ack.payload
        else {
            panic!("expected trust bundle ack");
        };

        assert_eq!(agent_id, config.agent_id);
        assert!(accepted);
        assert_eq!(current_fingerprint.as_deref(), Some("controller-fp-new"));
        assert_eq!(entries_count, 1);
        assert!(reason_code.is_none());
        assert!(matches!(
            event.payload,
            fleet_protocol::WirePayload::SecurityEvent { ref action, .. }
                if action == "controller_signing_trust_bundle_update_accepted"
        ));
        assert!(!encoded_ack.contains("controller-public-new"));
        assert!(!encoded_ack.contains("private_key"));
        assert!(!encoded_ack.contains("key_path"));
        assert!(!encoded_ack.contains("tls_certificate"));
    }

    #[test]
    fn agent_controller_signing_trust_bundle_update_rejection_ack_is_bounded() {
        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let config = test_agent_config();
        fs::create_dir_all(config.controller_trust_bundle_path.parent().unwrap()).unwrap();
        let task_state = test_task_session_state();
        let entries = vec![
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-duplicate".to_owned(),
                public_key: "public-material-a".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-duplicate".to_owned(),
                public_key: "public-material-b".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Previous,
                valid_from_ms: 10_000,
                valid_until_ms: Some(20_000),
            },
        ];
        let message = fleet_protocol::WireMessage::new(
            "msg-trust-update",
            "corr-trust-update",
            Some(config.agent_id.clone()),
            10_000,
            fleet_protocol::WirePayload::ControllerSigningTrustBundleUpdate { entries },
        );

        handle_agent_session_message(
            message,
            &config,
            "legacy-controller-public",
            "corr-test",
            &sender,
            &task_state,
        )
        .unwrap();

        let ack = receiver
            .try_recv()
            .expect("rejection ack should be enqueued");
        let event = receiver
            .try_recv()
            .expect("rejection security event should remain enqueued");
        let encoded_ack = fleet_protocol::encode_message(&ack).unwrap();
        let fleet_protocol::WirePayload::ControllerSigningTrustBundleAck {
            accepted,
            current_fingerprint,
            entries_count,
            reason_code,
            ..
        } = ack.payload
        else {
            panic!("expected trust bundle ack");
        };

        assert!(!accepted);
        assert!(current_fingerprint.is_none());
        assert_eq!(entries_count, 2);
        assert_eq!(reason_code.as_deref(), Some("invalid_trust_bundle"));
        assert!(matches!(
            event.payload,
            fleet_protocol::WirePayload::SecurityEvent { ref action, .. }
                if action == "controller_signing_trust_bundle_update_rejected"
        ));
        assert!(!encoded_ack.contains("public-material-a"));
        assert!(!encoded_ack.contains("public-material-b"));
        assert!(!encoded_ack.contains("private_key"));
        assert!(!encoded_ack.contains("key_path"));
        assert!(!encoded_ack.contains("tls_certificate"));
    }

    #[test]
    fn agent_certificate_lifecycle_update_rejects_until_runtime_support_exists() {
        let sender = test_outbound_queue(4);
        let receiver = TestOutboundReceiver(sender.clone());
        let config = test_agent_config();
        let task_state = test_task_session_state();
        let message = fleet_protocol::WireMessage::new(
            "msg-agent-cert-update",
            "corr-agent-cert-update",
            Some(config.agent_id.clone()),
            10_000,
            fleet_protocol::WirePayload::AgentCertificateLifecycleUpdate {
                agent_id: config.agent_id.clone(),
                action: fleet_protocol::AgentCertificateLifecycleActionWire::Issue,
                state: fleet_protocol::AgentCertificateLifecycleStateWire::Issued,
                current_certificate: Some(fleet_protocol::AgentCertificateMetadataWire {
                    serial: "serial-1".to_owned(),
                    fingerprint: "cert-fp-current".to_owned(),
                    not_before_ms: 10_000,
                    not_after_ms: 20_000,
                }),
                next_certificate: None,
                grace_until_ms: None,
                reason_code: None,
            },
        );

        handle_agent_session_message(
            message,
            &config,
            "legacy-controller-public",
            "corr-test",
            &sender,
            &task_state,
        )
        .unwrap();

        let ack = receiver
            .try_recv()
            .expect("certificate lifecycle rejection ack should be enqueued");
        let event = receiver
            .try_recv()
            .expect("certificate lifecycle security event should remain enqueued");
        let encoded_ack = fleet_protocol::encode_message(&ack).unwrap();
        let fleet_protocol::WirePayload::AgentCertificateLifecycleAck {
            agent_id,
            accepted,
            state,
            current_fingerprint,
            reason_code,
        } = ack.payload
        else {
            panic!("expected agent certificate lifecycle ack");
        };

        assert_eq!(agent_id, config.agent_id);
        assert!(!accepted);
        assert_eq!(
            state,
            fleet_protocol::AgentCertificateLifecycleStateWire::Issued
        );
        assert!(current_fingerprint.is_none());
        assert_eq!(
            reason_code.as_deref(),
            Some("certificate_lifecycle_runtime_not_implemented")
        );
        assert!(matches!(
            event.payload,
            fleet_protocol::WirePayload::SecurityEvent { ref action, .. }
                if action == "agent_certificate_lifecycle_update_rejected"
        ));
        assert!(!encoded_ack.contains("serial-1"));
        assert!(!encoded_ack.contains("private_key"));
        assert!(!encoded_ack.contains("certificate_body"));
        assert!(!encoded_ack.contains("ca_path"));
        assert!(!encoded_ack.contains("runtime_env"));
    }

    #[test]
    fn agent_task_verification_uses_updated_bundle_and_preserves_task_guards() {
        let old_key = fleet_core::generate_agent_key_pair().unwrap();
        let new_key = fleet_core::generate_agent_key_pair().unwrap();
        let mut config = test_agent_config();
        config.controller_fingerprint = old_key.fingerprint.clone();
        let task_state = test_task_session_state();
        let issued_at = UNIX_EPOCH + Duration::from_secs(20);
        let now = UNIX_EPOCH + Duration::from_secs(30);
        apply_agent_controller_signing_trust_bundle_update(
            &task_state,
            &[fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: new_key.fingerprint.clone(),
                public_key: new_key.public_key_hex.clone(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            }],
            None,
        )
        .unwrap();
        let envelope = signed_test_task_envelope(
            &config.agent_id,
            "nonce-updated-bundle",
            "payload-hash-updated-bundle",
            &new_key.private_key_hex,
            issued_at,
            UNIX_EPOCH + Duration::from_secs(60),
        );

        let result = verify_agent_task_envelope_once_with_session_trust(
            &envelope,
            &config,
            &old_key.public_key_hex,
            &task_state,
            now,
        )
        .unwrap();

        assert_eq!(
            result,
            Ok(fleet_domain::ControllerSigningTrustVerification::VerifiedCurrent)
        );

        let mismatched_target = signed_test_task_envelope(
            "agent-other",
            "nonce-target-mismatch",
            "payload-hash-target-mismatch",
            &new_key.private_key_hex,
            issued_at,
            UNIX_EPOCH + Duration::from_secs(60),
        );
        let mismatch = verify_agent_task_envelope_once_with_session_trust(
            &mismatched_target,
            &config,
            &old_key.public_key_hex,
            &task_state,
            now,
        )
        .unwrap();

        assert!(matches!(
            mismatch,
            Err(fleet_runner::RunnerError::Job(
                fleet_domain::JobError::TargetAgentMismatch
            ))
        ));
    }

    #[test]
    fn absent_controller_trust_bundle_sidecar_keeps_legacy_pinned_bundle() {
        let dir = unique_test_dir("agent-trust-sidecar-absent");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("agent.conf");
        write_secure_file(
            &config_path,
            "url=http://127.0.0.1:7700\nagent_id=agent-web-01\nfingerprint=agent-fp-1\ncontroller_fingerprint=controller-fp-1\n",
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "agent-private-key\n").unwrap();

        let config = read_agent_config(&config_path).unwrap();
        let task_state = agent_task_session_state(&config).unwrap();
        let bundle =
            agent_controller_signing_trust_bundle(&task_state, &config, "legacy-public-key")
                .unwrap();

        assert_eq!(
            config.controller_trust_bundle_path,
            dir.join("controller_trust_bundle.json")
        );
        assert!(config.controller_trust_bundle.is_none());
        assert_eq!(bundle.entries().len(), 1);
        assert_eq!(
            bundle.entries()[0].fingerprint().as_str(),
            "controller-fp-1"
        );
        assert_eq!(
            bundle.entries()[0].public_key().as_str(),
            "legacy-public-key"
        );
    }

    #[test]
    fn controller_trust_bundle_sidecar_roundtrips_public_fields_only() {
        let dir = unique_test_dir("agent-trust-sidecar-public");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("controller_trust_bundle.json");
        let bundle = controller_signing_trust_bundle_from_wire(&[
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: "controller-fp-new".to_owned(),
                public_key: "controller-public-new".to_owned(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
        ])
        .unwrap();

        write_agent_controller_trust_bundle_sidecar(&path, &bundle).unwrap();
        let loaded = read_agent_controller_trust_bundle_sidecar(&path)
            .unwrap()
            .expect("sidecar should exist");
        let body = fs::read_to_string(path).unwrap();

        assert_eq!(loaded, bundle);
        assert!(body.contains("controller-public-new"));
        assert!(body.contains("controller-fp-new"));
        assert!(!body.contains("private_key"));
        assert!(!body.contains("key_path"));
        assert!(!body.contains("tls_certificate"));
    }

    #[test]
    fn accepted_controller_trust_bundle_update_persists_for_restart() {
        let dir = unique_test_dir("agent-trust-sidecar-restart");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("agent.conf");
        write_secure_file(
            &config_path,
            "url=http://127.0.0.1:7700\nagent_id=agent-web-01\nfingerprint=agent-fp-1\ncontroller_fingerprint=controller-fp-old\n",
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "agent-private-key\n").unwrap();
        let config = read_agent_config(&config_path).unwrap();
        let task_state = agent_task_session_state(&config).unwrap();
        let update = vec![fleet_protocol::ControllerSigningTrustEntryWire {
            fingerprint: "controller-fp-new".to_owned(),
            public_key: "controller-public-new".to_owned(),
            role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
            valid_from_ms: 10_000,
            valid_until_ms: None,
        }];

        apply_agent_controller_signing_trust_bundle_update(
            &task_state,
            &update,
            Some(&config.controller_trust_bundle_path),
        )
        .unwrap();
        let restarted_config = read_agent_config(&config_path).unwrap();

        assert_eq!(
            restarted_config
                .controller_trust_bundle
                .as_ref()
                .unwrap()
                .entries()[0]
                .fingerprint()
                .as_str(),
            "controller-fp-new"
        );
    }

    #[test]
    fn corrupt_controller_trust_bundle_sidecar_rejects_without_material_leak() {
        let dir = unique_test_dir("agent-trust-sidecar-corrupt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("controller_trust_bundle.json");
        write_secure_file(
            &path,
            r#"{
              "entries": [{
                "fingerprint": "controller-fp-new",
                "public_key": "private-key-secret\nvalue",
                "role": "current",
                "valid_from_ms": 10000,
                "valid_until_ms": null
              }]
            }"#,
        )
        .unwrap();

        let error = read_agent_controller_trust_bundle_sidecar(&path)
            .expect_err("invalid sidecar should fail")
            .to_string();

        assert!(error.contains("invalid controller signing public key"));
        assert!(!error.contains("private-key-secret"));
    }

    #[test]
    fn persisted_controller_trust_bundle_verifies_task_after_restart() {
        let old_key = fleet_core::generate_agent_key_pair().unwrap();
        let new_key = fleet_core::generate_agent_key_pair().unwrap();
        let dir = unique_test_dir("agent-trust-sidecar-verify");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("agent.conf");
        write_secure_file(
            &config_path,
            &format!(
                "url=http://127.0.0.1:7700\nagent_id=agent-web-01\nfingerprint=agent-fp-1\ncontroller_fingerprint={}\n",
                old_key.fingerprint
            ),
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "agent-private-key\n").unwrap();
        let persisted_bundle = controller_signing_trust_bundle_from_wire(&[
            fleet_protocol::ControllerSigningTrustEntryWire {
                fingerprint: new_key.fingerprint.clone(),
                public_key: new_key.public_key_hex.clone(),
                role: fleet_protocol::ControllerSigningTrustRoleWire::Current,
                valid_from_ms: 10_000,
                valid_until_ms: None,
            },
        ])
        .unwrap();
        write_agent_controller_trust_bundle_sidecar(
            &agent_controller_trust_bundle_path(&config_path),
            &persisted_bundle,
        )
        .unwrap();
        let restarted_config = read_agent_config(&config_path).unwrap();
        let task_state = agent_task_session_state(&restarted_config).unwrap();
        let issued_at = UNIX_EPOCH + Duration::from_secs(20);
        let now = UNIX_EPOCH + Duration::from_secs(30);
        let envelope = signed_test_task_envelope(
            &restarted_config.agent_id,
            "nonce-persisted-bundle",
            "payload-hash-persisted-bundle",
            &new_key.private_key_hex,
            issued_at,
            UNIX_EPOCH + Duration::from_secs(60),
        );

        let result = verify_agent_task_envelope_once_with_session_trust(
            &envelope,
            &restarted_config,
            &old_key.public_key_hex,
            &task_state,
            now,
        )
        .unwrap();

        assert_eq!(
            result,
            Ok(fleet_domain::ControllerSigningTrustVerification::VerifiedCurrent)
        );
    }

    #[test]
    fn reads_secure_agent_config_with_private_key() {
        let dir = unique_test_dir("secure-agent-config");
        fs::create_dir_all(&dir).unwrap();
        write_secure_file(
            &dir.join("agent.conf"),
            "url=http://127.0.0.1:7700\nagent_id=agent-web-01\nfingerprint=fp-1\ncontroller_fingerprint=controller-fp-1\n",
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "private-key-1\n").unwrap();

        let config = read_agent_config(&dir.join("agent.conf")).unwrap();

        assert_eq!(config.agent_id, "agent-web-01");
        assert!(config.tls_ca_cert.is_none());
        assert_eq!(config.private_key, "private-key-1");
        assert_eq!(config.controller_fingerprint, "controller-fp-1");
        assert_eq!(config.replay_store_path, dir.join("task_nonces.log"));
        assert_eq!(
            config.delivery_journal_path,
            dir.join("journal").join("reports.sqlite3")
        );
    }

    #[test]
    fn reads_agent_config_with_tls_ca_cert() {
        let dir = unique_test_dir("secure-agent-config-tls-ca");
        fs::create_dir_all(&dir).unwrap();
        write_secure_file(
            &dir.join("agent.conf"),
            "url=https://127.0.0.1:7700\ntls_ca_cert=/tmp/fleet-ca.pem\nagent_id=agent-web-01\nfingerprint=fp-1\ncontroller_fingerprint=controller-fp-1\n",
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "private-key-1\n").unwrap();

        let config = read_agent_config(&dir.join("agent.conf")).unwrap();

        assert_eq!(
            config.tls_ca_cert.as_deref(),
            Some(Path::new("/tmp/fleet-ca.pem"))
        );
    }

    #[test]
    fn agent_nonce_replay_guard_uses_configured_file_backed_store() {
        let dir = unique_test_dir("agent-replay-guard");
        fs::create_dir_all(&dir).unwrap();
        let mut config = test_agent_config();
        config.replay_store_path = dir.join("task_nonces.log");
        let mut first_guard = agent_nonce_replay_guard(&config).unwrap();

        first_guard.accept_once("nonce-restart").unwrap();
        let mut restarted_guard = agent_nonce_replay_guard(&config).unwrap();

        assert_eq!(
            restarted_guard.accept_once("nonce-restart"),
            Err(fleet_runner::RunnerError::ReplayedNonce)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn agent_config_builds_legacy_controller_signing_trust_bundle() {
        let config = LocalAgentConfig {
            url: "http://127.0.0.1:7700".to_owned(),
            tls_ca_cert: None,
            agent_id: "agent-web-01".to_owned(),
            fingerprint: "agent-fp-1".to_owned(),
            private_key: "private-key-1".to_owned(),
            controller_fingerprint: "controller-fp-1".to_owned(),
            replay_store_path: unique_test_dir("agent-replay-store").join("task_nonces.log"),
            delivery_journal_path: unique_test_dir("agent-journal")
                .join("journal")
                .join("reports.sqlite3"),
            controller_trust_bundle_path: unique_test_dir("agent-trust-bundle")
                .join("controller_trust_bundle.json"),
            controller_trust_bundle: None,
        };

        let bundle =
            legacy_controller_signing_trust_bundle(&config, "controller-signing-public-key-1")
                .unwrap();
        let entry = bundle
            .entry_for_fingerprint(
                &fleet_domain::SigningKeyFingerprint::new("controller-fp-1").unwrap(),
                UNIX_EPOCH + Duration::from_secs(1),
                UNIX_EPOCH + Duration::from_secs(30),
            )
            .unwrap();

        assert_eq!(bundle.entries().len(), 1);
        assert_eq!(
            entry.role(),
            fleet_domain::ControllerSigningTrustRole::Current
        );
        assert_eq!(
            entry.public_key().as_str(),
            "controller-signing-public-key-1"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_agent_config_readable_by_group_or_other() {
        let dir = unique_test_dir("insecure-agent-config");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("agent.conf");
        write_secure_file(
            &config_path,
            "url=http://127.0.0.1:7700\nagent_id=agent-web-01\nfingerprint=fp-1\ncontroller_fingerprint=controller-fp-1\n",
        )
        .unwrap();
        write_secure_file(&dir.join("agent_private.key"), "private-key-1\n").unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            read_agent_config(&config_path),
            Err(CliError::Io(_))
        ));
    }

    #[test]
    fn rejects_changed_controller_fingerprint_without_reenroll() {
        let config = LocalAgentConfig {
            url: "http://127.0.0.1:7700".to_owned(),
            tls_ca_cert: None,
            agent_id: "agent-web-01".to_owned(),
            fingerprint: "agent-fp-1".to_owned(),
            private_key: "private-key-1".to_owned(),
            controller_fingerprint: "controller-fp-1".to_owned(),
            replay_store_path: unique_test_dir("agent-replay-store").join("task_nonces.log"),
            delivery_journal_path: unique_test_dir("agent-journal")
                .join("journal")
                .join("reports.sqlite3"),
            controller_trust_bundle_path: unique_test_dir("agent-trust-bundle")
                .join("controller_trust_bundle.json"),
            controller_trust_bundle: None,
        };
        let identity = fleet_controller::ControllerIdentityResponse {
            controller_public_key: "controller-public-key-2".to_owned(),
            controller_fingerprint: "controller-fp-2".to_owned(),
            controller_signing_public_key: "controller-public-key-2".to_owned(),
            controller_signing_fingerprint: "controller-fp-2".to_owned(),
            tls_endpoint: fleet_controller::ControllerTlsEndpointResponse::default(),
        };

        assert!(matches!(
            validate_pinned_controller_identity(&config, &identity),
            Err(CliError::Http(_))
        ));
    }

    #[test]
    fn controller_identity_is_created_once() {
        let dir = unique_test_dir("controller-identity-once");
        fs::create_dir_all(controller_dir(&dir)).unwrap();

        let first_fingerprint = ensure_controller_identity(&dir).unwrap();
        let first_public_key =
            fs::read_to_string(controller_dir(&dir).join("controller_public.key")).unwrap();
        let first_private_key =
            fs::read_to_string(controller_dir(&dir).join("controller_private.key")).unwrap();
        let second_fingerprint = ensure_controller_identity(&dir).unwrap();

        assert_eq!(first_fingerprint, second_fingerprint);
        assert_eq!(
            first_public_key,
            fs::read_to_string(controller_dir(&dir).join("controller_public.key")).unwrap()
        );
        assert_eq!(
            first_private_key,
            fs::read_to_string(controller_dir(&dir).join("controller_private.key")).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn controller_private_key_requires_secure_permissions() {
        let dir = unique_test_dir("controller-private-permission");
        fs::create_dir_all(controller_dir(&dir)).unwrap();
        let public_key_path = controller_dir(&dir).join("controller_public.key");
        let private_key_path = controller_dir(&dir).join("controller_private.key");
        let key_pair = fleet_core::generate_agent_key_pair().unwrap();
        fs::write(&public_key_path, format!("{}\n", key_pair.public_key_hex)).unwrap();
        fs::write(&private_key_path, format!("{}\n", key_pair.private_key_hex)).unwrap();
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            ensure_controller_identity(&dir),
            Err(CliError::Io(_))
        ));
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fleet-{name}-{}-{}",
            std::process::id(),
            epoch_millis()
        ))
    }

    #[cfg(unix)]
    fn test_agent_journal(
        name: &str,
        config: &LocalAgentConfig,
    ) -> (PathBuf, String, fleet_agent::journal_worker::JournalWorker) {
        use fleet_agent::journal_worker::{JournalWorker, JournalWorkerLimits};
        use fleet_domain::delivery::{JournalCapacity, JournalUsage};
        use fleet_store::agent_journal::SqliteAgentJournal;
        use std::os::unix::fs::DirBuilderExt;

        let root = unique_test_dir(name);
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let namespace = "a".repeat(64);
        let path = root.join("journal.sqlite3");
        let capacity = JournalCapacity::new(
            JournalUsage {
                reports: 4096,
                bytes: 64 * 1024 * 1024,
            },
            JournalUsage {
                reports: 4,
                bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        let limits = JournalWorkerLimits::new(16, 64 * 1024 * 1024, 8 * 1024 * 1024).unwrap();
        let repository = SqliteAgentJournal::open(&path, &namespace, &config.agent_id).unwrap();
        let worker = JournalWorker::spawn(repository, capacity, limits).unwrap();
        (root, namespace, worker)
    }

    fn initialized_controller_backup_fixture(name: &str) -> PathBuf {
        let data_dir = unique_test_dir(name);
        fs::create_dir_all(controller_dir(&data_dir)).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(agent_dir(&data_dir)).unwrap();
        let store = fleet_store::SqliteStore::open(controller_db_path(&data_dir)).unwrap();
        store.insert_admin_token_hash("backup-admin-hash").unwrap();
        ensure_controller_identity(&data_dir).unwrap();
        data_dir
    }

    fn test_agent_config() -> LocalAgentConfig {
        LocalAgentConfig {
            url: "http://127.0.0.1:7700".to_owned(),
            tls_ca_cert: None,
            agent_id: "agent-web-01".to_owned(),
            fingerprint: "agent-fp-1".to_owned(),
            private_key: "private-key-1".to_owned(),
            controller_fingerprint: "controller-fp-1".to_owned(),
            replay_store_path: unique_test_dir("agent-replay-store").join("task_nonces.log"),
            delivery_journal_path: unique_test_dir("agent-journal")
                .join("journal")
                .join("reports.sqlite3"),
            controller_trust_bundle_path: unique_test_dir("agent-trust-bundle")
                .join("controller_trust_bundle.json"),
            controller_trust_bundle: None,
        }
    }

    fn test_task_envelope(agent_id: &str) -> fleet_domain::TaskEnvelope {
        fleet_domain::TaskEnvelope {
            job_id: fleet_domain::JobId::new("job-queue").unwrap(),
            task_id: fleet_domain::TaskId::new("task-queue").unwrap(),
            target_agent_id: fleet_domain::AgentId::new(agent_id).unwrap(),
            issued_at: UNIX_EPOCH + Duration::from_millis(1),
            expires_at: fleet_domain::TaskExpiry::new(UNIX_EPOCH + Duration::from_secs(60)),
            nonce: fleet_domain::TaskNonce::new("nonce-queue").unwrap(),
            payload_hash: "hash-queue".to_owned(),
            signature: Some(fleet_domain::TaskSignature::new("signature-queue").unwrap()),
        }
    }

    #[test]
    fn drift_report_payload_echoes_signed_task_envelope_correlation() {
        let config = test_agent_config();
        let envelope = test_task_envelope(&config.agent_id);

        let payload = drift_report_payload_for_envelope(
            &config.agent_id,
            &envelope,
            "drifted".to_owned(),
            "package nginx present".to_owned(),
            "package nginx missing".to_owned(),
        );

        assert!(matches!(
            payload,
            fleet_protocol::WirePayload::DriftReport {
                agent_id,
                job_id: Some(job_id),
                task_id: Some(task_id),
                status,
                ..
            } if agent_id == config.agent_id
                && job_id == "job-queue"
                && task_id == "task-queue"
                && status == "drifted"
        ));
    }

    fn signed_test_task_envelope(
        agent_id: &str,
        nonce: &str,
        payload_hash: &str,
        controller_private_key: &str,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> fleet_domain::TaskEnvelope {
        fleet_domain::TaskEnvelope {
            job_id: fleet_domain::JobId::new("job-signed").unwrap(),
            task_id: fleet_domain::TaskId::new(nonce).unwrap(),
            target_agent_id: fleet_domain::AgentId::new(agent_id).unwrap(),
            issued_at,
            expires_at: fleet_domain::TaskExpiry::new(expires_at),
            nonce: fleet_domain::TaskNonce::new(nonce).unwrap(),
            payload_hash: payload_hash.to_owned(),
            signature: Some(
                fleet_domain::TaskSignature::new(
                    fleet_core::sign_challenge(controller_private_key, payload_hash).unwrap(),
                )
                .unwrap(),
            ),
        }
    }

    fn test_task_session_state() -> AgentTaskSessionState {
        AgentTaskSessionState {
            busy: Arc::new(AtomicBool::new(false)),
            runtime: Arc::new(AgentTaskRuntimeState::default()),
            replay_guard: Arc::new(Mutex::new(fleet_runner::NonceReplayGuard::default())),
            controller_trust_bundle: Arc::new(Mutex::new(None)),
            journal_client: Arc::new(Mutex::new(None)),
            delivery_identity: Arc::new(Mutex::new(None)),
        }
    }

    fn test_task_assignment_message(agent_id: &str) -> fleet_protocol::WireMessage {
        fleet_protocol::WireMessage::new(
            "msg-task-test",
            "corr-test",
            Some(agent_id.to_owned()),
            1,
            fleet_protocol::WirePayload::TaskAssignment {
                envelope: fleet_protocol::SignedTaskEnvelopeWire {
                    job_id: "job-test".to_owned(),
                    task_id: "task-test".to_owned(),
                    target_agent_id: agent_id.to_owned(),
                    issued_at_ms: 1,
                    expires_at_ms: 60_000,
                    nonce: "nonce-test".to_owned(),
                    payload_hash: "hash-test".to_owned(),
                    signature: "signature-test".to_owned(),
                },
                task: fleet_protocol::TaskWire::Command(fleet_protocol::CommandTaskWire {
                    program: "uptime".to_owned(),
                    args: Vec::new(),
                    timeout_ms: 30_000,
                    max_output_bytes: 1024,
                }),
            },
        )
    }
}
