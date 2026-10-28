# Sponzey Fleet

[한국어 설명서](README.ko.md)

Sponzey Fleet is a self-hosted, open-source server operations platform. It brings
remote commands, repeatable runbooks, server state, and policy-based fixes into
one workflow, with target selection, approvals, signed jobs, and audit records.

It is intended for people who manage multiple Linux servers, including machines
behind NAT or a private network. Instead of opening an SSH session for each task,
the operator works through a Controller. An Agent on each managed machine keeps
an outbound connection to that Controller, reports its state, and runs signed jobs.
The Agent still needs network access to the Controller.

The npm package is **`@sponzey/fleet`**. The executable and command are **`fleet`**.

Start with [the goals](#project-goals), [capabilities](#main-workflow-and-capabilities),
and [current scope](#development-status-and-current-scope), or go straight to
[installation](#install) and the [one-computer setup](#beginner-setup-controller-and-agent-on-one-computer).

## Project goals

Fleet aims to make routine server operations easier to repeat, review, and explain:

- Manage reachable Agents through their outbound connections, without requiring
  an inbound SSH connection to every managed server for each operation.
- Turn repeated commands and configuration changes into targeted jobs and
  runbooks, with review, approval where required, and an audit trail.
- Check whether servers still match a declared policy, then connect a detected
  difference to an approved fix and a fresh verification check.
- Keep job outcomes understandable through connection failures and restarts.
  Preserve supported reports until storage is confirmed, and expose uncertain
  execution rather than guessing success or automatically repeating a command.

The core user outcome is a complete operations loop: enroll a server, review the
targets, submit a job, inspect each Agent's output and result, and trace the action
in audit records. For policy work, the loop also includes detecting and verifying
a fix. Installation-time and fleet-size figures in the
[quality targets](.docs/architecture/quality-targets.md) are design candidates,
not measured service guarantees.

## Main workflow and capabilities

1. Register an Agent with an enrollment token and give it useful labels, such as
   `role=web` and `env=test`.
2. Review its connection state, inventory, facts, and metrics in Web Admin or the CLI.
3. Select Agents by ID or labels and preview the targets. A created job keeps its
   target snapshot; later label changes do not silently change that job's targets.
4. Submit a command or runbook. Work that requires approval waits for an operator's
   decision before dispatch; the Controller signs tasks and the Agent checks them.
5. Inspect per-Agent progress, output, terminal results, and audit events. Cancel a
   job when needed; execution has a time limit.
6. For ongoing configuration checks, assign a policy and schedule drift checks.
   Review a remediation proposal, approve its runbook, and inspect the verification
   result before considering the difference resolved.

A **Job** is the operator's request. An **Assignment** tracks that job on one
Agent, so a job sent to several Agents can have different outcomes on each machine.

| Capability | What it provides now |
| --- | --- |
| Agent inventory | Enrollment, labels, connection state, machine facts, capability declarations, and metrics snapshots |
| Command jobs | Target preview, multi-Agent assignments, output collection, approval checks, cancellation, and timeouts |
| Runbooks | YAML steps for package, service, file-copy, and template operations; remote execution uses the signed job path. `fleet apply` currently validates a document without executing it |
| Policies and remediation | Scheduled checks, drift history, approved fixes, and resolution based on fresh verification evidence |
| Public Git catalogs | Public HTTPS source registration, bounded sync and validation, explicit revision activation, and recorded document provenance; activation itself does not execute work |
| Operator interfaces | Controller-served Web Admin, CLI, protected REST APIs, OpenAPI, and Swagger UI |
| Operational records | Job/Assignment state, job output, Agent operational logs, audit records, retention, and Controller backup/restore |

Facts describe the machine; metrics describe sampled resource use; job output is
the command's stdout/stderr. These are separate records with different purposes.
Fleet provides the visibility needed to operate its jobs and policies. It does
not aim to replace a full metrics, logging, or alerting platform.

## Development status and current scope

Definition reviewed against the repository on **2026-10-23**. This checkout is based
on tag `v0.0.20` (`6683792`), and its manifests still report `0.0.20`. The working
tree also contains uncommitted reporting and recovery changes beyond that tag.
This README describes the current checkout; it does not establish the latest
published version or that these changes are available in an npm package.

The core operations loop is implemented. Operational hardening and some end-to-end
user flows are still in progress:

| Area | Current boundary |
| --- | --- |
| Deployment | The primary path is one Controller with SQLite and Linux Agents. macOS binaries and command execution exist, but service management and host data collection are not equivalent to Linux |
| Result delivery | Persistent Command and no-artifact Runbook paths have local report journaling, replay, signed storage receipts, and output-coverage checks. DriftCheck evidence and terminal reports also use receipts. Artifact-producing Runbook reports, direct one-shot results, and Drift execution recovery have different limits; see [the protocol](docs/protocol.md) |
| Failure recovery | Uncertain execution is reported as `failed` with a reason such as `execution_outcome_unknown`, without automatic re-execution. This is not a guarantee that external effects happen exactly once or that every byte of output was captured |
| PostgreSQL | A feature-gated adapter and repository tests exist. Current Controller startup rejects Postgres because Assignment/report recovery is not supported there; SQLite is the usable runtime path for this checkout |
| Web Admin | Shared Run/Runbooks Job observation supports pause/resume, stale-response guards, and terminal results including partial success. Stored-output paging and history navigation are implemented. The SQLite observation flow has scoped Linux/browser and output-cost verification. Active catalog Runbooks can be reviewed and submitted for approval, with fixed targets and immutable Job provenance. This checkout has scoped two-Agent Linux and native-browser verification of the public Git-to-result journey |
| Operator identity and secrets | Bootstrap authentication, role checks and local `fleet controller admin init-owner` / `recover-owner` commands exist. Personal HTTP login/session/logout, setup and cookie/PAT authentication foundations are connected; owner account reads, creation, changes and password reset are connected. Own password replacement and PAT issuance/metadata/revocation are connected; Command, DriftCheck, direct and catalog Runbook creation plus approval/rejection, explicit cancellation, manual approval expiry and remediation approval/job creation now recheck authority within atomic business transactions. Personal Admin login/account screens are connected. Personal CLI token input/profile integration is connected. Scoped two-user HTTPS browser/API/CLI, Linux Agent execution during revocation, recovery/restore and bounded authentication-load acceptance pass in this checkout. These are unreleased changes, not production capacity or release claims. OIDC/project RBAC and an external secret provider are separate. See the [local account contract](.docs/domains/identity/features/IAM-001-auth-contract.md). |
| Verification | Development records include local release checks, live PostgreSQL Store contracts, scoped persistent Command restart/reboot rehearsals, long-running UI/catalog acceptance and personal-account HTTPS/Linux acceptance. These cover their stated paths and do not establish complete recovery for every execution path, production capacity or release readiness for future features |

Controller and Agents use protocol v2 and must be upgraded together. There is no
v1 interoperability or mixed-version fallback. Existing local-data migration and
backup/restore safeguards still apply.

Future expansion includes full mTLS client-certificate enforcement, external
secret and S3 adapters, stronger team identity, HA coordination, Windows services,
notifications, and signed automatic updates. These are not current product
support claims. Ansible import is a future subset bridge, not full compatibility.
Fleet is not positioned as a CI/CD system or an endpoint-security product.
Team/Enterprise editions described in the original proposal are future product
ideas; their commercial scope and pricing are not established by this repository.

Start with the [documentation map](.docs/README.md) for the
[product scope](.docs/product/overview.md), [capabilities](.docs/product/capabilities.md),
and [overall plan](.docs/plans/plan.md). The agreed order is recovery validation,
long-running job observation, catalog-to-execution, individual identity and a real
secret provider, then measured performance work. Refactoring follows each boundary.
The [feature matrix](docs/feature-matrix.md) and protocol, storage, and security
contracts describe implementation details and limits. The
[original proposal](.docs/archive/project-proposal.md) is historical, not the active plan.

## Service form and components

Fleet currently runs on infrastructure you operate. A single `fleet` executable
provides the Controller, Agent, and operator CLI roles:

- The **Controller** stores jobs and operational data, authenticates Agents and
  operators, handles approvals and dispatch, and serves Web Admin and the API.
- An **Agent** runs on each managed machine. It maintains an outbound WebSocket
  session, collects host information, and executes permitted signed work.
- **Web Admin** is a static browser interface served by the Controller at `/admin`.
  Operators can also use the CLI or REST API; a separate Node.js web server is not
  part of the runtime.

One Controller can manage multiple Agents. The current design assumes a single
active Controller rather than coordinated HA or multi-tenant operation. Real and
long-running deployments use HTTPS/WSS, with built-in TLS or an HTTPS reverse proxy.

Distribution consists of the npm wrapper and platform binary packages for
Linux/macOS arm64/x64, plus standalone release archives. Linux service commands
target systemd. macOS packaging does not imply the same service and primitive
support, and Windows service support is future work.

## Technology stack

| Technology | Role in the current implementation |
| --- | --- |
| Rust, edition 2024 | Controller, Agent runtime, CLI, domain rules, storage adapters, and host operations |
| Axum and Tokio | Controller HTTP/WebSocket interface, asynchronous runtime, and worker lifecycle |
| SQLite with `rusqlite` | Default Controller store and Agent report journal; local filesystem storage holds artifact bodies |
| Serde / JSON and YAML documents | JSON wire/API messages; Fleet YAML runbooks and policies |
| Ed25519 and Rustls | Task and receipt signatures, Controller trust, and TLS transport support |
| clap | The `fleet` command and its subcommands |
| HTML, CSS, native JavaScript modules | Web Admin, with `allowJs`/`checkJs` validation and Node test/static-copy build scripts; no React/Vite application |
| libgit2 via `git2` | Bounded fetching and validation of public HTTPS Git catalogs |
| npm and GitHub Actions | Platform binary distribution, release checks, and npm Trusted Publishing via OIDC; Node.js is not the Fleet server runtime |

The Rust workspace separates domain rules, application use cases, protocol,
storage, runner, Controller, Agent support, and CLI composition. Agent extraction
is incomplete: the CLI still owns the active socket/task adapters, while
`fleet-agent` owns session state, the bounded journal worker, and receipt
verification. PostgreSQL uses an optional `postgres` adapter, not SQLx or SeaORM.

## What you need

For the easiest start, prepare:

- macOS or Linux
- Node.js and npm
- a terminal window
- a web browser

Check that Node.js and npm are installed:

```bash
node --version
npm --version
```

If either command is missing, install a current Node.js LTS release first.

## Install

Install Sponzey Fleet globally so the `fleet` command is available in every
terminal:

```bash
npm install -g @sponzey/fleet
fleet --version
```

If you install it only inside a project with `npm install @sponzey/fleet`, run it
as `npx fleet` instead.

If the terminal says `fleet: command not found`, inspect npm's global command
directory:

```bash
echo "$(npm prefix -g)/bin"
```

Add the printed directory to your shell `PATH`, then open a new terminal.

To build directly from this repository:

```bash
cargo build -p fleet-cli
./target/debug/fleet --version
```

When using the source build, replace `fleet` in the examples below with
`./target/debug/fleet`.

## Try the one-command demo

Before setting up real machines, run:

```bash
fleet demo
```

The demo creates temporary Controller and Agent data, runs a small job, and
prints a Web Admin URL. It removes the temporary data when it finishes.

## Understand the three important values

You will see these values during setup:

| Value | What it is | Where to use it |
| --- | --- | --- |
| Admin token | Shared bootstrap credential, before personal accounts are enabled | Paste it into the initial Web Admin screen |
| Personal token | One person's CLI/API credential, valid for 30 days | Enter it at the hidden `fleet login` prompt; it is separate from your account password |
| Enrollment token | A short-lived, usually one-time Agent registration code | Use it only with `fleet agent init` |
| Data directory | A folder containing keys, settings, and Controller or Agent data | Use the same directory every time you start that role |

The admin token and enrollment token are different. Do not use one in place of
the other.

## Beginner setup: Controller and Agent on one computer

This is the safest way to learn. You will use two terminal windows on the same
computer.

### Step 1: initialize the Controller

Open the first terminal and run:

```bash
mkdir -m 700 -p fleet-controller
fleet controller init --data-dir ./fleet-controller
```

The command prints an `admin token`. Copy it into a password manager or another
safe temporary place. The Controller stores only its hash and does not show the
same raw token again.

Initialization is normally done only once.

On macOS/Linux, the Controller data folder must belong to the OS user running
Fleet and have mode `0700`. For an existing folder you own, stop the old Controller
and run `chmod 700 ./fleet-controller` before starting this version. Fleet checks
these permissions and holds an exclusive lock while running; it does not change
existing folder permissions for you. Stop older Fleet binaries explicitly, since
they do not participate in this lock.

### Step 2: start the Controller

In the same terminal, run:

```bash
fleet controller start \
  --host 127.0.0.1 \
  --port 7700 \
  --data-dir ./fleet-controller \
  --external-url http://127.0.0.1:7700
```

Leave this terminal open. The Controller stops if you press `Ctrl+C` or close
the terminal.

`http://` is acceptable for this same-computer lesson only. Sponzey prints a
warning to remind you that HTTP is not encrypted.

### Step 3: open Web Admin

Open this address in your browser:

```text
http://127.0.0.1:7700/admin
```

Paste the admin token from Step 1. You should now see Web Admin, even though no
Agent is connected yet.

After a local first-owner cutover, use the username/password sign-in instead. In
Settings, My account manages your password and personal tokens; People is owner-only;
Controller contains enrollment and signing trust. A newly created person uses
Set up or reset a password with the once-shown code, then signs in. Codes expire
in 15 minutes. Signing out does not cancel Agent jobs.

### Step 4: create an Agent enrollment token

Open a second terminal. Run this command while the Controller remains running:

```bash
fleet enroll-token create \
  --data-dir ./fleet-controller \
  --labels role=test,env=local
```

Copy the token printed by the command. This is the enrollment token, not the
admin token. You can also create enrollment tokens from Web Admin.

### Step 5: initialize the Agent

In the second terminal, replace `PASTE_ENROLLMENT_TOKEN_HERE` with the token from
Step 4, then run:

```bash
mkdir -p fleet-agent
fleet agent init \
  --data-dir ./fleet-agent \
  --url http://127.0.0.1:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name my-first-agent \
  --labels role=test,env=local
```

Agent initialization creates an Agent identity and pins the Controller identity.
It is normally done only once per Agent data directory.

### Step 6: start the Agent

Run:

```bash
fleet agent start --data-dir ./fleet-agent
```

Leave this terminal open too. Refresh Web Admin. `my-first-agent` should appear
in the Agent list.

To perform only one connection check and exit, use:

```bash
fleet agent start --data-dir ./fleet-agent --once
```

The normal Agent keeps reconnecting when the network or Controller is briefly
unavailable.

## Real setup: Controller and Agent on different computers

The order is the same, but the Agent must use the Controller computer's real IP
address or DNS name.

The examples below use `192.168.0.10` as the Controller address. Replace it with
your own value.

### Step 1: find the Controller computer's address

On Linux, try:

```bash
hostname -I
```

On macOS Wi-Fi, try:

```bash
ipconfig getifaddr en0
```

You may also find the address in your router or cloud server dashboard.

### Step 2: initialize and start the Controller

On the Controller computer:

```bash
mkdir -p fleet-controller
fleet controller init --data-dir ./fleet-controller
```

Save the printed admin token, then start the Controller:

```bash
fleet controller start \
  --host 0.0.0.0 \
  --port 7700 \
  --data-dir ./fleet-controller \
  --external-url http://192.168.0.10:7700
```

Two addresses have different meanings here:

- `--host 0.0.0.0` means “listen on all network interfaces.” It is a bind value,
  not an address that an Agent can use.
- `--external-url http://192.168.0.10:7700` is the address Agents and operators
  actually use.

Never put `0.0.0.0` in `--external-url` or `agent init --url`.

Your firewall must allow the chosen port. If another computer cannot open
`http://192.168.0.10:7700/admin`, check the Controller process, IP address,
router/network rules, and firewall before continuing.

### Step 3: create an enrollment token on the Controller

On the Controller computer:

```bash
fleet enroll-token create \
  --data-dir ./fleet-controller \
  --labels role=web,env=test
```

Transfer the printed token securely to the Agent computer. Enrollment tokens
are short-lived and should not be posted in chat rooms, tickets, or source code.

### Step 4: install and initialize the Agent computer

On the Agent computer:

```bash
npm install -g @sponzey/fleet
mkdir -p fleet-agent
fleet agent init \
  --data-dir ./fleet-agent \
  --url http://192.168.0.10:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name web-01 \
  --labels role=web,env=test
```

Then start it:

```bash
fleet agent start --data-dir ./fleet-agent
```

Open `http://192.168.0.10:7700/admin` and confirm that `web-01` is online.

> `127.0.0.1` always means “this same computer.” An Agent on a second computer
> must not use `127.0.0.1` unless it connects through a local SSH tunnel.

## Use HTTPS for real or long-running environments

Plain HTTP does not encrypt admin tokens, enrollment traffic, jobs, or Agent
data. Use HTTP only for local learning, a private lab, or short-lived testing.
Use HTTPS for production, customer, shared, Internet-facing, or long-running
installations.

### Option A: built-in HTTPS

Prepare a certificate chain and private key on the Controller, then run:

```bash
fleet controller start \
  --host 0.0.0.0 \
  --port 7700 \
  --data-dir /var/lib/fleet \
  --external-url https://fleet.example.com:7700 \
  --tls-cert /etc/fleet/tls/fullchain.pem \
  --tls-key /etc/fleet/tls/privkey.pem
```

The private key should be readable only by the account running the Controller.

Initialize Agents with the same HTTPS URL:

```bash
fleet agent init \
  --data-dir /var/lib/fleet \
  --url https://fleet.example.com:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name web-01 \
  --labels role=web,env=prod
```

If the server certificate uses a private or self-signed CA, add:

```text
--tls-ca-cert /path/to/ca.pem
```

### Option B: HTTPS reverse proxy

Nginx, Caddy, a cloud load balancer, or another reverse proxy can handle HTTPS.
In that case, keep Sponzey on Controller loopback:

```bash
fleet controller start \
  --host 127.0.0.1 \
  --port 7700 \
  --data-dir /var/lib/fleet \
  --external-url https://fleet.example.com
```

Configure the proxy to forward HTTPS requests to `127.0.0.1:7700`, including
WebSocket connections.

## What you can do in Web Admin

After an Agent connects, Web Admin can:

- show Agent online/offline state and inventory
- display facts, metrics, drift history, and product-safe Agent logs
- create command and runbook jobs
- preview selector targets before creating a multi-Agent job
- show per-Agent assignment state and job output
- create and decide approval requests
- save and assign policies and schedule drift checks
- browse public catalog sources, their validated revisions, and runbook/policy metadata
- show remediation progress and audit events

In **Run** or **Runbooks**, select a job from history to open **Selected job**.
The panel shows each Agent's Assignment and the last successful update separately
from observation status. **Pause observation** only stops reads; it does not
cancel the job. **Resume observation** reads the Controller again. Returning to
either workspace also refreshes the selected job. **Clear token** removes the
token from this page's memory and stops its Job and artifact reads.
The same history is available in both workspaces. On narrower screens, tab to
the Assignment table and use the arrow keys to read columns to the right.

An access or connection error stops or temporarily retries observation; it does
not mean the job failed. Artifact inspection pauses observation until you resume.
When targets have different outcomes, `partial_success` is a finished result;
check each Agent's Assignment to see which succeeded or failed.
The result screen reads stored output in small pages. The live view keeps a limited
amount and tells you when earlier entries leave the view. Click **Browse stored history**
to read from the beginning, **Next page** to continue, and **Resume live observation**
to follow the current result again.
The Jobs list is a snapshot: use **Refresh** to update it, or select a Job for its current result.

Jobs are stored before they are sent. If an Agent is offline, its assignment
stays queued and can be delivered after the Agent reconnects.

On Linux and macOS, a command is stopped if output handling fails, you cancel it,
or its time limit expires. This also stops children in that command's process
group, but does not undo changes already made. Use service commands or runbooks
to manage long-running services, rather than leaving a background shell command running.

## Policies and remediation in plain language

A **runbook** says, “perform these steps now.” A **policy** says, “this condition
should remain true over time.”

For example, a policy can say that nginx should be running on every Agent with
the label `role=web`.

The remediation flow is:

1. A signed drift check reports that the machine does not match the policy.
2. The Controller creates a remediation proposal.
3. An operator reviews and approves it.
4. The Controller creates and signs a runbook job.
5. The Agent runs the job and reports the result.
6. The Controller runs a verification check.
7. Fresh compliant evidence resolves the remediation and its original drift.

Remediation does not bypass approval. The old manual `running`, `result`, and
`verify` API/CLI commands are deprecated and return `409`; authenticated Agent
events and stored verification evidence are the source of truth.

See [Runbooks](docs/runbooks.md), [Policies](docs/policy.md), and the
[API contract](docs/api.md) for complete schemas and advanced examples.

## Add a public runbook or policy catalog

A catalog is a public HTTPS Git repository containing validated runbook and
policy documents. Registering a source does not download it, syncing it does
not make it active, and activation does not execute anything on an Agent.
Those three separate steps make it easier to review what will be used.
Other YAML files, such as a CI workflow, are ignored. A file that declares a
Fleet `Runbook` or `Policy` must still be valid before the sync can succeed.

In Web Admin, open **Runbooks** or **Policies**. Each Catalog list has **First page**,
**Next page**, and **Retry** controls. Choose a source, then a revision and document;
changing pages keeps your explicit selection. Lists show metadata without downloading
a document body or running a job.

To add a source, expand **Manage catalog sources and revisions** in the Catalog panel:

1. Enter a short source ID, its public `https://` Git URL, and the branch or
   tag to follow; then choose **Register source**.
2. Enter a new operation ID such as `sync-2026-08-31-01`, then choose
   **Start sync**. The panel follows the operation ID returned by the Controller
   and shows in progress, completed, failed, or cancelled. Acceptance is not completion.
   **Stop observing** pauses the view; **Check again** resumes a status read.
   Reads stop after three minutes. If a request outcome is unknown, verify it before
   submitting again; the page never automatically resends a mutation. To check an
   existing operation, enter its source and canonical ID and choose **Check entered operation**.
3. Refresh the catalog, then select the source and a ready revision. The selection
   fills **Source ID** and **Ready commit**. Choose **Activate ready revision**, check
   the full source and commit in the confirmation, then choose **Activate exact revision**.
   Cancel returns to the form without sending activation. Refresh the catalog to
   review its active pointer; activation does not create or execute a Job.

The three columns show source, revision, and document metadata. They do not
show document bodies or treat a successful sync as an activation.

To run an activated Runbook, stay in **Runbooks**:

1. Select the source, its active ready revision, and a Runbook document. A Policy or
   inactive revision cannot be submitted here. If the active revision changes,
   refresh the catalog and select the intended document again.
2. Under **Run from this catalog**, enter the target labels, such as `role=web,env=test`,
   then choose **Review document and targets**. Open **Review stored Runbook** to
   read the stored document. Check its full source, commit, path and checksum,
   and every selected Agent ID. Disabled Agents are excluded; an offline Agent
   may still be selected. An empty result cannot be submitted.
3. Check the review confirmation and choose **Create catalog Job**. This sends the
   document reference and the reviewed Agent IDs. It creates an approval request;
   the confirmation checkbox does not approve execution.
4. Use **Approvals** on the same page to approve or reject the request. After approval,
   follow **Selected job** for each Agent's state and stored output. The Job keeps
   its original document provenance even if another revision becomes active.

Changing the document, target labels, page or token cancels the current review.
If submission times out, use **Check stored Job ID** before retrying. If the
Controller confirms it is missing, **Retry the same Job ID** sends the same reviewed
request. The page never automatically creates a new Job to recover an uncertain submission.

Source registration, sync and activation are also available after `fleet login`:

```bash
fleet catalog register public-operations https://example.com/operations.git main
fleet catalog sync public-operations sync-2026-08-31-01
fleet catalog list
fleet catalog activate public-operations FULL_READY_COMMIT_ID
```

Only an owner or administrator can register, sync, or activate a catalog.
Use public HTTPS repositories only; private repository credentials are not a
supported catalog setting.

## Personal accounts and optional CLI login

The shared admin token in the local lesson is for bootstrap. To give people their
own logins, stop the Controller. On its computer, from the lesson's folder, run:

```bash
fleet controller admin init-owner --data-dir ./fleet-controller --username owner
```

Enter a new password twice at the hidden prompts. Use a unique passphrase of at
least 15 characters. This creates the first owner and permanently ends shared-token
access. Keep the original data directory and signing keys. If you use a custom
`--db`, pass the same setting here. Restart the Controller using the same start
command, open `/admin`, and sign in as `owner`. Shared or ongoing installations
must use their configured HTTPS address.

In **Settings → People**, the owner creates another person and privately gives
them the once-shown setup code. They use **Set up or reset a password** on the login
screen within 15 minutes, then sign in. Each web login lasts 8 hours; refreshing
does not extend it.

For CLI access, open **Settings → My account → Connect CLI or API**, enter your
current password, and create a personal token. It lasts 30 days and is shown once.
On your computer, replace the address below with your Controller's HTTPS address:

```bash
fleet login --controller-url https://fleet.example.com
```

Paste the personal token at the hidden prompt and press Enter. Enter the token,
rather than your password. Fleet verifies it before saving a profile. Automation
can supply one token through stdin with `--token-stdin`; keep secrets out of shell
history and environment variables. From the same folder, these commands use it:

```bash
fleet agents remote-list
fleet jobs list
fleet approvals list
fleet remediations list
fleet audit export --category security --limit 100
```

The default profile is `.fleet/cli-profile.json` under your current folder. It
contains the Controller address and token, not your password. On macOS/Linux it
is an owned mode `0600` file, written atomically. Do not share or commit it. For a
different location, pass `--profile-path /your/private/path/profile.json` on login
and later commands. Changing only `--controller-url` cannot send a saved token to
another server; log in to that server separately.

For a Controller using a private CA, add `--tls-ca-cert /path/to/public-ca.pem`
to `fleet login`. Keep that public CA file on your computer: the profile records
its path and loads it when a CLI command starts. Certificate and hostname checks
stay enabled; system and browser trust settings do not change. Never pass a
private key file here.

Revoke a CLI token in **Settings → My account → Your personal tokens**. Its next
request gets an authentication error. An invalid, expired, or revoked credential
does not mean an Agent job failed: sign in and inspect the existing job. Web
sign-out ends that web session. Password or role changes, blocking, and password
resets revoke that person's sessions and tokens; accepted Agent jobs continue.

If all owners lose access, stop the Controller and run locally on its computer:

```bash
fleet controller admin recover-owner --data-dir ./fleet-controller --username owner
```

Use the existing login name, original data directory, and custom `--db` if any.
Enter a new password twice, restart, and sign in. That person's old credentials
are revoked. This cannot run remotely or replace missing signing keys; restore
the original keys from backup.

## Running continuously on Linux

On a Linux system using systemd, first initialize the Controller or Agent with
the same persistent data directory that the service will use. Preview the unit
before installing it:

```bash
fleet controller install-service \
  --data-dir /var/lib/fleet \
  --dry-run

fleet agent install-service \
  --data-dir /var/lib/fleet \
  --dry-run
```

Installing or removing a service requires Linux and root privileges:

```bash
sudo fleet agent install-service --data-dir /var/lib/fleet
sudo fleet agent start-service
sudo fleet agent status-service
sudo fleet agent logs-service
```

Controller service commands have the same shape. Verify the dry-run output and
your HTTPS/reverse-proxy settings before relying on a service in production.

## Back up the Controller

Back up before an upgrade, migration, or machine move. Stop the Controller first
so SQLite is not being written during the backup. Stop older binaries too; backup and actual
restore require the same exclusive data-directory lease as the Controller.

```bash
fleet controller backup \
  --data-dir ./fleet-controller \
  --output ./fleet-controller.backup.json
```

The backup contains Controller keys and operational data. Treat it as a secret.
Fleet writes a new private file (0600) and refuses to overwrite an existing filename.

Validate a backup without changing the source or destination. Fleet checks the database and
signing keys in temporary private scratch, then removes that scratch:

```bash
fleet controller restore \
  --data-dir ./restore-check \
  --input ./fleet-controller.backup.json \
  --dry-run
```

Restore into an empty data directory:

```bash
fleet controller restore \
  --data-dir ./fleet-controller-restored \
  --input ./fleet-controller.backup.json
```

A real restore keeps accounts, password verifiers and Agent identity, but invalidates every old
web session, personal token and unused setup/reset code. A backup without a usable owner
requires local owner setup; its old shared token stays disabled. Stop the Controller before restoring.
Fleet prepares a private candidate and atomically exchanges the directory. A warning after installation
can mean cleanup is pending or durability needs checking; keep the Controller stopped in that case.

A real restore keeps the Controller's delivery namespace but changes its store epoch. The Agent
keeps persistent-session TaskAck, TaskStarted, and TaskRejected reports, unconfirmed Command/no-artifact Runbook stdout/stderr chunks, and no-artifact
Command/Runbook final results in an owner-only local journal at
`<agent-data-dir>/journal/reports.sqlite3`. It commits each report before sending, replays pending
reports after reconnect, and removes one only after verifying the Controller's signed `stored`
receipt for that exact report in the authenticated session. For TaskAck, TaskStarted, and
pre-execution TaskRejected, the Controller checks Assignment ownership and atomically commits the
state transition, Job aggregate, audit, and inbox marker before issuing the receipt. TaskRejected
stores a redacted reason and only rejects an Assignment that has not yet been accepted. TaskStarted is journaled before the Agent begins
Command, Runbook, or Drift execution.
If a matching lifecycle report arrives after SQLite G2 marks its Assignment `failed/execution_outcome_unknown`,
the Controller stores one audit/inbox disposition and returns a signed receipt without changing the terminal
state. This clears that journal row so ordered replay can continue; it does not prove that the task succeeded.
Persistent DriftCheck evidence and its terminal result use separate reports and receipts on this path. An evidence receipt confirms stored evidence, not Job/Assignment success; the separate terminal-result receipt records the task outcome. A matching no-artifact DriftCheck final report received after G2 preserves the existing terminal state. Artifact-bearing Runbook finals use the authenticated v2 Controller effect and signed receipt, but the Agent does not journal those report/body bytes. SQLite retries already-staged pending final reports in bounded batches at startup and every 30 seconds (up to 100 reports/8 MiB per effect scan); it also scans up to 100 committed finals missing receipt bytes using only the stored key/digest, without repeating the final effect. It rechecks the body and owner, persists receipts only after effect commit, then queues them through an active session's single writer. Output gaps, corruption, unsupported follow-up, and terminal assignments remain pending and fail closed. If the connection fails before Controller inbox staging, the Agent cannot replay this artifact report. Postgres report recovery and direct one-shot results remain separate/unsupported paths. This does not recover reports already confirmed after the backup snapshot or
claim to capture every byte produced by task execution. Persistent Command and no-artifact Runbook final reports include
the number of locally journaled stdout/stderr chunks and whether capture was truncated. The Controller
waits until every reported chunk is stored in sequence before finalizing the result or sending its
receipt, and it will not accept truncated output as success. This verifies delivery of the Agent's
journaled chunks, not that task execution produced no uncaptured bytes. The summary is required by the
active v2 format; older final reports without it have no compatibility fallback.
On SQLite, the Controller also checks unfinished dispatched tasks before opening its listener and
every 30 seconds afterward. If the task timeout plus five minutes has elapsed, it marks the task
`failed` with `execution_outcome_unknown`; that means the Controller cannot verify whether the task
ran, and it will not retry the task automatically. Postgres-backed Controller startup is currently
disabled until that backend supports this recovery contract.
Upgrade the Controller and all Agents together: protocol v1 Agents are rejected, with no
compatibility fallback.

## Common problems

### `fleet: command not found`

Open a new terminal after global installation. If it still fails, check
`$(npm prefix -g)/bin` and add that directory to `PATH`.

### `controller is not initialized`

Run `fleet controller init` once. Make sure `controller init` and
`controller start` use exactly the same `--data-dir`.

### `agent is not enrolled`

Run `fleet agent init` once. Make sure `agent init` and `agent start` use
exactly the same Agent `--data-dir`.

### The Agent cannot connect

Check these items in order:

1. Is the Controller terminal or service still running?
2. Is the Agent using the Controller IP/DNS name instead of its own
   `127.0.0.1`?
3. Is port `7700` open in the operating-system and cloud firewalls?
4. Does the URL start with `https://` when the Controller uses TLS?
5. Does a private CA require `--tls-ca-cert` during Agent initialization?

### The Agent does not appear in Web Admin

Check the Agent terminal for enrollment, identity, or connection errors. An
enrollment token is usually one-time use; create a new one instead of retrying a
consumed token.

### `WARNING: insecure HTTP controller URL enabled`

This is a warning, not a crash. It means traffic is not encrypted. Use HTTPS
outside local or short-lived testing.

### Web Admin shows `{"error":"not_found"}`

Open `/admin`, for example `http://127.0.0.1:7700/admin`.

### A job stays queued

The target Agent may be offline or waiting behind another assignment. Start the
Agent and inspect the Job and Audit views. Queued work is not silently treated
as completed.

## Security reminders

- Never commit admin tokens, enrollment tokens, private keys, or backup files.
- Use HTTPS for real environments.
- Keep Controller, Agent, and TLS private-key files readable only by the service
  account that needs them.
- Review target preview and approval details before running privileged jobs.
- Back up the Controller before upgrades or destructive maintenance.

More detail is available in [Security](docs/security.md),
[Storage](docs/storage.md), and the [feature matrix](docs/feature-matrix.md).

## API and development documentation

The Controller serves:

```text
/admin         Web Admin
/openapi.json  OpenAPI 3.1 JSON
/swagger-ui    Interactive API documentation
```

Do not enter real admin tokens in Swagger UI over plain HTTP.

Install the UI test dependencies first. The workspace includes binary packages for several OS/CPU targets, so development installation uses --force with install scripts disabled. jsdom is a test-only dependency; it is not shipped in Fleet.

```bash
npm ci --workspace web-admin --force --ignore-scripts
```

For contributors, the main checks are:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test --workspace @sponzey/fleet
npm test --workspace web-admin
npm run typecheck --workspace web-admin
npm run build --workspace web-admin
```

See the [release gate](docs/release-gate.md) for the complete release procedure.

## License

Sponzey Fleet is licensed under the GNU Affero General Public License version 3
only (`AGPL-3.0-only`). The license covers the Rust workspace, Web Admin, npm
wrapper, and distributed binaries unless a file explicitly says otherwise.
See [LICENSE](LICENSE) and [license notes](docs/license.md).
