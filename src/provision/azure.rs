//! The Azure provider (#197, T9): the `az` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent,
//! the same shape as the Hetzner/AWS/GCP modules.
//!
//! Flow per ADR-0045 (mint-and-inject, Decision 1/6): mint the worker
//! host keypair coordinator-side → render the shared cloud-init template
//! → `vm create` with that user-data (`--custom-data @file`, the
//! authenticated API channel that carries the private half) → `vm show
//! --show-details` for the public IP → pin address + public half into
//! the managed `workers` block. The pin exists BEFORE first use;
//! `ssh-keyscan` is never called.
//!
//! User-data channel (the one T9-text choice, flagged for review): the
//! ticket says "Custom Script Extension / cloud-init-capable images
//! (shared template)"; the shared template (#273) is a `#cloud-config`
//! YAML and the Custom Script Extension executes a SHELL script, where
//! the YAML would fail. The pinned base image is cloud-init-capable
//! Ubuntu (ADR-0046), so the template rides the cloud-init channel:
//! `--custom-data @<file>` — the same authenticated channel that
//! carries the private half, and a file hand-off (the blob never enters
//! argv). Same rule as the sibling providers — the shared template is
//! consumed, never forked (hcloud `--user-datafile`, aws `file://`,
//! gcloud `user-data=`, azure `@file`). The Custom Script Extension
//! remains the channel for non-cloud-init images; none is pinned here.
//!
//! Spot (#197, opt-in): `--spot` rides `vm create` as `--priority Spot
//! --eviction-policy Delete --max-price <cap>`. The eviction policy is
//! pinned to `Delete` — an eviction is T5 WORKER LOSS (ADR-0040
//! Amendment 1): the farm re-dispatches the lost job, and no mid-flight
//! migration exists or will exist here. Azure's other policy,
//! `Deallocate`, would pretend a machine survives that does not — and
//! keeps billing its disks. Azure spot pricing is variable like AWS's,
//! so the cap is REQUIRED with `--spot` — an uncapped bid is not a cap
//! (GCP preemptibles are fixed-price and refuse `--max-price`; azure
//! follows the aws pairing). A `shuttle-worker-spot` tag names the
//! eviction class on the VM.
//!
//! Region discipline: provision's `--location` IS the Azure region. A
//! VM is created inside its resource group's region (`az vm create`
//! carries no `--location`), so provision first ensures the per-region
//! `shuttle-workers-<location>` group exists (`az group create` is
//! idempotent) and every create-path call carries `--resource-group`.
//! Destroy resolves the group by listing — the destroy verb carries no
//! location: `az vm list` finds the VM by name anywhere in the
//! subscription and names its group. Nothing is deleted beyond the VM
//! itself; leftovers are warned, never silently removed.
//!
//! Order discipline (the Hetzner module's contract): dry-run and every
//! local refusal resolve before ANY API call — credentials ride the
//! inherited environment (`az login` state / service-principal env, the
//! az CLI convention) and never enter argv, and no partial state
//! survives a failure: VMs created before a later failure are deleted,
//! config is appended only after every VM is up. No retries are named
//! by the ticket: a failed step fails the provision and tears the set
//! down; the operator re-runs.

use std::path::Path;

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, mint_host_keypair, now_epoch_secs,
    render_user_data, stage_user_data, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams,
};

/// The worker presence tag shuttle stamps at create time — the key
/// shared with the #269 v2 TTL contract (Hetzner writer, cross-provider
/// vocabulary): presence marks the VM as a shuttle worker. The value is
/// `true` (presence semantics; expiry rides the TTL tag only).
pub const WORKER_TAG: &str = "shuttle-worker";

/// The TTL tag: expiry in EPOCH SECONDS UTC, set AT CREATE — the source
/// of truth of the #269 v2 contract (the in-guest marker is a fallback
/// COPY). The same decimal shape the `shuttle-worker-ttl` hcloud label
/// carries; the sweep's `is_epoch` parses decimal only. (The sweep
/// itself is hcloud-only today — #287; the same gap applies to azure.)
pub const WORKER_TTL_TAG: &str = "shuttle-worker-ttl";

/// The spot tag, present (`true`) only on `--spot` VMs: names the
/// eviction class (T5 worker loss, ADR-0040 Amendment 1) so
/// operator-side tooling can tell an interruptible lane from an
/// on-demand one.
pub const WORKER_SPOT_TAG: &str = "shuttle-worker-spot";

/// The worker base image (providers plan §3, ADR-0046): the LATEST
/// Ubuntu LTS — the contract pins "latest LTS", never a codename — as
/// the Canonical marketplace URN, bumped on every new LTS like the
/// Hetzner slug and the GCP family (26.04 at the 2026-09-27 decision;
/// #273 reconciled the stale 24.04 wording). `:latest` is the IMAGE
/// VERSION digit (the marketplace rolls security updates into it); the
/// offer/sku legs pin the LTS release. The overlay is entirely in the
/// shared cloud-init template: stock provider image, no custom images.
pub const IMAGE_URN: &str = "Canonical:ubuntu-26_04-lts:ubuntu-2604-lts-amd64:latest";

/// The resource-group prefix; the group is per-region
/// (`shuttle-workers-<location>`) because a VM's region is its group's
/// region. Created (idempotently) at provision; NEVER deleted at
/// destroy — the group may hold operator resources.
pub const RESOURCE_GROUP_PREFIX: &str = "shuttle-workers";

/// The `az vm create --admin-username`. The shared template authorizes
/// root (key-only), so the admin user is a CLI-required artifact that
/// also carries the operator key (`--ssh-key-value`) as a break-glass
/// login; worker traffic goes to root.
pub const ADMIN_USERNAME: &str = "azureuser";

pub struct AzureProvisioner<R: CommandRunner> {
    runner: R,
    /// Where the az CLI would resolve credentials from (the `az login`
    /// token cache or the service-principal env triple) — `None` is the
    /// no-credentials refusal path, checked before any API call. The
    /// credential itself never enters argv; the az CLI inherits it.
    credentials: Option<String>,
    /// The pinned shuttle binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at
    /// the CLI boundary (`SHUTTLE_OPERATOR_KEY` / default key halves) so
    /// the core stays env-free under test.
    operator_key: String,
}

impl<R: CommandRunner> AzureProvisioner<R> {
    pub fn new(
        runner: R,
        credentials: Option<String>,
        binary_url: String,
        operator_key: String,
    ) -> Self {
        AzureProvisioner {
            runner,
            credentials,
            binary_url,
            operator_key,
        }
    }

    /// One az CLI call. Region scoping rides `--resource-group` (a VM's
    /// region is its group's region), never a global flag. Credentials
    /// ride the inherited environment — they never enter argv.
    fn az(&self, args: &[&str]) -> miette::Result<String> {
        let mut argv = vec!["az".to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("provision: cannot run the az CLI (is it installed?): {e}")
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "provision: az {} failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: CommandRunner> Provisioner for AzureProvisioner<R> {
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>> {
        // Local refusals first — every one of them API-free. Azure spot
        // pricing is variable (the aws pairing): `--spot` requires a
        // `--max-price` cap, a cap requires `--spot`, the cap must be a
        // positive finite decimal.
        validate_spot(req)?;

        // Local resolution: mint, template, TTL. All of it is API-free,
        // so the dry-run plan is the REAL plan.
        let expiry_epoch = now_epoch_secs()? + req.ttl_secs;
        let expiry_iso = iso8601_utc(expiry_epoch);
        let dir = tempfile::tempdir()
            .map_err(|e| miette::miette!("provision: cannot create the mint scratch dir: {e}"))?;
        let minted = mint_host_keypair(&self.runner, dir.path())?;
        let user_data = render_user_data(&UserDataParams {
            host_private_key: &minted.private_pem,
            host_public_key: &minted.public_line,
            operator_key: &self.operator_key,
            binary_url: &self.binary_url,
            ttl_expiry_epoch: expiry_epoch,
        });
        let user_data_sha256 = crate::oci::sha256_hex(user_data.as_bytes());

        if req.dry_run {
            // Deliberately BEFORE the credentials check: a plan needs no
            // credentials and must make no API call.
            print_plan(
                &ProvisionPlan {
                    server_type: req.server_type.clone(),
                    location: req.location.clone(),
                    count: req.count,
                    image: IMAGE_URN.to_string(),
                    ttl_secs: req.ttl_secs,
                    ttl_expiry_iso: expiry_iso,
                    binary_url: self.binary_url.clone(),
                    spot_max_price: req.max_price.clone().filter(|_| req.spot),
                    user_data_sha256,
                },
                req.spot,
            );
            return Ok(Vec::new());
        }

        // az reads credentials from its inherited environment (`az
        // login` state / service-principal env); they never enter argv.
        // Presence is checked before any API call.
        self.require_credentials()?;

        let user_data_file = stage_user_data(dir.path(), &user_data)?;

        // The per-region group first (idempotent): the VM's region is
        // its group's region, so this is how `--location` takes effect.
        let rg = resource_group(&req.location);
        self.az(&[
            "group",
            "create",
            "--name",
            &rg,
            "--location",
            &req.location,
        ])?;

        // Create + describe; every successfully created name rides
        // `created` so any later failure tears the whole set down.
        let mut created: Vec<(String, String)> = Vec::new();
        let result = self.create_and_pin(
            req,
            &rg,
            &user_data_file,
            expiry_epoch,
            &minted.public_line,
            &mut created,
        );
        if let Err(e) = result {
            let mut torn_down = 0usize;
            let mut stuck: Vec<&str> = Vec::new();
            for (name, _) in &created {
                if self
                    .az(&[
                        "vm",
                        "delete",
                        "--resource-group",
                        &rg,
                        "--name",
                        name,
                        "--yes",
                    ])
                    .is_ok()
                {
                    torn_down += 1;
                } else {
                    stuck.push(name);
                }
            }
            if stuck.is_empty() {
                return Err(miette::miette!(
                    "provision: {e:#} — deleted {torn_down} created VM(s), config untouched"
                ));
            }
            return Err(miette::miette!(
                "provision: {e:#} — deleted {torn_down} created VM(s), config untouched; \
                 FAILED to delete {} — it is still running and billing; delete it with \
                 'shuttle workers destroy' or by hand",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(name, address)| ProvisionedWorker {
                host_key: pin_with_comment(&minted.public_line, &name),
                name,
                address,
            })
            .collect())
    }

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool> {
        self.require_credentials()?;
        // The destroy verb carries no location: find the VM by name
        // anywhere in the subscription and take its group from the
        // listing (filtered client-side — the name never enters a
        // JMESPath expression).
        let rg = self.resolve_resource_group(name)?;
        // One describe serves the address (the config pin's key).
        let ip = self.public_ip(&rg, name)?;
        // The #269 v2 pre-delete check: disks that will NOT vanish with
        // the VM get a loud warning BEFORE the delete.
        self.warn_surviving_disks(&rg, name)?;
        // Delete first: if the call fails the worker is still live and
        // the config pin must stay.
        self.az(&[
            "vm",
            "delete",
            "--resource-group",
            &rg,
            "--name",
            name,
            "--yes",
        ])?;
        // Teardown truthfulness: `az vm delete` leaves the VM's NIC and
        // public IP behind, and public IPs keep billing. Name the
        // residuals — never silently remove them (the group may hold
        // operator resources).
        self.warn_orphans(&rg, name)?;
        match evict_worker_entry(config, &address_for(&ip)) {
            Ok(true) => Ok(true),
            Ok(false) => {
                crate::output::warn(format!(
                    "destroy: VM '{name}' deleted, but no managed workers entry pins {} — \
                     config left untouched",
                    address_for(&ip)
                ));
                Ok(false)
            }
            Err(e) => Err(miette::miette!(
                "destroy: VM '{name}' deleted, but the config entry could not be evicted: {e:#}"
            )),
        }
    }
}

impl<R: CommandRunner> AzureProvisioner<R> {
    fn require_credentials(&self) -> miette::Result<()> {
        if self.credentials.is_none() {
            return Err(miette::miette!(
                "provision: no Azure credentials found (checked AZURE_CLIENT_ID + \
                 AZURE_TENANT_ID + AZURE_CLIENT_SECRET/AZURE_CLIENT_CERTIFICATE_PATH, \
                 AZURE_CONFIG_DIR, ~/.azure token cache) — run 'az login', or export the \
                 dedicated worker-subscription service principal (never a TOFU_INPUTS \
                 credential)"
            ));
        }
        Ok(())
    }

    /// Create `count` VMs, describe each for its public IP, then pin all
    /// entries in ONE pass. Records every created name in `created`
    /// (name, address-so-far) as teardown-on-failure state — pushed
    /// BEFORE the describe, so a VM that exists but fails its describe
    /// is still deleted.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        rg: &str,
        user_data_file: &Path,
        expiry_epoch: u64,
        public_line: &str,
        created: &mut Vec<(String, String)>,
    ) -> miette::Result<()> {
        let mut pins: Vec<(String, String)> = Vec::new();
        for i in 0..req.count {
            let name = instance_name(i);
            let custom_data = format!("@{}", user_data_file.display());
            let tags_value = tags(req, expiry_epoch);
            let mut args = vec![
                "vm",
                "create",
                "--resource-group",
                rg,
                "--name",
                &name,
                "--size",
                &req.server_type,
                "--image",
                IMAGE_URN,
                "--admin-username",
                ADMIN_USERNAME,
                "--ssh-key-value",
                &self.operator_key,
                "--custom-data",
                &custom_data,
                "--tags",
                &tags_value,
            ];
            if req.spot {
                args.extend([
                    "--priority",
                    "Spot",
                    "--eviction-policy",
                    "Delete",
                    "--max-price",
                    req.max_price.as_deref().unwrap_or_default(),
                ]);
            }
            self.az(&args)?;
            // Teardown state FIRST: a VM that exists but fails its
            // describe must still be deleted.
            created.push((name.clone(), String::new()));
            let ip = self.public_ip(rg, &name)?;
            let address = address_for(&ip);
            created.last_mut().expect("just pushed").1 = address.clone();
            pins.push((name, address));
        }
        // The pin transaction: all entries after every VM is up — a
        // provision that dies here leaves no config (and the caller's
        // teardown leaves no VM). Nothing unpinned survives.
        for (name, address) in &pins {
            append_worker_entry(&req.config, address, &pin_with_comment(public_line, name))?;
        }
        Ok(())
    }

    /// The VM's public IPv4 from `az vm show --show-details` (JSON via
    /// `--query`). Absent → named refusal with the remedy: the create
    /// never pretends an unreachable worker was provisioned.
    fn public_ip(&self, rg: &str, name: &str) -> miette::Result<String> {
        let body = self.az(&[
            "vm",
            "show",
            "--resource-group",
            rg,
            "--name",
            name,
            "--show-details",
            "--query",
            "publicIps",
            "--output",
            "json",
        ])?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("provision: az show '{name}' is not JSON: {e}"))?;
        let ip = v.as_str().map(str::trim).filter(|s| !s.is_empty());
        ip.map(str::to_string).ok_or_else(|| {
            miette::miette!(
                "provision: VM '{name}' has no public IP — the subnet must grant one \
                 (the create relies on the default new-public-IP behavior) or the worker \
                 is unreachable; nothing was pinned"
            )
        })
    }

    /// The resource group carrying VM `name`: one subscription-wide
    /// `az vm list`, filtered client-side (the operator-supplied name
    /// never enters a JMESPath expression). A miss is a named refusal.
    fn resolve_resource_group(&self, name: &str) -> miette::Result<String> {
        let body = self.az(&[
            "vm",
            "list",
            "--query",
            "[].{name:name, rg:resourceGroup}",
            "--output",
            "json",
        ])?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("destroy: az vm list is not JSON: {e}"))?;
        for vm in v.as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if vm["name"].as_str() == Some(name) {
                return vm["rg"].as_str().map(str::to_string).ok_or_else(|| {
                    miette::miette!("destroy: az vm list has no group for '{name}'")
                });
            }
        }
        Err(miette::miette!(
            "destroy: no VM named '{name}' in this subscription — names are printed by \
             provision; nothing was deleted"
        ))
    }

    /// The #269 v2 pre-delete check: disks whose `deleteOption` is not
    /// `Delete` will NOT vanish with the VM and keep billing — a loud
    /// warning names the count, and then the delete proceeds anyway:
    /// the operator asked for the destruction, the warning exists so
    /// lingering storage bills are never silent.
    fn warn_surviving_disks(&self, rg: &str, name: &str) -> miette::Result<()> {
        let body = self.az(&[
            "disk",
            "list",
            "--resource-group",
            rg,
            "--query",
            "[?managedBy!=null].{name:name, vm:managedBy, del:deleteOption}",
            "--output",
            "json",
        ])?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("destroy: az disk list is not JSON: {e}"))?;
        let vm_suffix = format!("/{name}");
        let surviving = v
            .as_array()
            .map(|ds| {
                ds.iter()
                    .filter(|d| {
                        d["vm"].as_str().is_some_and(|vm| vm.ends_with(&vm_suffix))
                            && d["del"].as_str() != Some("Delete")
                    })
                    .count()
            })
            .unwrap_or(0);
        if surviving > 0 {
            crate::output::warn(format!(
                "destroy: VM '{name}' still has {surviving} attached disk(s) that will NOT be \
                 deleted with it (deleteOption is not Delete) — the storage keeps billing; \
                 delete them by hand"
            ));
        }
        Ok(())
    }

    /// Post-delete residual check: `az vm delete` leaves the VM's NIC
    /// and public IP behind (public IPs bill). Name them — they were
    /// created for this VM but shuttle never removes resources it
    /// cannot attribute beyond doubt.
    fn warn_orphans(&self, rg: &str, name: &str) -> miette::Result<()> {
        let nics = self.unattached_names(
            &[
                "network",
                "nic",
                "list",
                "--resource-group",
                rg,
                "--query",
                "[?virtualMachine==null].name",
                "--output",
                "json",
            ],
            "nic list",
        )?;
        let pips = self.unattached_names(
            &[
                "network",
                "public-ip",
                "list",
                "--resource-group",
                rg,
                "--query",
                "[?ipConfiguration==null].name",
                "--output",
                "json",
            ],
            "public-ip list",
        )?;
        if !nics.is_empty() || !pips.is_empty() {
            crate::output::warn(format!(
                "destroy: VM '{name}' deleted, but {} unattached network interface(s) and {} \
                 unassociated public IP(s) remain in resource group '{rg}' — public IPs keep \
                 billing; delete them by hand (e.g. {})",
                nics.len(),
                pips.len(),
                pips.join(", ")
            ));
        }
        Ok(())
    }

    fn unattached_names(&self, args: &[&str], what: &str) -> miette::Result<Vec<String>> {
        let body = self.az(args)?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("destroy: az {what} is not JSON: {e}"))?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }
}

// ── Local refusals and shape helpers ──

/// The spot/price-cap pairing rules (#197; the aws pairing — azure spot
/// pricing is variable, so an uncapped bid is not a cap): a spot bid
/// without a cap has no ceiling; a cap without `--spot` has nothing to
/// cap; the cap itself must parse as a positive finite hourly USD
/// decimal. All API-free.
fn validate_spot(req: &ProvisionRequest) -> miette::Result<()> {
    match (req.spot, &req.max_price) {
        (true, None) => Err(miette::miette!(
            "provision: --spot requires --max-price — an uncapped spot bid is not a price cap; \
             name the hourly USD ceiling the lane may bid"
        )),
        (false, Some(_)) => Err(miette::miette!(
            "provision: --max-price requires --spot — on-demand has no bid to cap"
        )),
        (true, Some(cap)) => {
            let price: f64 = cap
                .trim()
                .parse()
                .map_err(|_| miette::miette!("--max-price must be a decimal USD/h, got '{cap}'"))?;
            if !price.is_finite() || price <= 0.0 {
                return Err(miette::miette!(
                    "--max-price must be a positive finite USD/h, got '{cap}'"
                ));
            }
            Ok(())
        }
        (false, None) => Ok(()),
    }
}

/// The `--tags` value: the `shuttle-worker` presence tag, the
/// `shuttle-worker-ttl` epoch-seconds EXPIRY (the #269 v2 contract —
/// the source of truth the sweep reads — set AT CREATE), and
/// `shuttle-worker-spot` on spot VMs. One argv element (the az
/// space-separated convention), no shell.
fn tags(req: &ProvisionRequest, expiry_epoch: u64) -> String {
    let mut t = vec![
        format!("{WORKER_TAG}=true"),
        format!("{WORKER_TTL_TAG}={expiry_epoch}"),
    ];
    if req.spot {
        t.push(format!("{WORKER_SPOT_TAG}=true"));
    }
    t.join(" ")
}

/// The per-region resource group: `shuttle-workers-<location>`. A VM's
/// region is its group's region, so this is the shape `--location`
/// takes on the wire.
fn resource_group(location: &str) -> String {
    format!("{RESOURCE_GROUP_PREFIX}-{location}")
}

/// The address shape every provisioned entry carries: the shared
/// template authorizes root (key-only, `PermitRootLogin
/// prohibit-password`), so the login is root on the stock Ubuntu image
/// too, default SSH port.
fn address_for(ip: &str) -> String {
    format!("ssh://root@{ip}")
}

/// The pinned public half: `ssh-keygen`'s line with the VM name as the
/// single comment word (the pin grammar allows at most one) —
/// traceability from a known_hosts/`workers` line back to the Azure
/// resource.
fn pin_with_comment(public_line: &str, name: &str) -> String {
    let mut parts = public_line.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    let key = parts.next().unwrap_or_default();
    format!("{key_type} {key} {name}")
}

/// `shuttle-worker-<hex nanos>-<NN>` — unique per subscription; the
/// prefix mirrors the tag key, so name and tags read as one identity.
fn instance_name(i: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("shuttle-worker-{nanos:x}-{:02}", i + 1)
}

fn print_plan(plan: &ProvisionPlan, spot: bool) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         azure");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  region:           {}", plan.location));
    crate::output::info(format!(
        "  resource group:   {}",
        resource_group(&plan.location)
    ));
    crate::output::info(format!("  base image:       {}", plan.image));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    if let Some(cap) = &plan.spot_max_price {
        crate::output::info(format!(
            "  spot max price:   {cap} USD/h (eviction: delete — T5 worker loss)"
        ));
    } else if spot {
        crate::output::info("  class:            spot");
    } else {
        crate::output::info("  class:            on-demand");
    }
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  tags:             {WORKER_TAG} + {WORKER_TTL_TAG}=<ttl epoch>"
    ));
}
