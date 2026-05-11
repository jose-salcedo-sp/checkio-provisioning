use clap::Parser;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(author, version, about = "Tenant provisioning for CheckIO")]
struct Cli {
    #[arg(long)]
    tenant: String,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value = "checkio.app")]
    base_domain: String,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long, default_value_t = 41000)]
    min_port: u16,

    #[arg(long, default_value_t = 49000)]
    max_port: u16,

    #[arg(long, env = "CHECKIO_JWT_SECRET")]
    jwt_secret: String,

    #[arg(long)]
    client_origin: Option<String>,

    #[arg(long, env = "CHECKIO_OPS_EMAIL")]
    ops_email: String,

    #[arg(long, default_value = "/var/checkio")]
    tenants_root: PathBuf,

    #[arg(long, default_value = "/etc/checkio")]
    env_dir: PathBuf,

    #[arg(long, default_value = "/var/lib/checkio/provision-state.json")]
    state_file: PathBuf,

    #[arg(long, default_value = "/opt/checkio-back")]
    backend_root: PathBuf,

    #[arg(long, default_value = "/etc/nginx/sites-available")]
    nginx_available_dir: PathBuf,

    #[arg(long, default_value = "/etc/nginx/sites-enabled")]
    nginx_enabled_dir: PathBuf,

    #[arg(long, default_value = "checkio")]
    service_user: String,

    #[arg(long, default_value = "checkio@")]
    systemd_unit_prefix: String,

    #[arg(long, value_enum, default_value_t = ServiceEnableMode::Runtime)]
    service_enable_mode: ServiceEnableMode,

    #[arg(long, default_value = "sqlx")]
    sqlx_bin: String,

    #[arg(long, default_value = "nginx")]
    nginx_bin: String,

    #[arg(long, default_value = "certbot")]
    certbot_bin: String,

    #[arg(long, default_value = "/")]
    health_path: String,

    #[arg(long, default_value_t = false)]
    skip_certbot: bool,

    /// Path to a pre-built frontend dist/ directory. When provided, static
    /// files are copied to the tenant's public dir and nginx is configured
    /// to serve them at / and proxy /api/ to the backend.
    #[arg(long)]
    frontend_dist: Option<PathBuf>,

    /// Path to a TLS certificate file (PEM). When provided together with
    /// --tls-key, nginx is configured to serve HTTPS on port 443 with an
    /// HTTP→HTTPS redirect on port 80. Intended for use with mkcert or
    /// other pre-generated certificates when --skip-certbot is set.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file (PEM) matching --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Seed user: full name (must be provided together with --seed-email and --seed-password).
    #[arg(long)]
    seed_name: Option<String>,

    /// Seed user: email address.
    #[arg(long)]
    seed_email: Option<String>,

    /// Seed user: plain-text password (hashed with Argon2id before storage).
    #[arg(long)]
    seed_password: Option<String>,

    /// Seed user: role assigned to the seed user (default: admin).
    #[arg(long, default_value = "admin")]
    seed_role: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ServiceEnableMode {
    None,
    Runtime,
    Persistent,
}

#[derive(Debug, Error)]
enum ProvisionError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProvisionState {
    tenants: BTreeMap<String, TenantState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TenantState {
    port: u16,
    domain: String,
}

#[derive(Debug, Serialize)]
struct StepStatus {
    name: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ProvisionOutput {
    success: bool,
    tenant: String,
    domain: String,
    port: u16,
    service: String,
    steps: Vec<StepStatus>,
}

#[derive(Debug)]
struct RuntimeContext {
    tenant: String,
    domain: String,
    port: u16,
    database_url: String,
    client_origin: String,
    service_name: String,
    tenant_dir: PathBuf,
    public_dir: PathBuf,
    env_file: PathBuf,
    nginx_file: PathBuf,
    nginx_enabled_symlink: PathBuf,
}

#[derive(Debug)]
struct FileBackup {
    path: PathBuf,
    previous: Option<Vec<u8>>,
}

#[derive(Debug)]
struct SymlinkBackup {
    path: PathBuf,
    previous_target: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let mut steps = Vec::new();

    match run(cli, &mut steps) {
        Ok(output) => {
            let serialized = serde_json::to_string_pretty(&output)
                .unwrap_or_else(|_| "{\"success\":true,\"detail\":\"provisioned\"}".to_string());
            println!("{serialized}");
        }
        Err(error) => {
            let output = serde_json::json!({
                "success": false,
                "error": error.to_string(),
                "steps": steps,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output)
                    .unwrap_or_else(|_| "{\"success\":false}".to_string())
            );
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli, steps: &mut Vec<StepStatus>) -> Result<ProvisionOutput, ProvisionError> {
    validate_tenant(&cli.tenant)?;
    if cli.min_port > cli.max_port {
        return Err(ProvisionError::Message(
            "min-port cannot be greater than max-port".to_string(),
        ));
    }

    match (&cli.seed_name, &cli.seed_email, &cli.seed_password) {
        (Some(_), Some(_), Some(_)) | (None, None, None) => {}
        _ => {
            return Err(ProvisionError::Message(
                "--seed-name, --seed-email, and --seed-password must all be provided together"
                    .to_string(),
            ));
        }
    }

    match (&cli.tls_cert, &cli.tls_key) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProvisionError::Message(
                "--tls-cert and --tls-key must be provided together".to_string(),
            ));
        }
        (Some(cert), Some(key)) => {
            if !cert.exists() {
                return Err(ProvisionError::Message(format!(
                    "tls cert not found: {}",
                    cert.display()
                )));
            }
            if !key.exists() {
                return Err(ProvisionError::Message(format!(
                    "tls key not found: {}",
                    key.display()
                )));
            }
        }
        (None, None) => {}
    }

    let domain = cli
        .domain
        .clone()
        .unwrap_or_else(|| format!("{}.{}", cli.tenant, cli.base_domain));
    validate_domain(&domain)?;

    let client_origin = cli
        .client_origin
        .clone()
        .unwrap_or_else(|| format!("https://{domain}"));

    let mut state = load_state(&cli.state_file)?;
    let port = reserve_port(&cli, &state, &domain)?;
    steps.push(StepStatus {
        name: "validate_and_reserve_port".to_string(),
        status: "ok".to_string(),
        detail: format!("tenant={}, domain={}, port={}", cli.tenant, domain, port),
    });

    let tenant_dir = cli.tenants_root.join(&cli.tenant);
    let env_file = cli.env_dir.join(format!("{}.env", cli.tenant));
    let nginx_file = cli
        .nginx_available_dir
        .join(format!("checkio-{}.conf", cli.tenant));
    let nginx_enabled_symlink = cli
        .nginx_enabled_dir
        .join(format!("checkio-{}.conf", cli.tenant));
    let database_path = tenant_dir.join("restaurant.db");
    let database_url = format!("sqlite:{}", database_path.display());
    let service_name = format!("{}{}", cli.systemd_unit_prefix, cli.tenant);

    let public_dir = tenant_dir.join("public");

    let runtime = RuntimeContext {
        tenant: cli.tenant.clone(),
        domain: domain.clone(),
        port,
        database_url,
        client_origin,
        service_name: service_name.clone(),
        tenant_dir: tenant_dir.clone(),
        public_dir,
        env_file: env_file.clone(),
        nginx_file: nginx_file.clone(),
        nginx_enabled_symlink: nginx_enabled_symlink.clone(),
    };

    let mut pre_nginx_backups: Vec<FileBackup> = Vec::new();
    let mut nginx_backups: Vec<FileBackup> = Vec::new();
    let mut symlink_backup: Option<SymlinkBackup> = None;
    let mut allow_rollback = false;

    let provision_result = (|| -> Result<(), ProvisionError> {
        create_directories(&cli, &runtime, steps)?;
        create_database_file(&cli, &runtime, steps)?;
        run_migrations(&cli, &runtime, steps)?;
        create_seed_user(&cli, &runtime, steps)?;

        let env_content = render_env_file(&cli, &runtime);
        pre_nginx_backups.push(atomic_write_with_backup(
            &runtime.env_file,
            env_content.as_bytes(),
        )?);
        run_chown(
            &runtime.env_file,
            &format!("root:{}", cli.service_user),
            "chown_env_file",
            steps,
        )?;
        set_file_mode(&runtime.env_file, 0o640)?;
        steps.push(StepStatus {
            name: "write_env_file".to_string(),
            status: "ok".to_string(),
            detail: runtime.env_file.display().to_string(),
        });

        run_command(
            "systemctl",
            &["daemon-reload"],
            None,
            "systemd_daemon_reload",
            steps,
        )?;
        enable_service(&cli, &runtime, steps)?;
        run_command(
            "systemctl",
            &["restart", &runtime.service_name],
            None,
            "start_service",
            steps,
        )?;

        deploy_frontend(&cli, &runtime, steps)?;

        let has_frontend = cli.frontend_dist.is_some();
        let tls = cli.tls_cert.as_ref().zip(cli.tls_key.as_ref());
        let nginx_config = render_nginx_config(&runtime, has_frontend, tls);
        allow_rollback = true;
        nginx_backups.push(atomic_write_with_backup(
            &runtime.nginx_file,
            nginx_config.as_bytes(),
        )?);
        symlink_backup = Some(ensure_symlink(
            &runtime.nginx_file,
            &runtime.nginx_enabled_symlink,
        )?);
        steps.push(StepStatus {
            name: "write_nginx_config".to_string(),
            status: "ok".to_string(),
            detail: runtime.nginx_file.display().to_string(),
        });

        run_command(&cli.nginx_bin, &["-t"], None, "nginx_validate", steps)?;
        {
            let reload_ok = Command::new("systemctl")
                .args(["reload", "nginx"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !reload_ok {
                let out = Command::new("systemctl")
                    .args(["restart", "nginx"])
                    .output()
                    .map_err(|e| {
                        ProvisionError::Message(format!("failed to execute systemctl: {e}"))
                    })?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let detail = if !stderr.is_empty() {
                        stderr
                    } else if !stdout.is_empty() {
                        stdout
                    } else {
                        "command failed without output".to_string()
                    };
                    steps.push(StepStatus {
                        name: "nginx_reload".to_string(),
                        status: "failed".to_string(),
                        detail: detail.clone(),
                    });
                    return Err(ProvisionError::Message(format!(
                        "nginx_reload failed: {detail}"
                    )));
                }
                steps.push(StepStatus {
                    name: "nginx_reload".to_string(),
                    status: "ok".to_string(),
                    detail: "reload failed, restarted nginx successfully".to_string(),
                });
            } else {
                steps.push(StepStatus {
                    name: "nginx_reload".to_string(),
                    status: "ok".to_string(),
                    detail: "systemctl reload nginx".to_string(),
                });
            }
        }

        if cli.skip_certbot {
            steps.push(StepStatus {
                name: "issue_ssl_cert".to_string(),
                status: "skipped".to_string(),
                detail: "skip-certbot is true".to_string(),
            });
        } else {
            run_command(
                &cli.certbot_bin,
                &[
                    "--nginx",
                    "-d",
                    &runtime.domain,
                    "--non-interactive",
                    "--agree-tos",
                    "-m",
                    &cli.ops_email,
                ],
                None,
                "issue_ssl_cert",
                steps,
            )?;
        }

        run_command(
            "systemctl",
            &["is-active", "--quiet", &runtime.service_name],
            None,
            "verify_service_active",
            steps,
        )?;
        verify_port_listening(runtime.port, steps)?;
        let has_tls = cli.tls_cert.is_some() || !cli.skip_certbot;
        if has_tls {
            verify_https_health(&runtime, &cli.health_path, steps)?;
        } else {
            verify_http_local_health(runtime.port, &cli.health_path, steps)?;
        }

        Ok(())
    })();

    if let Err(error) = provision_result {
        if allow_rollback {
            for backup in nginx_backups.into_iter().rev() {
                let _ = restore_backup(backup);
            }
            if let Some(link_backup) = symlink_backup {
                let _ = restore_symlink(link_backup);
            }
            steps.push(StepStatus {
                name: "rollback".to_string(),
                status: "ok".to_string(),
                detail: "restored nginx artifacts after failure; env/service state preserved"
                    .to_string(),
            });
        } else {
            drop(pre_nginx_backups);
            steps.push(StepStatus {
                name: "rollback".to_string(),
                status: "skipped".to_string(),
                detail: "skipped rollback because nginx configuration was not applied".to_string(),
            });
        }
        return Err(error);
    }

    state.tenants.insert(
        runtime.tenant.clone(),
        TenantState {
            port: runtime.port,
            domain: runtime.domain.clone(),
        },
    );
    save_state(&cli.state_file, &state)?;
    steps.push(StepStatus {
        name: "persist_state".to_string(),
        status: "ok".to_string(),
        detail: cli.state_file.display().to_string(),
    });

    Ok(ProvisionOutput {
        success: true,
        tenant: runtime.tenant,
        domain: runtime.domain,
        port: runtime.port,
        service: runtime.service_name,
        steps: std::mem::take(steps),
    })
}

fn validate_tenant(tenant: &str) -> Result<(), ProvisionError> {
    if tenant.is_empty() {
        return Err(ProvisionError::Message(
            "tenant cannot be empty".to_string(),
        ));
    }
    if tenant
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Ok(());
    }
    Err(ProvisionError::Message(
        "tenant must contain only lowercase letters, digits, and '-'".to_string(),
    ))
}

fn validate_domain(domain: &str) -> Result<(), ProvisionError> {
    if !domain.contains('.') {
        return Err(ProvisionError::Message(
            "domain must include at least one '.'".to_string(),
        ));
    }
    if domain
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
    {
        return Ok(());
    }
    Err(ProvisionError::Message(
        "domain contains unsupported characters".to_string(),
    ))
}

fn load_state(path: &Path) -> Result<ProvisionState, ProvisionError> {
    if !path.exists() {
        return Ok(ProvisionState::default());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(ProvisionState::default());
    }
    Ok(serde_json::from_str(&content)?)
}

fn save_state(path: &Path, state: &ProvisionState) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_vec_pretty(state)?;
    atomic_write(path, &content)?;
    set_file_mode(path, 0o640)?;
    Ok(())
}

fn reserve_port(cli: &Cli, state: &ProvisionState, domain: &str) -> Result<u16, ProvisionError> {
    let existing = state.tenants.get(&cli.tenant).map(|v| v.port);
    let candidate = if let Some(explicit) = cli.port {
        explicit
    } else if let Some(existing) = existing {
        existing
    } else {
        find_available_port(cli, state)?
    };

    if candidate < cli.min_port || candidate > cli.max_port {
        return Err(ProvisionError::Message(format!(
            "port {} outside allowed range {}-{}",
            candidate, cli.min_port, cli.max_port
        )));
    }

    for (tenant, tenant_state) in &state.tenants {
        if tenant != &cli.tenant && tenant_state.port == candidate {
            return Err(ProvisionError::Message(format!(
                "port {} already reserved by tenant '{}'",
                candidate, tenant
            )));
        }
    }

    if existing != Some(candidate) && !is_port_available(candidate) {
        return Err(ProvisionError::Message(format!(
            "port {} is not currently available",
            candidate
        )));
    }

    if let Some(existing_tenant) = state.tenants.get(&cli.tenant) {
        if existing_tenant.domain != domain {
            return Ok(candidate);
        }
    }
    Ok(candidate)
}

fn find_available_port(cli: &Cli, state: &ProvisionState) -> Result<u16, ProvisionError> {
    for port in cli.min_port..=cli.max_port {
        let reserved = state.tenants.values().any(|value| value.port == port);
        if !reserved && is_port_available(port) {
            return Ok(port);
        }
    }
    Err(ProvisionError::Message(
        "no available ports in configured range".to_string(),
    ))
}

fn is_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn create_directories(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    fs::create_dir_all(&runtime.tenant_dir)?;
    fs::create_dir_all(&cli.env_dir)?;
    fs::create_dir_all(&cli.nginx_available_dir)?;
    fs::create_dir_all(&cli.nginx_enabled_dir)?;
    if let Some(state_parent) = cli.state_file.parent() {
        fs::create_dir_all(state_parent)?;
    }

    // tenants_root (/var/checkio) must be world-traversable so nginx can reach public/
    set_dir_mode(&cli.tenants_root, 0o755)?;

    run_chown(
        &runtime.tenant_dir,
        &format!("{}:{}", cli.service_user, cli.service_user),
        "chown_tenant_dir",
        steps,
    )?;
    set_dir_mode(&runtime.tenant_dir, 0o751)?;
    steps.push(StepStatus {
        name: "create_directories".to_string(),
        status: "ok".to_string(),
        detail: runtime.tenant_dir.display().to_string(),
    });
    Ok(())
}

fn create_database_file(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    if !runtime.tenant_dir.exists() {
        return Err(ProvisionError::Message(format!(
            "tenant directory missing: {}",
            runtime.tenant_dir.display()
        )));
    }
    let db_path = runtime.tenant_dir.join("restaurant.db");
    if !db_path.exists() {
        let mut file = fs::File::create(&db_path)?;
        file.write_all(b"")?;
    }
    set_file_mode(&db_path, 0o640)?;
    run_chown(
        &db_path,
        &format!("{}:{}", cli.service_user, cli.service_user),
        "chown_database_file",
        steps,
    )?;
    steps.push(StepStatus {
        name: "create_database".to_string(),
        status: "ok".to_string(),
        detail: db_path.display().to_string(),
    });
    Ok(())
}

fn run_migrations(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let migrations_path = cli.backend_root.join("migrations");
    run_command(
        &cli.sqlx_bin,
        &[
            "migrate",
            "run",
            "--database-url",
            &runtime.database_url,
            "--source",
            &migrations_path.display().to_string(),
        ],
        Some(&cli.backend_root),
        "run_migrations",
        steps,
    )?;
    Ok(())
}

fn enable_service(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    match cli.service_enable_mode {
        ServiceEnableMode::None => {
            steps.push(StepStatus {
                name: "enable_service".to_string(),
                status: "skipped".to_string(),
                detail: "service-enable-mode is none".to_string(),
            });
            Ok(())
        }
        ServiceEnableMode::Runtime => run_command(
            "systemctl",
            &["--runtime", "enable", &runtime.service_name],
            None,
            "enable_service",
            steps,
        ),
        ServiceEnableMode::Persistent => run_command(
            "systemctl",
            &["enable", &runtime.service_name],
            None,
            "enable_service",
            steps,
        ),
    }
}

fn create_seed_user(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let (name, email, password) = match (
        cli.seed_name.as_deref(),
        cli.seed_email.as_deref(),
        cli.seed_password.as_deref(),
    ) {
        (Some(n), Some(e), Some(p)) => (n, e, p),
        _ => {
            steps.push(StepStatus {
                name: "create_seed_user".to_string(),
                status: "skipped".to_string(),
                detail: "no seed user flags provided".to_string(),
            });
            return Ok(());
        }
    };

    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ProvisionError::Message(format!("failed to hash password: {e}")))?
        .to_string();

    let id = uuid::Uuid::new_v4().to_string();
    let escape = |s: &str| s.replace('\'', "''");
    let db_path = runtime.database_url.trim_start_matches("sqlite:");
    let sql = format!(
        "INSERT INTO users (id, name, email, password_hash, role, is_active) \
         VALUES ('{}', '{}', '{}', '{}', '{}', 1);",
        id,
        escape(name),
        escape(email),
        escape(&hash),
        escape(&cli.seed_role),
    );

    run_command("sqlite3", &[db_path, &sql], None, "create_seed_user", steps)
}

fn render_env_file(cli: &Cli, runtime: &RuntimeContext) -> String {
    format!(
        "DATABASE_URL={}\nHOST=0.0.0.0\nPORT={}\nJWT_SECRET={}\nCLIENT_ORIGIN={}\n",
        runtime.database_url, runtime.port, cli.jwt_secret, runtime.client_origin
    )
}

fn render_nginx_config(
    runtime: &RuntimeContext,
    has_frontend: bool,
    tls: Option<(&PathBuf, &PathBuf)>,
) -> String {
    let upstream = format!("checkio_{}", runtime.tenant.replace('-', "_"));

    let listen_block = if let Some((cert, key)) = tls {
        format!(
            "    listen 443 ssl;
    server_name {domain};
    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;",
            domain = runtime.domain,
            cert = cert.display(),
            key = key.display(),
        )
    } else {
        format!(
            "    listen 80;\n    server_name {domain};",
            domain = runtime.domain
        )
    };

    let http_redirect = if tls.is_some() {
        format!(
            "server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}

",
            domain = runtime.domain
        )
    } else {
        String::new()
    };

    let locations = if has_frontend {
        format!(
            "
    root {public_dir};
    index index.html;

    location /api/ {{
        proxy_pass http://{upstream};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}

    location / {{
        try_files $uri $uri/ /index.html;
    }}",
            public_dir = runtime.public_dir.display(),
            upstream = upstream,
        )
    } else {
        format!(
            "
    location / {{
        proxy_pass http://{upstream};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}",
            upstream = upstream,
        )
    };

    format!(
        "upstream {upstream} {{
    server 127.0.0.1:{port};
}}

{http_redirect}server {{
{listen_block}
{locations}
}}
",
        upstream = upstream,
        port = runtime.port,
        http_redirect = http_redirect,
        listen_block = listen_block,
        locations = locations,
    )
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), ProvisionError> {
    fs::create_dir_all(dst)?;
    set_dir_mode(dst, 0o755)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
            set_file_mode(&dst_path, 0o644)?;
        }
    }
    Ok(())
}

fn deploy_frontend(
    cli: &Cli,
    runtime: &RuntimeContext,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let dist = match &cli.frontend_dist {
        Some(p) => p,
        None => {
            steps.push(StepStatus {
                name: "deploy_frontend".to_string(),
                status: "skipped".to_string(),
                detail: "--frontend-dist not provided".to_string(),
            });
            return Ok(());
        }
    };

    if !dist.exists() {
        return Err(ProvisionError::Message(format!(
            "frontend dist directory not found: {}",
            dist.display()
        )));
    }

    if runtime.public_dir.exists() {
        fs::remove_dir_all(&runtime.public_dir)?;
    }

    copy_dir_all(dist, &runtime.public_dir)?;
    run_chown(
        &runtime.public_dir,
        &format!("{}:{}", cli.service_user, cli.service_user),
        "chown_public_dir",
        steps,
    )?;

    steps.push(StepStatus {
        name: "deploy_frontend".to_string(),
        status: "ok".to_string(),
        detail: format!(
            "{} -> {}",
            dist.display(),
            runtime.public_dir.display()
        ),
    });
    Ok(())
}

fn ensure_symlink(target: &Path, link: &Path) -> Result<SymlinkBackup, ProvisionError> {
    let previous_target = if link.exists() || link.symlink_metadata().is_ok() {
        Some(fs::read_link(link)?)
    } else {
        None
    };

    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }

    if link.exists() || link.symlink_metadata().is_ok() {
        fs::remove_file(link)?;
    }
    symlink(target, link)?;

    Ok(SymlinkBackup {
        path: link.to_path_buf(),
        previous_target,
    })
}

fn restore_symlink(backup: SymlinkBackup) -> Result<(), ProvisionError> {
    if backup.path.exists() || backup.path.symlink_metadata().is_ok() {
        fs::remove_file(&backup.path)?;
    }
    if let Some(target) = backup.previous_target {
        symlink(target, backup.path)?;
    }
    Ok(())
}

fn run_chown(
    path: &Path,
    owner_group: &str,
    step_name: &str,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    run_command(
        "chown",
        &[owner_group, &path.display().to_string()],
        None,
        step_name,
        steps,
    )
}

fn set_dir_mode(path: &Path, mode: u32) -> Result<(), ProvisionError> {
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn set_file_mode(path: &Path, mode: u32) -> Result<(), ProvisionError> {
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn atomic_write_with_backup(path: &Path, content: &[u8]) -> Result<FileBackup, ProvisionError> {
    let previous = fs::read(path).ok();
    atomic_write(path, content)?;
    Ok(FileBackup {
        path: path.to_path_buf(),
        previous,
    })
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn restore_backup(backup: FileBackup) -> Result<(), ProvisionError> {
    if let Some(content) = backup.previous {
        atomic_write(&backup.path, &content)?;
    } else if backup.path.exists() {
        fs::remove_file(backup.path)?;
    }
    Ok(())
}

fn run_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    step_name: &str,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().map_err(|error| {
        ProvisionError::Message(format!("failed to execute '{}': {}", program, error))
    })?;

    if output.status.success() {
        steps.push(StepStatus {
            name: step_name.to_string(),
            status: "ok".to_string(),
            detail: format!("{} {}", program, args.join(" ")),
        });
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "command failed without output".to_string()
    };
    steps.push(StepStatus {
        name: step_name.to_string(),
        status: "failed".to_string(),
        detail: detail.clone(),
    });
    Err(ProvisionError::Message(format!(
        "{} failed: {}",
        step_name, detail
    )))
}

fn verify_port_listening(port: u16, steps: &mut Vec<StepStatus>) -> Result<(), ProvisionError> {
    let addr = format!("127.0.0.1:{port}");
    let socket_addr = addr
        .parse()
        .map_err(|_| ProvisionError::Message("invalid local socket address".to_string()))?;
    TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)).map_err(|error| {
        ProvisionError::Message(format!("backend is not listening on {}: {}", addr, error))
    })?;
    steps.push(StepStatus {
        name: "verify_port_listening".to_string(),
        status: "ok".to_string(),
        detail: addr,
    });
    Ok(())
}

fn verify_http_local_health(
    port: u16,
    health_path: &str,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{health_path}")
    };
    let url = format!("http://127.0.0.1:{port}{path}");
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let response = client.get(&url).send()?;
    let status = response.status();
    if status.is_server_error() {
        steps.push(StepStatus {
            name: "http_health_check".to_string(),
            status: "failed".to_string(),
            detail: format!("{} -> HTTP {}", url, status.as_u16()),
        });
        return Err(ProvisionError::Message(format!(
            "HTTP health check failed with status {}",
            status
        )));
    }
    steps.push(StepStatus {
        name: "http_health_check".to_string(),
        status: "ok".to_string(),
        detail: format!("{} -> HTTP {}", url, status.as_u16()),
    });
    Ok(())
}

fn verify_https_health(
    runtime: &RuntimeContext,
    health_path: &str,
    steps: &mut Vec<StepStatus>,
) -> Result<(), ProvisionError> {
    let path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{health_path}")
    };
    let url = format!("https://{}{}", runtime.domain, path);
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let response = client.get(&url).send()?;
    let status = response.status();
    if status.is_server_error() {
        steps.push(StepStatus {
            name: "https_health_check".to_string(),
            status: "failed".to_string(),
            detail: format!("{} -> HTTP {}", url, status.as_u16()),
        });
        return Err(ProvisionError::Message(format!(
            "HTTPS health check failed with status {}",
            status
        )));
    }
    steps.push(StepStatus {
        name: "https_health_check".to_string(),
        status: "ok".to_string(),
        detail: format!("{} -> HTTP {}", url, status.as_u16()),
    });
    Ok(())
}
