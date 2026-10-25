# Vaultwarden

Rust (Rocket + Diesel) reimplementation of the Bitwarden server API. Single binary crate plus a tiny proc-macro crate in `macros/` (workspace member).

## Build / verify

- **A DB backend feature is mandatory**; there is no default. Bare `cargo build`/`cargo test` fails via `compile_error!` in `build.rs`. Use `--features sqlite` for quick work.
- Toolchain is pinned in `rust-toolchain.toml`; MSRV is `rust-version` in `Cargo.toml`. CI builds both, so don't use std APIs newer than the MSRV.
- CI (`.github/workflows/build.yml`) runs with `RUSTFLAGS=-Dwarnings`, and the workspace lints in `Cargo.toml` are strict (clippy `pedantic` and more, `unsafe_code = forbid`). Any warning fails the build. Before finishing:
  - `cargo fmt --all -- --check` (max_width 120, `use_small_heuristics = "Off"`)
  - `cargo clippy --features sqlite,mysql,postgresql,enable_mimalloc,s3 -- -D warnings`
  - `cargo test --features sqlite,mysql,postgresql`
- CI also builds each backend on its own (`sqlite`, `mysql`, `postgresql`), so code gated with `#[cfg(...)]` has to compile in every combination.
- Building mysql/postgresql needs `libmariadb-dev-compat` and `libpq-dev` (or the platform equivalents).
- Pass a single test as `cargo test --features sqlite <name>`. Unit tests sit in `#[cfg(test)]` modules inside `src/`, and there is no `tests/` dir.
- `typos` runs in CI and pre-commit; add allowed words to `.typos.toml`.

## Database

- `build.rs` sets short cfgs: write `#[cfg(sqlite)]`, `#[cfg(mysql)]`, `#[cfg(postgresql)]`, `#[cfg(s3)]`, not `#[cfg(feature = "...")]`.
- One shared `src/db/schema.rs` covers all backends. Update it by hand when you add columns.
- Every schema change needs a migration with the **same directory name** in `migrations/sqlite`, `migrations/mysql` and `migrations/postgresql`, each written in that dialect (see `2026-10-07-120000_add_org_policy_revision_date` for UTC timestamp handling). Migrations are embedded at compile time from those three dirs only (`src/db/mod.rs`). `migrations/cockroachdb` is not embedded.
- Model DB access goes through the `db_run!` macro, with per-backend arms where SQL differs.

## Config

- All env/config options are declared in the `make_config!` block in `src/config.rs`. The env var is the field name in uppercase. Add or change the matching documented entry in `.env.template` in the same change.
- Bitwarden client feature flags go in `SUPPORTED_FEATURE_FLAGS` in `src/config.rs`, and they're also documented in `.env.template`.

## Templates / static

- Handlebars templates in `src/static/templates/` are compiled in through `include_str!` in `load_templates` (`src/config.rs`). A new template must be registered there. Emails need both `name.hbs` (text) and `name.html.hbs` (html).
- The web vault is not in this repo (`web-vault/` is gitignored, `WEB_VAULT_FOLDER`). Use `WEB_VAULT_ENABLED=false` to run the API without it.

## Docker

- `docker/Dockerfile.debian` and `docker/Dockerfile.alpine` are generated. Edit `docker/Dockerfile.j2` / `DockerSettings.yaml`, then run `make` in `docker/`. CI fails on any diff.

## Integration tests

- Playwright e2e tests are in `playwright/` and use docker compose with `playwright/test.env`. See `playwright/README.md`, e.g. `docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite`. They're slow, and CI doesn't run them.

## Agent skills

### Issue tracker

GitHub Issues on the `itsmeyaw/vaultwarden` fork (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-label vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
