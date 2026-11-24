# Couche d'abstraction plateforme — `platform.rs` (phase 1)

> Statut : **✅ implémentée (phase 1)**. C'est la phase 1 de
> [platforms.md](platforms.md) §5 : **primitives OS uniquement, aucun backend de
> confinement** (pas de seatbelt, pas de WSL2, pas de landlock dans cette PR).
> Principes inchangés : fail-closed, `#![forbid(unsafe_code)]` intact, la console
> applique elle-même validation, limites et kill, et chaque plateforme ajoutée
> est une surface d'attaque à auditer.

## 1. Objectif et périmètre

Un seul module connaît l'OS ; tout le reste du code passe par ses fonctions.

- **macOS** (plateforme cible visée, décision 2026-11-24) **+ Linux** (même
  code, gardé dans la matrice CI) : comportement **inchangé** — la CI tourne
  déjà sur ubuntu + macOS ; tous les tests existants doivent passer sans
  modification de sémantique.
- **Windows natif** : le code **compile** et tourne **fail-closed** là où il n'y a
  pas de backend : `trusted` → `denied` (pas de shell), limites backend de
  `trusted.toml` → `denied` (déjà le cas via `backend_limit()`). Les commandes
  whitelist in-process et `resolve()` fonctionnent normalement.
- **Windows réel = WSL2** (la console tourne dans la VM, build Linux inchangé
  dedans) : hors scope de cette PR — voir [platforms.md](platforms.md) §3
  (phase 4) pour le lanceur `wsl.exe`, la traduction des chemins et la fermeture
  des ponts (`/mnt/c`, interop `.exe`, réseau NAT).

Hors scope : seatbelt (macOS), WSL2 (Windows), landlock par spawn (Linux),
plugins, commandes `git` whitelist.

## 2. Inventaire : ce qui est OS-spécifique aujourd'hui

| # | Point | Aujourd'hui (unix-only) | Abstraction `platform.rs` | Linux / macOS | Windows natif |
|---|---|---|---|---|---|
| 1 | Identité fichier (dev/ino) | `std::os::unix::fs::MetadataExt` (`dev()`, `nlink()`) — `resolve.rs:2,98-106` | `FileId { dev, ino }`, `file_id(&Metadata) -> Option<FileId>`, `file_id_of_path(&Path)`, `hardlink_escape(root, target) -> bool` | `MetadataExt` (std) | `winapi-util` (`GetFileInformationByHandle` : volume serial + file index + `nNumberOfLinks`) |
| 2 | `canonicalize` verbatim `\\?\` | `fs::canonicalize` | `canonicalize(&Path) -> io::Result<PathBuf>` | `std::fs::canonicalize` | `dunce::canonicalize` |
| 3 | Composants Windows (`C:`, `\`) | `normalize()` ignore `Component::Prefix` — `resolve.rs:52-66` | `looks_like_windows_path(&str) -> bool` ; `normalize()` rejette fail-closed | rejet de tout `\` (jamais un séparateur sur unix) + des `C:` | rejet de tout `:` (drive `C:…` + NTFS ADS `file:stream`) et des préfixes UNC `\\…` ; les relatifs natifs `src\a.rs` restent valides |
| 4 | Comparaison de chemins / casse | `starts_with` byte-à-byte | comparer uniquement des chemins passés par `platform::canonicalize` (casse réelle du disque) | inchangé | idem via `dunce` |
| 5 | Shell trusted | `SHELL = "/bin/sh"` — `trusted.rs:15` | `shell() -> Option<&'static str>` | `Some("/bin/sh")` | `None` → `trusted` denied |
| 6 | Env minimal / `PATH` (`:` vs `;`) | `DEFAULT_PATH_ENV` en dur — `trusted.rs:16` | `default_path_entries() -> Vec<PathBuf>` + `env::join_paths` | idem | chemins Windows, `;` géré par std |
| 7 | Nouveau groupe de processus | `process_group(0)` — `trusted.rs:440-443` | `set_new_process_group(&mut Command)` | `CommandExt::process_group(0)` | no-op (pas de pgid POSIX) |
| 8 | Kill de l'arbre au timeout | `kill_group_unix` : `kill -KILL -<pgid>` via le shell — `trusted.rs:531-552` | `kill_process_tree(&mut Child)` ; `child.kill()` **toujours** exécuté en premier | kill du pgid via le shell | `taskkill /T /F /PID <pid>` (spawn, best-effort) |
| 9 | Exit code | `128+signal` via `ExitStatusExt` — `trusted.rs:554-560` | `exit_code(&ExitStatus) -> u16` | code, ou `128+signal` | `code().unwrap_or(1)` tronqué (documenté ; aucun processus exécuté en phase 1) |
| 10 | Symlinks de test | `std::os::unix::fs::symlink` — `tests/evasion.rs:3`, `resolve.rs:154`, `commands/grep.rs:1579,1736` | `testutil::symlink(orig, link)` | `fs::symlink` | `symlink_file` / `symlink_dir` ; skip gracieux si privilège absent |
| 11 | Modes unix 0o755/0o555 (tests) | `PermissionsExt` — tests | `testutil::set_exec_mode(&Path)` | `from_mode(0o755)` | no-op |

Notes :

- `std::os::windows::fs::MetadataExt::{volume_serial_number, file_index}` existe
  mais est **nightly-only** (feature `windows_by_handle`), et `same-file` 1.x
  n'expose `dev()`/`ino()` que sur unix → d'où `winapi-util` (déjà transitif via
  `same-file`, 0 nouveau transitif) qui lit volume serial + file index +
  `nNumberOfLinks` via `GetFileInformationByHandle`. `file_id(&Metadata)`
  retourne `None` sur Windows ; on passe par `file_id_of_path`.
- Chemins internes : tout chemin interne (résultats du walker/globs) est
  normalisé en relatif avec séparateurs `/` (`platform::path_to_slash`) avant
  de repartir dans `resolve()` — ainsi un root absolu `C:\...` ne fait jamais
  passer un chemin interne par le rejet fail-closed réservé à l'input.
- Sémantique hardlink sur Windows : on refuse si le volume diffère de celui du
  root **ou** si `nNumberOfLinks > 1` (le link count existe bien sur Windows via
  `GetFileInformationByHandle`). Résiduel : sur ReFS l'index de fichier 64 bits
  n'est pas garanti unique (même caveat que `same-file`), documenté dans
  [security.md](security.md). Fail-closed avant tout : identité illisible = refus.

## 3. Dépendances

| Crate | Rôle | Coût | Licence (allow-list `deny.toml`) |
|---|---|---|---|
| `winapi-util` 0.1 | `FileId` + link count sur Windows (`GetFileInformationByHandle`) | **déjà dans `Cargo.lock`** (transitif via `same-file`) → 0 nouveau transitif ; dep cible `cfg(windows)` | Unlicense/MIT ✅ |
| `dunce` | `canonicalize` sans préfixe `\\?\` sur Windows | 1 crate, 0 dépendance ; dep cible `cfg(windows)` | CC0/MIT-0/Apache-2.0 ✅ |

Le reste est en `std` (`std::os::{unix,windows}`, `env::join_paths`, `process`) ou
en spawn de binaires (`taskkill`) — cohérent avec « zéro FFI/`unsafe` chez nous ».

## 4. Design de `platform.rs` (clean, testable)

```
src/platform.rs          # API publique (fonctions libres) + ré-exports + doc
src/platform/macos.rs    # #[cfg(any(target_os = "macos", target_os = "linux"))] : impls macOS (cible) + Linux
src/platform/windows.rs  # #[cfg(windows)]   : impls Windows natif (fail-closed)
```

- **Fonctions libres, pas de traits** : le code appelant ne change pas de forme ;
  un trait n'est introduit que si un besoin de mock apparaît. La logique pure est
  extraite en fonctions sans effet de bord, testables telles quelles :
  `looks_like_windows_path`, `group_kill_args(pgid)`, `taskkill_args(pid)`,
  `hardlink_escape` sur des `FileId` synthétiques, construction de l'env trusted.
- **Fail-closed par défaut** : toute primitive incertaine renvoie `None`/`Err`,
  traduit en `denied` par l'appelant.
- **Aucune logique métier** dans `platform.rs`, que des primitives OS.

API (signatures indicatives) :

```rust
pub fn canonicalize(path: &Path) -> std::io::Result<PathBuf>;
pub struct FileId { pub dev: u64, pub ino: u64 }
pub fn file_id(meta: &std::fs::Metadata) -> Option<FileId>;
pub fn hardlink_escape(root_meta: &std::fs::Metadata, meta: &std::fs::Metadata) -> bool;
pub fn looks_like_windows_path(input: &str) -> bool;
pub fn shell() -> Option<&'static str>;
pub fn default_path_entries() -> Vec<PathBuf>;
pub fn set_new_process_group(cmd: &mut std::process::Command);
pub fn kill_process_tree(child: &mut std::process::Child, shell: Option<&str>);
pub fn exit_code(status: &std::process::ExitStatus) -> u16;
#[doc(hidden)] pub mod testutil { pub fn symlink(...); pub fn set_exec_mode(...); }
```

## 5. Branchements dans le code existant

| Fichier | Changement |
|---|---|
| `lib.rs` | `pub mod platform;` |
| `resolve.rs` | `MetadataExt` → `platform::{file_id, hardlink_escape}` ; `fs::canonicalize` → `platform::canonicalize` ; `normalize()` rejette `Component::Prefix` et toute entrée `looks_like_windows_path` |
| `trusted.rs` | `SHELL` → `platform::shell()` (`None` → denied) ; `process_group` → `platform::set_new_process_group` ; `kill_process_group`/`kill_group_unix` → `platform::kill_process_tree` ; `exit_code` → `platform::exit_code` ; `DEFAULT_PATH_ENV` → `env::join_paths(platform::default_path_entries())` |
| `tests/evasion.rs`, tests de `resolve.rs`, tests de `commands/grep.rs` | `std::os::unix::fs::symlink` → `platform::testutil::symlink` |

## 6. Stratégie de tests

- **Unit cross-OS (sans `cfg`)** : toute la logique pure de §4 (validation des
  chemins Windows, args du kill, `hardlink_escape` synthétique, env trusted)
  tourne sur ubuntu + macOS + Windows.
- **Unit/e2e `cfg(any(target_os = "macos", target_os = "linux"))`** : identité
  fichier réelle, kill du groupe de processus
  (test existant `timeout_kills_the_whole_process_group`), symlinks → ubuntu + macOS.
- **Unit/e2e `cfg(windows)`** : `file_id_of_path` via `winapi-util`, `canonicalize` sans
  préfixe verbatim, `taskkill_args` → runner `windows-latest`. Sur les runners
  GitHub `windows-latest` le Developer Mode est actif : les symlinks de test
  fonctionnent ; si la création échoue (permission), le test **skippe**
  (uniquement sur Windows, jamais silencieusement sur macOS/Linux).
- **e2e nouveaux scénarios Windows** : `trusted x` → `denied` (pas de shell) ;
  `resolve()` refuse `C:\foo`, `a\b`, `..` →
  `tests/evasion.rs` / `tests/e2e.rs`.
- **proptest** : l'invariant « `resolve()` ne renvoie jamais rien hors du root »
  doit passer sur les 3 OS (cœur portable).
- **Fuzz / mutants nightly** : inchangés, ubuntu-only (ASan incompatible musl).

## 7. CI

- La PR d'implémentation ajoute `windows-latest` à la matrice du job `test`
  (`.github/workflows/ci.yml`) : `os: [ubuntu-latest, macos-latest, windows-latest]`.
  **Pas avant** : le code actuel ne compile pas sur Windows (`std::os::unix`
  inconditionnel dans `resolve.rs`) — la matrice Windows s'active donc dans la
  même PR que `platform.rs`, pour garder la CI verte à chaque commit.
- Optionnel : `cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc`
  sur le runner ubuntu pour attraper tôt les divergences de compilation.
- `fmt` / `clippy` / `deny`+`audit` : inchangés (ubuntu).
- Nightly (fuzz long + mutants) : inchangé, ubuntu-only. Garde-fou anti-fork :
  inchangé, s'applique à tous les jobs.

## 8. Plan de PR

Une seule PR, testable, CI verte sur les 3 OS :

1. `platform.rs` + `platform/macos.rs` + `platform/windows.rs` + `testutil` ;
2. branchements `resolve.rs` / `trusted.rs` / tests (tableau §5) ;
3. `Cargo.toml` : `+ dunce`, `+ winapi-util` en `[target.'cfg(windows)'.dependencies]` (`cargo deny` / `cargo audit` restent verts) ;
4. `ci.yml` : matrice `+ windows-latest` ;
5. docs : cette spec + sommaire `spec/README.md` + `structure.md` + `ROADMAP.md`.

**Testable** : CI verte ubuntu + macOS + Windows ; sur macOS/Linux tous les
tests existants passent sans changement de sémantique ; sur Windows, whitelist +
`resolve()` fonctionnent et `trusted` / limites backend sont
refusés fail-closed.

Les phases suivantes restent celles de [platforms.md](platforms.md) §5 : backend
seatbelt (macOS), WSL2 (Windows), landlock par spawn (Linux) — chacune s'appuie
sur `platform.rs` comme point d'ancrage unique.
