# État des lieux — la-console (2026-11-24)

Vérifié contre le code de `main` au commit `7e54af4` (PR #41).
Document de travail, non indexé dans `spec/README.md`.

## Décisions de direction (2026-11-24)

1. **✅ FAIT — Supprimer le mode server** : `--mode server`, le re-exec `unshare` userns+chroot
   (`sandbox.rs` supprimé), la mini-image de cage (`--sandbox-busybox` / `--sandbox-busybox-sha256` /
   `--sandbox-tools-dir`, remount read-only, `trusted` via `busybox sh` dans la cage) retirés,
   ainsi que `Ctx::sandboxed`/`Ctx::sandbox_shell`, le paramètre `cage_shell` de
   `kill_process_tree`, et la dépendance `walkdir` (staging de cage). Le flag `--mode`
   disparaît du CLI.
2. **✅ FAIT — `platform.rs` : renommer `unix` → `macos`** (cette PR) — la cible
   visée est macOS, pas Linux générique : `platform/unix.rs` est devenu
   `platform/macos.rs`, et les `cfg(unix)` du crate sont devenus
   `cfg(any(target_os = "macos", target_os = "linux"))` partout où le code référence
   les primitives `platform` (Linux garde le même code via la matrice CI).
   Windows natif reste fail-closed tel quel.
3. **✅ DÉCISION ACTÉE (2026-11-24) — backend sandbox OS = crate `nono`** (nolabs-ai, Apache-2.0,
   v0.79, ~28K SLoC, ~3,6K stars — Landlock Linux ≥ 5.13 / Seatbelt macOS / WSL2 pour Windows),
   **via une couche d'abstraction unique** `src/sandbox_backend.rs` (`apply(profile)` +
   `support_info()`) : toute référence à `nono::` vit dans ce seul module, donc un breaking change
   pre-1.0 de nono ne touche qu'un seul fichier à adapter. Version épinglée dans `Cargo.toml` +
   `Cargo.lock` committé, auditée avant chaque bump. Intégration prévue (~1 PR) : helper arg0
   `la-console __sandbox_helper <profil.json> -- <cmd…>` (profil depuis `trusted.toml` + `Limits`)
   → `Sandbox::apply_auto(&CapabilitySet)` → exec ; fail-closed si backend non supporté
   (noyau < 5.13, ABI Landlock réseau < v4) → `denied`. `#![forbid(unsafe_code)]` intact (la FFI
   privée Apple `sandbox_init` est dans la dep, pas chez nous).
   **Reste chez nous quoi qu'il arrive** : proxy réseau fin `network = "proxy"` (allowlist de
   domaines + anti-DNS-rebinding 169.254.0.0/16 — `nono-proxy` est async/tokio, donc thread dédié
   ou mini-proxy maison), rlimits `nix` pour `mem_bytes`/`cpus`/`max_write_bytes` (non couvert par
   nono hors cgroups Linux → fail-closed entre-temps), lanceur WSL2 `wsl.exe` (Windows natif
   fail-closed ; nono tourne *dans* WSL2), timeout + kill du groupe (`platform.rs`, inchangé).
   Alternative écartée : backends 100 % maison (SBPL + `sandbox-exec` + crate `landlock` officielle +
   mini-proxy maison) ≈ 6 PR / 2–4 semaines + revue sécurité interne. Détails : `spec/platforms.md` §3.

## A. Ce qui est livré dans le code (PR #2 → #41)

### Cœur / sécurité

- `lib.rs` avec `#![forbid(unsafe_code)]` ; protocole JSON ligne par ligne synchrone (`console.rs`, PR #4)
- `parse.rs` : parser shell cadré (shell-words + globs wax) → arbre `Seq`/`Pipe`/`Simple`, règles de parse fail-closed : `TrustedInPipe` (trusted = tête de pipe uniquement, #30), `SedStreamNeedsPipe`, `SedInPlaceInPipe`, `SubInPipe`, `TeeNeedsPipe` (#35, #37) ; proptests `pipe_has_misplaced_trusted` / `pipe_has_stream_forbidden`
- `resolve.rs` : confinement root (unique point de passage) — canonicalize, `..`, symlinks, hardlinks via `FileId`, rejet fail-closed des chemins Windows (#6, #41)
- `sink.rs` : interface d'écriture unique — `FileSink` (validation avant ouverture, masquage secrets, `DiskQuota`), `CallerSink`, `PipeSink` (#8)
- Erreurs structurées `kind` = `denied`/2, `limit`/3, `fail`/1 (#19) ; `--max-output-bytes`, `>>`, redirection `<` (#22) ; timeout par commande (thread + `recv_timeout`, 30 s) et quota disque par commande (16 MiO)

### Whitelist — 18 commandes dans le registre `COMMANDS`

`commands/mod.rs:314-480` (source de vérité de `help` et du dispatcher) :

- v1 : `cat`, `ls [--all]`, `echo >/>>`, `grep`, `sub`, `sed s///[g]` (preview / `-i`), `http` (localhost only, reqwest blocking + rustls), `help` (#9–#13, #19, #20)
- whitelist-expansion livrée : flags grep paquet A `-F -e -E -i -v -w -x -n -c -o -l -L -m -q -B/-A/-C` (#32) ; globs `--include/--exclude/--exclude-dir` + `-f/--file` + `--exclude-from` (#33) ; filtres de flux `head/tail/wc/sort/uniq/cut/tr` (#34) ; `sed` sur flux (#35) ; `json <selector>` (#36) ; `tee <path>` en position de pipe (#37)

### Trusted (#14 → #39)

- `trusted.toml` seul format (`.toml`, `deny_unknown_fields`), sha256 re-vérifié avant **chaque** exécution (`--trusted-file`/`--trusted-sha256`)
- Par entrée : `command`, `description`, `no_path_check`, `timeout_secs`, `max_write_bytes`, `mem_bytes`, `cpus`, `network`, `flags` (allowlist des `-...`)
- **Plus d'`ulimit`** (#39) : timeout wall-clock + kill du **groupe de processus** par la console (`process_group(0)`)
- Limites backend (`max_write_bytes`/`mem_bytes`/`cpus`/`network`) : parsées, **refusées `denied` fail-closed** tant qu'aucun backend OS n'existe (`backend_limit()`, `trusted.rs:87-99`)
- Shell via `platform::shell()` : `/bin/sh` en mode user, `busybox sh` dans la cage, `None` → `denied`

### Sandbox serveur (#24, #26, #27) — ⚠️ prévu d'être supprimé (décision 1)

- `--mode user|server` : `server` Linux-only, re-exec via `unshare --user --map-root-user --mount --root <root> --wd /`, exit 2 ailleurs
- Mini-image de cage : `--sandbox-busybox` (statique, vérifié ELF + `ldd`, sha256 optionnel) → `/bin/busybox` + applets ; `--sandbox-tools-dir` → `/opt/la-console-tools` avec deps `ldd` ; remount **read-only fail-closed** (exit 2) au démarrage (#27)
- Sans busybox stagé, `trusted` = `denied` en mode serveur

### Multi-plateforme phase 1 (#41)

- `platform.rs` + `platform/{unix,windows}.rs` : `FileId`/`hardlink_escape`, `canonicalize` (dunce), `looks_like_windows_path`, `path_to_slash`, `shell()`, `set_new_process_group`, `kill_process_tree` (kill pgid / `taskkill /T`), `exit_code`, `testutil` — ✅ `unix` renommé `macos` (décision 2, cette PR)
- Deps `cfg(windows)` : `dunce` + `winapi-util` ; CI matrice **ubuntu + macOS + windows-latest**
- Windows natif : compile et tourne fail-closed — whitelist + `resolve()` OK, `trusted` / `--mode server` / limites backend refusés

### Tests / CI

- `tests/` : `evasion.rs`, `parse.rs` (proptests), `commands.rs`, `e2e.rs` (binaire réel), `json.rs`, `stream_filters.rs`, `tee.rs`
- `fuzz/` : `parse_input`, `resolve_path` ; nightly fuzz 30 min + `cargo mutants` seuil ≥ 80 % (#15, #16, #21)
- Gate PR : fmt, clippy `-D warnings`, tests 3 OS, llvm-cov, `deny`+`audit`, fuzz ~5 min, garde-fou anti-fork

## B. Prévu mais PAS fait (backlog — specs seulement, aucun code)

1. **Backends de confinement OS par spawn** : seatbelt (macOS, `sandbox-exec` + profil SBPL), landlock (Linux), WSL2 (Windows), via helper arg0 `la-console __sandbox_helper <profil.json> -- <cmd…>`. Rien dans le code (seuls des commentaires, ex. `trusted.rs:37`, `platform/windows.rs:3`). C'est aussi ce backend qui appliquera `max_write_bytes`/`mem_bytes`/`cpus`/`network` de `trusted.toml`. (La cage userns+chroot du mode serveur, elle, est supprimée — décision 1.) **Option retenue** : la crate `nono` (décision 3 actée) couvre Landlock+Seatbelt+réseau en une dépendance, via `src/sandbox_backend.rs`.
2. **Lanceur WSL2** pour Windows réel (`wsl.exe`, traduction de chemins, fermeture des ponts `/mnt/c`, interop `.exe`, réseau NAT, socket docker).
3. **Commandes `git` whitelist read-only** (`status`/`diff`/`log`/`show`/`branch`/`rev-parse`, via `git2` ou binaire épinglé) — mutations restent `trusted`.
4. **`plugins.json` + `plugins.rs`** : binaires épinglés par l'humain (`--plugins-file`/`--plugins-sha256`), sous-commandes, `url_hosts`, limites — zéro code.
5. `grep -a` au sens GNU (`--text`) — à trancher (conflit avec `-a` = `--all`).
6. **Vérification formelle** (Kani/Prusti) du parser — envisagée, rien fait.
7. Discussions ouvertes : synchrone vs async (implémentation 100 % synchrone volontaire), répartition des responsabilités harness/console.

## C. Docs en retard sur le code (à intégrer dans une réécriture)

- `ROADMAP.md` : étapes 5, 6, v2-étape 2, « prochaine fournée », backlog pipe-trusted + whitelist-expansion + Windows — toutes livrées (#13/#14/#26/#30/#32-#37/#39/#41) mais encore marquées 🚧 « cette PR » ; étape 6 décrit `trusted.txt` + `ulimit` + « scan des changements » (le scan n'existe pas dans le code, seul le sha256 re-vérifié avant chaque exécution, `trusted.rs:150-156`)
- `spec/README.md` : `tee` « reste optionnel » → fait (#37) ; `trusted.toml` « prévu » → fait (#39)
- `spec/commands.md:300-304` : « scan des changements (diff du fichier + code de test) » — **absent du code**, à supprimer
- `spec/plugins.md` : `.txt` « compat lecture » → retiré (#39, `trusted.rs:28`) ; pipe `trusted → whitelist` 🚧 → #30 ; « Hors scope ❌ Windows » → phase 1 faite (#41) ; phases 2/4/5 à cocher (#30/#39/#41)
- `spec/platforms.md` : `platform.rs` « prévu » → fait (#41) ; inventaire `SHELL = /bin/sh`, script `ulimit` obsolète ; §5 phases 1-2 à cocher
- `spec/testing.md:57` : matrice CI « ubuntu + macOS » → ajouter `windows-latest` (`.github/workflows/ci.yml:51`)
- `spec/structure.md` : manque `json.rs`/`tee.rs` dans `commands/`, `json.rs`/`stream_filters.rs`/`tee.rs` dans `tests/` ; « scan des diffs » fantôme ligne 22

## D. Impact des décisions de direction sur les docs

- **Décision 1 (suppression du mode server)** : ✅ traité avec le code — `ROADMAP.md` (v2 étapes 1 et 2 marquées supprimées), `spec/security.md` (niveaux de confinement), `spec/protocol.md` (flags retirés), `spec/structure.md` (`sandbox.rs` et `walkdir` retirés), `spec/commands.md` (trusted en mode serveur + « scan des changements » fantôme retirés), `spec/platform.md` §2/§5, `docs/README.md`, `spec/platforms.md`, `spec/plugins.md`, `spec/testing.md` : tout ce qui décrivait `--mode server`, la cage userns+chroot, le busybox stagé et le remount read-only a été retiré.
- **Décision 2 (unix → macos)** — ✅ faite (cette PR) : `platform/unix.rs` →
  `platform/macos.rs` ; `cfg(unix)` → `cfg(any(target_os = "macos", target_os = "linux"))`
  dans tout le crate (sélection de l'impl dans `platform.rs` + code/tests qui
  référencent les primitives `platform`) ; commentaires et noms de tests ajustés ;
  `spec/platform.md` (§1, §4 `platform/macos.rs`, §5 branchements, §6, §8),
  `spec/platforms.md` §2 (inventaire), `spec/structure.md` (ligne `platform.rs`),
  `ROADMAP.md` mis à jour.
