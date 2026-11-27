# Feuille de route — la-console

## Principes

- Chaque étape = une PR indépendante, **testable et avec CI verte avant merge**.
- TDD systématique (voir `spec/testing.md`).
- Cœur sécurité (`resolve()`, parser) écrit maison, volontairement.
- Aucun `unsafe` en v1 (`#![forbid(unsafe_code)]`).
- Sur le dépôt public : workflows de PR de forks bloqués (approbation requise côté settings + garde-fou `if:` dans la CI) — jamais de jobs coûteux exposés aux forks.

## Étape 0 — Squelette + arsenal (fondation) ✅ (PR #2)

- Workspace conforme à `spec/structure.md` : `Cargo.toml` virtuel, `crates/la-console` (binaire + lib), `lib.rs` avec `#![forbid(unsafe_code)]`, `main.rs` avec CLI clap minimale (`--root` parsé).
- Fichiers de config : `rustfmt.toml`, `deny.toml`, `.gitignore` (incl. `mutants.out/`).
- CI GitHub Actions (gate PR) : `cargo fmt --check`, `clippy -D warnings`, `cargo test`, matrice ubuntu + macOS, `cargo deny` + `cargo audit`, garde-fou anti-fork sur les jobs.
- **Testable** : une PR qui merge avec CI verte sur un code minimal (un test bidon suffit).

## Étape 1 — Protocole JSON ligne par ligne ✅ (PR #4)

- `console.rs` : boucle stdin/stdout, une ligne JSON en entrée, une ligne JSON en sortie (`{ok, code, stdout, stderr, truncated}`).
- **Testable** : test e2e qui spawn le binaire (`CARGO_BIN_EXE_la-console`) et assert le contrat JSON.

## Étape 2 — `resolve()` + confinement ✅ (PR #6)

- `resolve.rs` : unique point de passage pour les chemins (canonicalize, `..`, symlinks, absolus, hardlinks).
- **Testable** : tests d'évasion (`tests/evasion.rs` : `..`, symlinks, absolus, unicode, `//`, trailing slashes, NUL, hardlinks) + proptest « jamais hors du root » + cible fuzz `resolve_path`.

## Étape 3 — Parser shell cadré ✅ (PR #7)

- Tokenisation `shell-words` + interprétation maison des opérateurs autorisés (`&&`/`;`, pipes, redirections, globs, variables déclarées) → arbre de commandes.
- **Testable** : proptest « jamais de `trusted` dans un pipe, jamais de sous-exécution » + fuzz `parse_input`.

## Étape 4 — Sink (interface d'écriture unique) ✅ (PR #8)

- `sink.rs` : trait `Sink` + `FileSink` / `CallerSink` / `PipeSink` (validation avant ouverture, masquage secrets, troncature).
- **Testable** : tests unitaires par sink.

## Étape 5 — Whitelist, commande par commande ✅ (PR #9–#13, #19–#22)

- `cat` ✅ (PR #9), puis `ls`, `echo >`, `grep`, `sub`, `http` (localhost uniquement en v1).
- ✅ `cat <path...>` (PR #9) : `resolve()` + sensibles + borne de lecture, globs re-résolus.
- ✅ `ls [path] [--all]` (PR #11) : entrées bornées, `.gitignore` respecté par défaut via le walker `ignore`.
- ✅ `echo <text> [> path]` (PR #12) : texte littéral, redirections via `FileSink` (validation avant ouverture, borne, masquage).
- ✅ `grep <pattern> <path...> [--all]`, `sub <pattern> <repl> <path...>`, `http <METHOD> <url> [--data b] [--header k:v]` (PR #13, #19, #20) :
  - `grep` : moteur `grep` (ripgrep en lib) sur fichiers du walker `ignore` (`.gitignore` par défaut, `--all` sinon), chaque fichier `resolve()` + borné, matchs bornés ;
  - `sub` : substitution `regex` (temps linéaire), réécriture via `FileSink` (masquage secrets, borne) ;
  - `http` : `reqwest` + rustls (manual-roots), allowlist v1 = `localhost`/`127.0.0.1`/`::1` uniquement (bloque 169.254.169.254 et plages privées), redirects revalidés un par un (max 5), timeout 10 s, `--data` et réponse bornés.
- Bornes générales par commande (cette PR) : `Limits` centralise toutes les bornes ; **timeout** par commande (`run_with_timeout` : thread + `recv_timeout`, défaut 30 s, CLI `--timeout-secs`) et **quota disque par commande** (`DiskQuota` partagé entre tous les `FileSink` d'une commande, défaut 16 MiO) → `denied` code 2.
- **Testable** : tests unitaires + e2e par commande.

## Étape 6 — Commandes trusted ✅ (PR #14, puis #39)

- `trusted.rs` + manifeste `trusted.toml` (dans le dépôt de l'agent) : parsing TOML strict, checksum sha256, exécution shell réduit (`cwd = root`, env minimal).
- ✅ `trusted.rs` : manifeste `trusted.toml` seul format (`deny_unknown_fields`), vérification sha256 **avant chaque exécution** (`--trusted-sha256`), exécution via `/bin/sh -c` avec `cwd = root`, env réduit (`PATH`, `LANG`, `HOME` hors du root via `tempfile`), stdin `null`, args passés en `"$@"` (jamais réinterprétés) ; args de chemin validés via `resolve()` + sensibles sauf `no_path_check` ; **plus d'`ulimit`** (#39) : timeout wall-clock + kill du **groupe de processus** par la console (`process_group(0)`). CLI : `--trusted-file`, `--trusted-sha256`, `--sensibles-file`.
- **Testable** : e2e avec un fichier trusted de test.

## Étape 7 — Nightly (fuzz long + mutation testing) ✅ (cette PR)

- Workflow nightly (`.github/workflows/nightly.yml`, cron quotidien + `workflow_dispatch`) : fuzz 30 min sur `parse_input` + `resolve_path` (matrice, toolchain nightly, cible `x86_64-unknown-linux-gnu` car ASan est incompatible avec musl statique), `cargo mutants` sur `resolve.rs` + `parse.rs` avec seuil de score ≥ 80 % vérifié via `mutants.out/outcomes.json`.
- **Testable** : le job nightly tourne vert sur `main`.

## Suite v1 — terminée ✅

- **Bornes configurables + `>>` exposé** ✅ (PR #22) : `--max-output-bytes N` au CLI (défaut 1 MiO, passé dans `Limits`), syntaxes `>>` listées dans le registre `COMMANDS` pour `cat`/`echo`/`grep`/`ls`.
- **Redirection `<` (stdin depuis fichier)** ✅ (PR #22) : `Redirect::In` dans le parser, lecture bornée via `read_bounded` (resolve + sensibles + `max_read_bytes`), input passé aux commandes (`cat`/`grep` sans opérande lisent cet input).
- **Erreurs structurées** ✅ (PR #19) : champ `kind` (`denied`/2, `limit`/3, `fail`/1).
- **`help`** ✅ (PR #19) : registre `COMMANDS` comme source de vérité unique.
- **`sed`** ✅ (PR #20) : alias restreint `s///[g]`, preview stdout + `-i` in-place.

La v1 est Unix-only (Linux + macOS), documenté.

## v2 — étapes 1 et 2 : mode serveur (userns+chroot) + mini-image de cage — ❌ supprimés (décision 2026-11-24)

Livrés en v2 (PR #24/#26/#27 : `--mode server`, re-exec `unshare --user
--map-root-user --mount --root`, mini-image busybox/outillage, remount
read-only), puis **supprimés** (décision du 2026-11-24, voir
`docs/etat-des-lieux-2026-11-24.md`) : les flags `--mode`, `--inside-sandbox`,
`--sandbox-busybox*`, `--sandbox-tools-dir` et le module `sandbox.rs` sont
retirés. Le confinement noyau passe désormais par le backend par spawn
(crate `nono`, fournée suivante ci-dessous).

## v2 — prochaine fournée planifiée 🚧 (brouillon soumis à revue)

- ✅ **`trusted.toml` + retrait des `ulimit`** (cette PR) : manifeste TOML
  strict (`.toml` seul format accepté — v1 `.txt` retiré —, `deny_unknown_fields`,
  épinglage sha256 re-vérifié avant chaque exécution) avec, par entrée,
  `description`, limites (`no_path_check`, `timeout_secs`, `max_write_bytes`,
  `mem_bytes`/`cpus`, `network`) et `flags` = allowlist des arguments `-...`
  (avec `description` par flag, rendu par `help`) ; tout flag non déclaré =
  `denied` fail-closed ; plus d'`ulimit` dans le shell — la console
  applique le timeout wall-clock + kill du **groupe de processus**
  (`process_group(0)`, `timeout_secs` par entrée, défaut `--timeout-secs`) ;
  `network = "none"`/`"loopback"` seront appliquées par le backend nono à la
  fournée suivante (plan `spec/sandbox-backend.md`) ; `network = "proxy"`,
  `max_write_bytes`/`mem_bytes`/`cpus` restent refusées `denied` fail-closed
  (reportées v3, décision 2026-11-27). `help` liste les entrées avec leurs
  limites.
- ✅ **Architecture multi-plateforme — phase 1** (cette PR) : couche
  d'abstraction `platform.rs` (`platform/macos.rs` + `platform/windows.rs`,
  fonctions libres, fail-closed par défaut) ; branchements `resolve.rs`
  (`file_id`/`hardlink_escape`/`canonicalize` via `platform`, `normalize()`
  refuse fail-closed les chemins absolus Windows — drive `C:`, UNC `\\`, tout
  `:` sur Windows, tout backslash sur unix — et les chemins internes sont
  normalisés en relatifs `/` (`path_to_slash`) avant `resolve()`), `trusted.rs` (`shell()`, `set_new_process_group`, `kill_process_tree`,
  `exit_code`, `PATH` via `env::join_paths`), symlinks des tests via
  `platform::testutil` ; deps `dunce` + `winapi-util` (cible `cfg(windows)`
  uniquement) ; CI `+ windows-latest` à la matrice `test`. Sur Linux/macOS
  aucun changement de sémantique ; sur Windows natif, whitelist + `resolve()`
  fonctionnent et `trusted` (pas de shell) ainsi que les
  limites backend restent refusés fail-closed. Spec : `spec/platform.md` ;
  backends OS (seatbelt/WSL2/landlock) : `spec/platforms.md`.
- ✅ **Renommage `unix` → `macos`** (décision 2026-11-24, cette PR) :
  `platform/unix.rs` → `platform/macos.rs` (macOS = plateforme cible visée,
  Linux garde le même code via la matrice CI) ; les `cfg(unix)` du crate
  deviennent `cfg(any(target_os = "macos", target_os = "linux"))` partout où
  le code référence les primitives `platform` (sélection de l'impl dans
  `platform.rs`, branchements `resolve.rs`/`trusted.rs`, tests) — aucun
  changement de sémantique ; commentaires/noms de tests ajustés ; docs
  (`spec/platform.md`, `spec/platforms.md`, `spec/structure.md`) à jour.
- 🚧 **Backend de confinement OS par spawn — crate `nono`** — plan d'impl :
  `spec/sandbox-backend.md` (décisions 2026-11-24 + 2026-11-27). Scope v2 (une
  PR) : `src/sandbox_backend.rs` (unique module `nono::`, dep épinglée `=`
  + auditée avant bump), helper arg0 `__sandbox_helper <profil.json> -- <cmd…>`
  + profil depuis `trusted.toml` + `Limits`, sandbox **FS + exec par spawn**
  (landlock Linux ≥ 5.13 / seatbelt macOS / WSL2), réseau **`none` (défaut) /
  `loopback`** via nono ; timeout + kill du groupe inchangés (`platform.rs`).
  **Reporté à une v3 (décision 2026-11-27 : l'agent est borné par son nombre de
  tours max)** : `network = "proxy"` (allowlist de domaines +
  anti-DNS-rebinding), `mem_bytes`, `max_write_bytes`, `cpus` (rlimits `nix` /
  cgroups — non couvert par nono hors cgroups Linux), lanceur WSL2 (`wsl.exe` ;
  Windows natif fail-closed) — ces limites restent parsées dans
  `trusted.toml` mais **refusées `denied` fail-closed** tant qu'elles ne sont
  pas livrées. La cage userns+chroot du mode serveur est supprimée (décision 1).
  (cf. `spec/sandbox-backend.md`, `spec/platforms.md` §3, `spec/security.md`).
- 🚧 **Commandes `git` en whitelist** : read-only d'abord (`status`/`diff`/`log`/
  `show`/`branch`/`rev-parse`, in-process via `git2`) ; mutations (`add`,
  `commit`, `push`…) restent `trusted` (cf. `spec/commands.md`).

- ✅ **Hygiène de l'écosystème Rust (cette PR)** : fin des roues maison là où
  l'écosystème fait déjà le job —
  - masquage des secrets : `SecretMasker` maison → `aho-corasick`
    (`MatchKind::LeftmostLongest`, carry de flux conservé ; déjà transitif via
    `regex`, aucun ajout à l'arbre) ;
  - `HOME` des shells trusted créé via `tempfile` (nom imprévisible, `O_EXCL`,
    0700 — l'ancien `la-console-home-<pid>` était prévisible sous un `/tmp`
    partagé) et supprimé à la sortie de la console (`cleanup_home`) ;
  - `platform::path_to_slash` → `path-slash` (`PathExt::to_slash`) ;
  - sha256 : hex via `format!("{:x}", …)` et `trusted::sha256_hex` unique ;
  - `read_bounded` lit via `File::take(max_read_bytes + 1)` (plus de read entier
    en mémoire après le stat) ;
  - `has_glob` aligné sur le moteur `wax` (métacaractères `*?[{` + délégation à
    `Glob::partition` ; un backslash seul reste littéral pour que `resolve()`
    rende toujours `denied` WindowsPath) ;
  - **`--secrets-file <chemin>` branché** : liste des secrets connus chargée au
    démarrage (une ligne par secret, `#` commentaires, UTF-8 strict, bornée
    1 MiO, fail-closed) — le masquage `***` en sortie JSON et avant écriture
    disque est désormais effectif en production (avant : `ctx.secrets` vide).

## v2 (backlog)

- **Pipe `trusted | whitelist`, tête uniquement** ✅ (PR #30) : `trusted` est accepté comme **premier élément** d'un pipe (`trusted run-tests | grep ERROR`) ; toute autre position (`whitelist | trusted …`, `a | trusted … | b`, `trusted a | trusted b`) reste `denied` au parse (`TrustedInPipe`). Le stdin du shell trusted reste `null` — aucun octet pipé ne peut lui être fourni ni interprété ; sa sortie est bornée via `PipeSink` (troncature) puis passée aux commandes whitelist suivantes, chacune revalidée (niveaux 1–3) ; redirection `>`/`>>` toujours réservée au dernier élément, via `FileSink`. Le checksum sha256 de `trusted.toml` est re-vérifié avant chaque exécution, y compris en tête de pipe. Proptest : jamais de `trusted` après la tête d'un pipe (`pipe_has_misplaced_trusted`). Cf. `spec/plugins.md` (phase 2). **Testable** : tests unitaires parse + exécution (pipe tête → `grep`, redirect, checksum) + e2e.
- **Élargir la whitelist pour l'ergonomie agent** ✅ (PR #32–#37, spec `spec/whitelist-expansion.md`) : constats — sur un flux pipe seules `cat`/`grep` lisent l'entrée (`sed`/`sub` exigent des chemins), `grep` n'a que `--all` (pas de `-v`/`-i`/`-c`), aucun `head`/`tail`/`sort`/`uniq`/`wc`/`cut`/`tr` whitelist. Paquets proposés, chacun en PR dédiée : A) flags `grep` — ✅ implémenté (branche `vibe/grep-flags-spec-377153`) : décision actée dans `spec/commands.md` (`-F -e -E -i -v -w -x -n -c -o -l -L -m -q -B/-A/-C` acceptés, `-P -G -z` refusés, `-f`/`--file`/`--exclude-from` ✅ paquet A3 (même branche) : lecture via `read_bounded` (resolve + sensibles + `max_read_bytes`), UTF-8 strict, bornés (`max_grep_patterns`, 4096 o/ligne, `max_grep_globs`) ; `-a` binaire reste à réfléchir ; `--include`/`--exclude`/`--exclude-dir` ✅ paquet A2 (branche `vibe/grep-globs-a2-3cc883`, décision dans `spec/commands.md`) : filtres gitignore via `filter_entry` après `hidden`/`.gitignore`, bornés (`max_grep_globs`, 256 o/glob), récursif uniquement) ; B) filtres de flux in-process bornés (`head`/`tail`/`wc`/`sort`/`uniq`/`cut`/`tr`, nouveau `Limits::max_stream_lines`) ✅ paquet B (branche `vibe/stream-filters-b-c4cd4a`, décision actée dans `spec/commands.md` « Filtres de flux ») ; C) `sed` sur flux sans chemin ✅ paquet C (branche `vibe/sed-stream-c-090baf`, décision actée dans `spec/commands.md` « Paquet C » : position pipe > 0 enforce au parse (`SedStreamNeedsPipe` hors position de flux), `-i` interdit sur flux (`SedInPlaceInPipe`), `sub` reste fichier-only (`SubInPipe` = `denied` en pipe), UTF-8 strict, `… | sed s/a/b/ > out.txt` via `FileSink`, proptest/fuzz `pipe_has_stream_forbidden`) ; D) `json` minimal \u2705 impl\u00e9ment\u00e9 (branche `vibe/json-extractor-d-b83094`, d\u00e9cision act\u00e9e dans `spec/commands.md` \u00ab Paquet D \u00bb : `json <selector> [path...]`, s\u00e9lecteur `a.b[0].c`, lit le flux pipe/`<` sans chemin, profondeur born\u00e9e `max_json_depth` = 128, parsing fail-closed, aucune option) et E) `tee` ✅ implémenté (branche `vibe/tee-stream-e-624c06`, décision actée dans `spec/commands.md` « Paquet E » : `tee <path>` en position de flux uniquement (`TeeNeedsPipe` hors pipe, proptest/fuzz `pipe_has_stream_forbidden`), copie du flux via `FileSink` (resolve + sensibles + quota + masquage, validation avant ouverture) **et** passage du flux inchangé à la suite du pipe, aucune option, un seul opérande cible, glob interdit). Hors scope : `awk`, `jq` complet, `less` (pas de TTY) → `trusted` + pipe tête (PR #30). Principe : fail-closed, in-process, testé comme toute commande whitelist.
- **Synchrone vs asynchrone (discussion ouverte)** : l'implémentation actuelle est volontairement 100 % synchrone — boucle `read_line` bloquante dans `console.rs` (une requête à la fois), timeout par commande via `std::thread` + `recv_timeout` (`run_with_timeout`), `reqwest` en mode `blocking` pour `http`. `tokio` n'est présent que comme dépendance transitive de `reqwest`, jamais en direct. La spec reflète ce choix (`spec/structure.md`). Discussion à avoir : faut-il un runtime async (concurrence de requêtes, I/O non bloquantes) ? Trade-off : une runtime async ajoute de la complexité et de la surface d'attaque (état partagé, tâches en parallèle soumises aux mêmes bornes) pour un gain de débit incertain, le protocole étant ligne par ligne et mono-appelant. Position actuelle : rester synchrone tant qu'aucun besoin mesuré ne justifie le changement.
- **Plugins et responsabilité d'exécution** (discussion ouverte) : concevoir un mécanisme de « plugins » (ex. module lançant des OCI) et répartir les responsabilités — le harnais de l'agent déclare la politique (fichiers revus par l'humain, épinglés par sha256, comme `trusted.toml`), mais la console conserve la validation, le confinement, les limites et le kill de l'exécution (jamais délégués au harnais).
- **Support Windows** (phase 1 livrée PR #41, discussion ouverte pour la suite) : `platform.rs` abstrait les primitives (hardlink, symlink, shell, limites) et Windows natif tourne fail-closed ; le déploiement Windows visé reste la console dans **WSL2**. Chaque plateforme ajoutée est une nouvelle surface d'attaque à auditer.
