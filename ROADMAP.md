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

## Étape 5 — Whitelist, commande par commande 🚧 (cette PR : branche unique étape 5)

- `cat` ✅ (PR #9), puis `ls`, `echo >`, `grep`, `sub`, `http` (localhost uniquement en v1).
- ✅ `cat <path...>` (PR #9) : `resolve()` + sensibles + borne de lecture, globs re-résolus.
- ✅ `ls [path] [--all]` (PR #11) : entrées bornées, `.gitignore` respecté par défaut via le walker `ignore`.
- ✅ `echo <text> [> path]` (PR #12) : texte littéral, redirections via `FileSink` (validation avant ouverture, borne, masquage).
- 🚧 `grep <pattern> <path...> [--all]`, `sub <pattern> <repl> <path...>`, `http <METHOD> <url> [--data b] [--header k:v]` (cette PR) :
  - `grep` : moteur `grep` (ripgrep en lib) sur fichiers du walker `ignore` (`.gitignore` par défaut, `--all` sinon), chaque fichier `resolve()` + borné, matchs bornés ;
  - `sub` : substitution `regex` (temps linéaire), réécriture via `FileSink` (masquage secrets, borne) ;
  - `http` : `reqwest` + rustls (manual-roots), allowlist v1 = `localhost`/`127.0.0.1`/`::1` uniquement (bloque 169.254.169.254 et plages privées), redirects revalidés un par un (max 5), timeout 10 s, `--data` et réponse bornés.
- Bornes générales par commande (cette PR) : `Limits` centralise toutes les bornes ; **timeout** par commande (`run_with_timeout` : thread + `recv_timeout`, défaut 30 s, CLI `--timeout-secs`) et **quota disque par commande** (`DiskQuota` partagé entre tous les `FileSink` d'une commande, défaut 16 MiO) → `denied` code 2.
- **Testable** : tests unitaires + e2e par commande.

## Étape 6 — Commandes trusted ✅ (cette PR)

- `trusted.rs` + `trusted.txt` (dans le dépôt de l'agent) : parsing, checksum sha256, scan des changements, exécution shell réduit (`cwd = root`, env minimal).
- ✅ `trusted.rs` : parsing strict de `trusted.txt` (`<nom> [--no-path-check] = <commande>`), vérification sha256 du fichier **avant chaque exécution** (`--trusted-sha256`), exécution via `/bin/sh -c` avec `cwd = root`, env réduit (`PATH`, `LANG`, `HOME` hors du root), stdin `null`, args passés en `"$@"` (jamais réinterprétés) ; args de chemin validés via `resolve()` + sensibles sauf `--no-path-check` ; limites du sous-processus via `ulimit` appliqué par le shell (`-v` 1 GiO, `-t` timeout+5 s, `-f` quota disque), timeout avec `kill()` du fils. CLI : `--trusted-file`, `--trusted-sha256`, `--sensitives-file`.
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

## v2 — étape 1 : confinement noyau en déploiement serveur ✅ (cette PR)

- `--mode user|server` (défaut `user`) : `user` tourne partout (macOS + Linux poste utilisateur, confinement pur Rust v1) ; `server` est **Linux-only** et re-exec le binaire dans `unshare --user --map-root-user --mount --root <root> --wd /` (user namespace non privilégié + chroot, defense in depth). Hors Linux, `--mode server` est refusé fail-closed (exit 2).
- Le binaire (et ses dépendances dynamiques, via `ldd`) est d'abord copié dans la cage puis nettoyé au démarrage ; dans la cage, `--root /`. Marqueur `--inside-sandbox` + env anti-boucle. Zéro `unsafe` (`#![forbid(unsafe_code)]` intact).
- **Déploiement** : lancer la console comme l'utilisateur propriétaire du `root` — les permissions Unix s'appliquent toujours dans le userns, jamais de root global.
- **Commandes `trusted` indisponibles en mode serveur** (pas de `/bin/sh` dans la cage) → `denied` ; mini-image équipée (busybox statique) prévue plus tard.
- **Testable** : tests unitaires (`sandbox.rs`), e2e Linux (cage + évasion `..` + `trusted` refusé) et e2e de refus hors Linux.

## v2 (backlog)

- **Plugins et responsabilité d'exécution** (discussion ouverte) : concevoir un mécanisme de « plugins » (ex. module lançant des OCI) et répartir les responsabilités — le harnais de l'agent déclare la politique (fichiers revus par l'humain, épinglés par sha256, comme `trusted.txt`), mais la console conserve la validation, le confinement, les limites et le kill de l'exécution (jamais délégués au harnais).
- **Support Windows** (discussion ouverte) : le code v1 est Unix-only (`std::os::unix` pour `st_dev`/`st_ino` dans `resolve.rs`, `symlink` dans les tests, `/bin/sh` + `ulimit` dans `trusted.rs`). Porter sur Windows via une couche d'abstraction des primitives plateforme (hardlink, symlink, shell, limites) — chaque plateforme ajoutée est une nouvelle surface d'attaque à auditer.
