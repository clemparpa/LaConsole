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

## Suite v1 (backlog, à prioriser)

- **Bornes configurables + `>>` exposé** ✅ (cette PR) : `--max-output-bytes N` au CLI (défaut 1 MiO, passé dans `Limits`), syntaxes `>>` listées dans le registre `COMMANDS` pour `cat`/`echo`/`grep`/`ls` (le parser et `FileSink` géraient déjà l'append).
- **Redirection `<` (stdin depuis fichier)** ✅ (cette PR) : `Redirect::In` dans le parser, lecture bornée via `read_bounded` (resolve + sensibles + `max_read_bytes`) dans `exec_simple`, input passé aux commandes (`cat`/`grep` sans opérande lisent cet input).
- **Erreurs structurées** ✅ (cette PR) : champ `kind` dans la réponse JSON (présent uniquement en cas d'échec) avec codes distincts — `denied`/2 (refus de sécurité), `limit`/3 (timeout, quota disque, bornes, trop de matchs), `fail`/1 (usage/I/O) — pour que l'agent distingue « interdit » de « trop lent / trop gros » sans parser le texte de `stderr`. Classification faite à la source (`ExecError::Limit`), conversion unique dans `console.rs`.
- **`help`** ✅ (cette PR) : commande en lecture seule, sans effet de bord. Source de vérité unique = registre `COMMANDS` (`CommandSpec { name, syntaxes, summary, run }`) partagé par le dispatcher et `help` — ajouter une commande = une entrée, impossible à désynchroniser ; les syntaxes bis (ex. `echo <text>` / `echo <text> > <path>`) sont listées via le champ `syntaxes` ; les commandes `trusted` sont listées depuis le registre runtime.
- **`sed`** ✅ (cette PR) : alias restreint `sed [-i] s/<pat>/<repl>/[g] <path...>` (une seule expression `s`, flag `g` uniquement, regex Rust en `(?m)`, `\1`/`&` dans le remplacement) ; sans `-i` affiche sur stdout (prévisualisation), avec `-i` réécrit en place via `FileSink` ; toute forme non couverte = erreur `fail` avec message précis. Voir `spec/commands.md`.
- **Plugins et responsabilité d'exécution** (discussion ouverte) : concevoir un mécanisme de « plugins » (ex. module lançant des OCI) et répartir les responsabilités — le harnais de l'agent déclare la politique (fichiers revus par l'humain, épinglés par sha256, comme `trusted.txt`), mais la console conserve la validation, le confinement, les limites et le kill de l'exécution (jamais délégués au harnais) ; à terme, user namespace + chroot côté console (voir `spec/security.md`, v2) comme defense in depth.
- **Support Windows** (discussion ouverte) : le code v1 est Unix-only (`std::os::unix` pour `st_dev`/`st_ino` dans `resolve.rs`, `symlink` dans les tests, `/bin/sh` + `ulimit` dans `trusted.rs`). Choix à faire : rester Unix-only (Linux + macOS) en v1 et le documenter, ou porter sur Windows via une couche d'abstraction des primitives plateforme (hardlink, symlink, shell, limites) — en sachant que chaque plateforme ajoutée est une nouvelle surface d'attaque à auditer.
