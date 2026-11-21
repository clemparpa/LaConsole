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

## v2 — étape 2 : mini-image de cage (busybox statique + outillage) 🚧 (cette PR)

- Nouveaux flags (mode serveur uniquement, consommés avant le re-exec) : `--sandbox-busybox <PATH>` (busybox **statique** fourni par l'opérateur, vérifié ELF + statique via `ldd`, épinglable par `--sandbox-busybox-sha256 <hex>`) et `--sandbox-tools-dir <DIR>` (ex. git + toolchain go) copié dans la cage en `/opt/la-console-tools` avec les dépendances dynamiques de chaque binaire ELF (`ldd` : loader + libs).
- Le busybox est copié en `/bin/busybox` (0555) avec un symlink par applet dans `/bin` (`busybox --list`) : `trusted` fonctionne en mode serveur via `<busybox> sh -c`, `PATH = /bin:/opt/la-console-tools/bin:/opt/la-console-tools/go/bin`, `HOME=/tmp`, `GOROOT` détecté si présent. Sans `--sandbox-busybox`, `trusted` reste `denied` (fail-closed).
- Defense in depth : au démarrage dans la cage, `/bin`, `/opt/la-console-tools` et le dossier de libs stagées sont remountés read-only (bind + remount,ro via l'applet `mount` de busybox ; le processus est root dans son propre user namespace, le remount ne fuite pas sur l'hôte) pour empêcher l'agent d'écraser un outil via une écriture whitelist. **Fail-closed** : si un remount échoue, la console refuse de démarrer (exit 2).
- **Testable** : tests unitaires du staging (refus busybox dynamique/non-ELF/sha faux, copie de l'outillage + deps ELF, symlinks d'applets), tests `trusted` en cage via faux busybox, e2e Linux (outillage visible dans la cage, `trusted` via vrai busybox statique quand disponible, `trusted` toujours refusé sans busybox).

## v2 (backlog)

- **Pipe `trusted | whitelist`, tête uniquement** 🚧 (cette PR) : `trusted` est accepté comme **premier élément** d'un pipe (`trusted run-tests | grep ERROR`) ; toute autre position (`whitelist | trusted …`, `a | trusted … | b`, `trusted a | trusted b`) reste `denied` au parse (`TrustedInPipe`). Le stdin du shell trusted reste `null` — aucun octet pipé ne peut lui être fourni ni interprété ; sa sortie est bornée via `PipeSink` (troncature) puis passée aux commandes whitelist suivantes, chacune revalidée (niveaux 1–3) ; redirection `>`/`>>` toujours réservée au dernier élément, via `FileSink`. Le checksum sha256 de `trusted.txt` est re-vérifié avant chaque exécution, y compris en tête de pipe. Proptest : jamais de `trusted` après la tête d'un pipe (`pipe_has_misplaced_trusted`). Cf. `spec/plugins.md` (phase 2). **Testable** : tests unitaires parse + exécution (pipe tête → `grep`, redirect, checksum) + e2e.
- **Élargir la whitelist pour l'ergonomie agent** 🚧 (cette PR : brouillon `spec/whitelist-expansion.md` soumis à revue) : constats — sur un flux pipe seules `cat`/`grep` lisent l'entrée (`sed`/`sub` exigent des chemins), `grep` n'a que `--all` (pas de `-v`/`-i`/`-c`), aucun `head`/`tail`/`sort`/`uniq`/`wc`/`cut`/`tr` whitelist. Paquets proposés, chacun en PR dédiée : A) flags `grep` — ✅ implémenté (branche `vibe/grep-flags-spec-377153`) : décision actée dans `spec/commands.md` (`-F -e -E -i -v -w -x -n -c -o -l -L -m -q -B/-A/-C` acceptés, `-P -G -z` refusés, `-f`/`--file`/`--exclude-from` ✅ paquet A3 (même branche) : lecture via `read_bounded` (resolve + sensibles + `max_read_bytes`), UTF-8 strict, bornés (`max_grep_patterns`, 4096 o/ligne, `max_grep_globs`) ; `-a` binaire reste à réfléchir ; `--include`/`--exclude`/`--exclude-dir` ✅ paquet A2 (branche `vibe/grep-globs-a2-3cc883`, décision dans `spec/commands.md`) : filtres gitignore via `filter_entry` après `hidden`/`.gitignore`, bornés (`max_grep_globs`, 256 o/glob), récursif uniquement) ; B) filtres de flux in-process bornés (`head`/`tail`/`wc`/`sort`/`uniq`/`cut`/`tr`, nouveau `Limits::max_stream_lines`) ✅ paquet B (branche `vibe/stream-filters-b-c4cd4a`, décision actée dans `spec/commands.md` « Filtres de flux ») ; C) `sed` sur flux sans chemin ✅ paquet C (branche `vibe/sed-stream-c-090baf`, décision actée dans `spec/commands.md` « Paquet C » : position pipe > 0 enforce au parse (`SedStreamNeedsPipe` hors position de flux), `-i` interdit sur flux (`SedInPlaceInPipe`), `sub` reste fichier-only (`SubInPipe` = `denied` en pipe), UTF-8 strict, `… | sed s/a/b/ > out.txt` via `FileSink`, proptest/fuzz `pipe_has_stream_forbidden`) ; D) `json` minimal \u2705 impl\u00e9ment\u00e9 (branche `vibe/json-extractor-d-b83094`, d\u00e9cision act\u00e9e dans `spec/commands.md` \u00ab Paquet D \u00bb : `json <selector> [path...]`, s\u00e9lecteur `a.b[0].c`, lit le flux pipe/`<` sans chemin, profondeur born\u00e9e `max_json_depth` = 128, parsing fail-closed, aucune option) et E) `tee` ✅ implémenté (branche `vibe/tee-stream-e-624c06`, décision actée dans `spec/commands.md` « Paquet E » : `tee <path>` en position de flux uniquement (`TeeNeedsPipe` hors pipe, proptest/fuzz `pipe_has_stream_forbidden`), copie du flux via `FileSink` (resolve + sensibles + quota + masquage, validation avant ouverture) **et** passage du flux inchangé à la suite du pipe, aucune option, un seul opérande cible, glob interdit). Hors scope : `awk`, `jq` complet, `less` (pas de TTY) → `trusted` + pipe tête (PR #30). Principe : fail-closed, in-process, testé comme toute commande whitelist.
- **Synchrone vs asynchrone (discussion ouverte)** : l'implémentation actuelle est volontairement 100 % synchrone — boucle `read_line` bloquante dans `console.rs` (une requête à la fois), timeout par commande via `std::thread` + `recv_timeout` (`run_with_timeout`), `reqwest` en mode `blocking` pour `http`. `tokio` n'est présent que comme dépendance transitive de `reqwest`, jamais en direct. La spec reflète ce choix (`spec/structure.md`). Discussion à avoir : faut-il un runtime async (concurrence de requêtes, I/O non bloquantes) ? Trade-off : une runtime async ajoute de la complexité et de la surface d'attaque (état partagé, tâches en parallèle soumises aux mêmes bornes) pour un gain de débit incertain, le protocole étant ligne par ligne et mono-appelant. Position actuelle : rester synchrone tant qu'aucun besoin mesuré ne justifie le changement.
- **Plugins et responsabilité d'exécution** (discussion ouverte) : concevoir un mécanisme de « plugins » (ex. module lançant des OCI) et répartir les responsabilités — le harnais de l'agent déclare la politique (fichiers revus par l'humain, épinglés par sha256, comme `trusted.txt`), mais la console conserve la validation, le confinement, les limites et le kill de l'exécution (jamais délégués au harnais).
- **Support Windows** (discussion ouverte) : le code v1 est Unix-only (`std::os::unix` pour `st_dev`/`st_ino` dans `resolve.rs`, `symlink` dans les tests, `/bin/sh` + `ulimit` dans `trusted.rs`). Porter sur Windows via une couche d'abstraction des primitives plateforme (hardlink, symlink, shell, limites) — chaque plateforme ajoutée est une nouvelle surface d'attaque à auditer.
