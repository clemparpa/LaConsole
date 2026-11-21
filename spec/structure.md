# Structure du dépôt et dépendances

## Structure

```
la-console/
  Cargo.toml          # workspace root (virtual manifest, un seul Cargo.lock)
  rustfmt.toml
  deny.toml
  .github/workflows/ci.yml
  crates/
    la-console/       # la fausse console (binaire + lib)
      Cargo.toml
      src/
        main.rs       # CLI clap : --root, bornes, --mode, image de cage (--sandbox-busybox/--sandbox-tools-dir) ; spawn du protocole JSON
        lib.rs        # #![forbid(unsafe_code)]
        console.rs    # boucle protocole JSON stdin/stdout, synchrone (std::io, une requete a la fois)
        parse.rs      # parser shell cadré : shell-words + opérateurs whitelistés -> arbre de commandes
        resolve.rs    # resolve() : confinement root, unique point de passage
        commands/     # whitelist: cat, ls, echo, grep, sed, sub, http + filtres de flux head/tail/wc/sort/uniq/cut/tr (stream.rs = helpers communs)
        trusted.rs    # commandes trusted : parsing + wrapping + checksum + scan + exécution (/bin/sh en mode user, busybox sh dans la cage en mode server)
        sandbox.rs    # mode serveur : unshare userns+chroot, staging du binaire/libs, mini-image de cage (busybox + outillage)
        platform.rs   # (prévu v2) couche d'abstraction OS : primitives fs, spawn+limites, backends seatbelt/WSL2/landlock
        sink.rs       # trait Sink + FileSink / CallerSink / PipeSink
      tests/
        evasion.rs    # tests d'évasion (.., symlinks, absolus, unicode...)
        parse.rs      # proptests du parser (jamais de trusted dans un pipe, jamais de sous-exécution)
        commands.rs
        e2e.rs        # spawn du binaire, protocole JSON ligne par ligne
  tests/              # tests d'intégration haut niveau (niveau workspace)
  fuzz/
    Cargo.toml
    fuzz_targets/
      parse_input.rs   # parser shell cadré (invariants : pas de trusted en pipe, pas de sous-exécution)
      resolve_path.rs
```

- Nommage : crates en kebab-case (`la-console`) ; tout le code, fichiers et
  symboles en anglais.
- Le fichier `trusted.txt` (et les regex de fichiers sensibles) vit **dans
  chaque dépôt où tourne l'agent**, pas dans la-console : le module
  `trusted.rs` ne gère que le parsing, le wrapping, la sécurité (checksum, scan
  des diffs) et l'exécution — il reçoit le chemin du fichier en argument.

## Dépendances figées (v1)

| Besoin | Crate |
|---|---|
| Protocole JSON stdin/stdout | `serde`, `serde_json` |
| Timeout par commande | aucun crate : `std::thread` + `recv_timeout` |
| `grep` dans des fichiers | `grep` (moteur ripgrep en lib) |
| `ls` (respecte .gitignore, bornes) | `ignore` (walker ripgrep) |
| Checksum sha256 des commandes trusted | `sha2` |
| Regex des fichiers sensibles | `regex` (temps linéaire, pas de ReDoS) |
| Limites du sous-processus trusted | v1 : `ulimit` appliqué par le shell lancé (pas de crate, pas d'`unsafe`) ; **v2 prévu : backend OS (seatbelt/landlock/WSL2) + limites par entrée TOML, `ulimit` retiré** |
| Manifeste TOML `trusted.toml` (prévu v2) | `toml` (à épingler en direct ; `toml_edit` déjà présent transitivement dans le lock) |
| `git` whitelist read-only (prévu v2) | `git2` (à auditer : `libgit2-sys` natif, toolchain C requise) |
| Erreurs typées | `thiserror` |
| CLI | `clap` |
| Tokenisation shell (quotes, espaces) | `shell-words` |
| Globs (`*.rs`, `**/*.md`) | `wax` (moteur de glob de ripgrep) |
| HTTP whitelisté (localhost uniquement) | `reqwest` + rustls |
| Tests (répertoires temporaires) | `tempfile` (dev-dependency) |
| Property-based testing | `proptest` (dev-dependency) |

Notes :

- Spawn du sous-processus et pipes : `std::process` suffit, pas de crate.
- Cœur sécurité (`resolve()`, parser whitelist) : **maison**, volontairement.
- La console est volontairement **synchrone** : boucle `read_line` bloquante, une
  requête à la fois, timeout par thread dédié, `reqwest` en mode `blocking`.
  Pas de runtime async (`tokio` n'apparaît que comme dépendance transitive de
  `reqwest`). Voir la discussion synchrone/asynchrone dans `ROADMAP.md`.
