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
        main.rs       # CLI clap : --root, bornes, --trusted-file/--trusted-sha256, --sensibles-file, --secrets-file ; spawn du protocole JSON
        lib.rs        # #![forbid(unsafe_code)]
        console.rs    # boucle protocole JSON stdin/stdout, synchrone (std::io, une requete a la fois)
        parse.rs      # parser shell cadré : shell-words + opérateurs whitelistés -> arbre de commandes
        resolve.rs    # resolve() : confinement root, unique point de passage
        commands/     # whitelist: cat, ls, echo, grep, sed, sub, http + filtres de flux head/tail/wc/sort/uniq/cut/tr (stream.rs = helpers communs)
        trusted.rs    # commandes trusted : manifeste TOML strict (trusted.toml, seul format accepté), checksum sha256, exécution shell réduite (/bin/sh via platform::shell()) ; plus d'ulimit : timeout/kill du groupe de processus par la console
        platform.rs   # couche d'abstraction OS (spec/platform.md) : primitives fs (identité fichier, canonicalize), spawn + kill de l'arbre, exit code, shell — impls platform/macos.rs (cfg(any(target_os = "macos", target_os = "linux")); macOS = cible visée, Linux = même code) / platform/windows.rs (cfg(windows)), fail-closed sur Windows natif
        sandbox_backend.rs  # backend de confinement OS par spawn (plan : spec/sandbox-backend.md) : SEUL module référençant la crate `nono` épinglée (`apply(profile)` + `support_info()`) + helper arg0 `__sandbox_helper <profil.json> -- <cmd…>` ; scope v2 = FS/exec + réseau none/loopback ; proxy/mem_bytes/max_write_bytes/cpus reportés v3 (restent `denied`)
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
- Le fichier `trusted.toml` (et les regex de fichiers sensibles) vit **dans
  chaque dépôt où tourne l'agent**, pas dans la-console : le module
  `trusted.rs` ne gère que le parsing, le wrapping, la sécurité (checksum
  sha256 re-vérifié avant chaque exécution) et l'exécution — il reçoit le
  chemin du fichier en argument.

## Dépendances figées (v1)

| Besoin | Crate |
|---|---|
| Protocole JSON stdin/stdout | `serde`, `serde_json` |
| Timeout par commande | aucun crate : `std::thread` + `recv_timeout` |
| `grep` dans des fichiers | `grep` (moteur ripgrep en lib) |
| `ls` (respecte .gitignore, bornes) | `ignore` (walker ripgrep) |
| Checksum sha256 des commandes trusted | `sha2` |
| Regex des fichiers sensibles | `regex` (temps linéaire, pas de ReDoS) |
| Limites du sous-processus trusted | ✅ `ulimit` retiré ; timeout/kill du groupe de processus par la console (std, pas d'`unsafe`) ; `network = "none"`/`"loopback"` appliquées en v2 par le backend OS (ligne `nono` ci-dessous) ; `network = "proxy"`/`max_write_bytes`/`mem_bytes`/`cpus` refusés fail-closed, reportés v3 (décision 2026-11-27) |
| Backend de confinement OS par spawn (v2) | `nono` (nolabs-ai, Apache-2.0 — landlock Linux ≥ 5.13 / seatbelt macOS / WSL2), épinglée `=x.y.z`, `Cargo.lock` committé, auditée (`cargo deny` + `cargo audit`) avant chaque bump ; référence unique dans `sandbox_backend.rs` (plan : spec/sandbox-backend.md) |
| Manifeste TOML `trusted.toml` | `toml` (épinglé en direct) |
| Identité de fichier cross-OS (dev/ino ; volume serial + file index + link count sur Windows) — v2 `platform.rs` ✅ | `winapi-util` (déjà transitif via `same-file`, dep cible `cfg(windows)`) |
| `canonicalize` sans préfixe `\\?\` sur Windows — v2 `platform.rs` ✅ | `dunce` (dep cible `cfg(windows)`) |
| `git` whitelist read-only (prévu v2) | `git2` (à auditer : `libgit2-sys` natif, toolchain C requise) |
| Erreurs typées | `thiserror` |
| CLI | `clap` |
| Tokenisation shell (quotes, espaces) | `shell-words` |
| Globs (`*.rs`, `**/*.md`) | `wax` (moteur de glob de ripgrep) |
| Masquage multi-secrets (`***` en sortie et avant écriture disque) | `aho-corasick` (déjà transitif via `regex`, leftmost-longest) |
| Rendu des chemins en séparateurs `/` (contrat JSON, `platform::path_to_slash`) | `path-slash` |
| HTTP whitelisté (localhost uniquement) | `reqwest` + rustls |
| Répertoire temporaire (HOME des shells trusted, supprimé à la sortie ; aussi utilisé par les tests) | `tempfile` |
| Property-based testing | `proptest` (dev-dependency) |

Notes :

- Spawn du sous-processus et pipes : `std::process` suffit, pas de crate.
- Cœur sécurité (`resolve()`, parser whitelist) : **maison**, volontairement.
- La console est volontairement **synchrone** : boucle `read_line` bloquante, une
  requête à la fois, timeout par thread dédié, `reqwest` en mode `blocking`.
  Pas de runtime async (`tokio` n'apparaît que comme dépendance transitive de
  `reqwest`). Voir la discussion synchrone/asynchrone dans `ROADMAP.md`.
