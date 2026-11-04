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
        main.rs       # CLI clap : --root, bornes ; spawn du protocole JSON
        lib.rs        # #![forbid(unsafe_code)]
        console.rs    # boucle protocole JSON stdin/stdout (tokio)
        resolve.rs    # resolve() : confinement root, unique point de passage
        commands/     # cat, ls, echo, grep, sub, http (whitelist)
        trusted.rs    # commandes trusted : parsing + wrapping + checksum + scan + exécution
        sink.rs       # trait Sink + FileSink / CallerSink / PipeSink
      tests/
        evasion.rs    # tests d'évasion (.., symlinks, absolus, unicode...)
        commands.rs
        e2e.rs        # spawn du binaire, protocole JSON ligne par ligne
  tests/              # tests d'intégration haut niveau (niveau workspace)
  fuzz/
    Cargo.toml
    fuzz_targets/
      parse_input.rs
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
| Async + timeout par commande | `tokio` |
| `grep` dans des fichiers | `grep` (moteur ripgrep en lib) |
| `ls` (respecte .gitignore, bornes) | `ignore` (walker ripgrep) |
| Checksum sha256 des commandes trusted | `sha2` |
| Regex des fichiers sensibles | `regex` (temps linéaire, pas de ReDoS) |
| Limites mémoire/CPU du sous-processus | `rlimit` |
| Logs structurés | `tracing`, `tracing-subscriber` |
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
