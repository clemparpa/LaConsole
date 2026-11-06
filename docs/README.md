# la-console — vue d'ensemble

**la-console** est une fausse console, volontairement très limitée et très sûre,
destinée à être pilotée par un agent (IA) sans risque de sortie de son périmètre.
L'agent envoie des commandes en texte — une ligne JSON par commande sur stdin —
et la console répond en JSON, une ligne par réponse sur stdout.

## Principes

- **Périmètre absolu** : tout accès fichier est confiné sous un répertoire `root` donné.
- **Opérations limitées** : seules quelques commandes whitelistées sont disponibles, plus des commandes « trusted » validées par un humain.
- **Fail-closed** : au doute, refuser. Aucun `unsafe` en v1.

## Lancement et protocole

```
la-console --root <chemin> [--timeout-secs N] [--trusted-file <chemin> --trusted-sha256 <hex>] [--sensitives-file <chemin>]
```

- Entrée : `{"op": "exec", "cmd": "ls src"}`
- Sortie : `{"ok": true, "code": 0, "stdout": "...", "stderr": "", "truncated": false}`
- Refus : `{"ok": false, "code": 2, "stdout": "", "stderr": "denied: ...", "truncated": false}`

La console est stateless : chaque commande repart du `root`.

## Commandes disponibles

Whitelist v1 (voir [ROADMAP.md](../ROADMAP.md)) :
`cat <path...>`, `ls [path] [--all]`, `echo <text> [> path]`,
`grep <pattern> <path...> [--all]`, `sub <pattern> <repl> <path...>` et
`http <METHOD> <url> [--data b] [--header k:v]` (v1 : `localhost` uniquement)
sont disponibles. Toute autre commande est refusée (`denied: unknown command`,
code 2).

`trusted <nom> [args...]` exécute une commande définie par l'humain dans
`--trusted-file` (ex. `trusted.txt`, revu en PR), uniquement si le sha256 du
fichier correspond à `--trusted-sha256` (re-vérifié avant chaque exécution).
L'exécution se fait dans un shell réduit : `cwd = root`, environnement minimal
(`HOME` hors du root), stdin fermé, limites `ulimit` sur le sous-processus,
jamais dans un pipe. Les arguments de chemin passent par `resolve()` +
fichiers sensibles, sauf flag `--no-path-check` déclaré dans `trusted.txt`.

## Documents de référence

- [spec/](../spec/README.md) — spécification complète : protocole, architecture, commandes, sécurité, stratégie de test, structure du dépôt ;
- [ROADMAP.md](../ROADMAP.md) — feuille de route : étapes 0 à 7, une PR indépendante et testable par étape.

## Développement

Gate « prêt pour PR » : `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
