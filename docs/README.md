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
la-console --root <chemin> [--mode user|server] [--timeout-secs N] [--max-output-bytes N] [--trusted-file <chemin> --trusted-sha256 <hex>] [--sensibles-file <chemin>] [--sandbox-busybox <chemin> [--sandbox-busybox-sha256 <hex>]] [--sandbox-tools-dir <dir>]
```

Deux modes de déploiement (voir [spec/security.md](../spec/security.md)) :
`--mode user` (défaut) tourne partout, macOS compris, avec le confinement pur
Rust ; `--mode server` (Linux uniquement) re-exécute la console dans un user
namespace non privilégié + chroot (`unshare`), pour un déploiement serveur —
refusé proprement (exit 2) sur les autres plateformes. La console doit tourner
comme l'utilisateur propriétaire du `root`.

En mode serveur, la cage peut être équipée d'une mini-image (v2 étape 2) :
`--sandbox-busybox` (busybox statique, épinglable par sha256) placé en
`/bin/busybox` avec ses applets, et `--sandbox-tools-dir` (ex. git + go) copié
en `/opt/la-console-tools` ; `/bin` et l'outillage sont remontés read-only au
démarrage (échec = exit 2, fail-closed). Avec un busybox stagé, les commandes `trusted` tournent via
`busybox sh -c` ; sans busybox, elles restent indisponibles (`denied`).

- Entrée : `{"op": "exec", "cmd": "ls src"}`
- Sortie : `{"ok": true, "code": 0, "stdout": "...", "stderr": "", "truncated": false}`
- Refus : `{"ok": false, "code": 2, "kind": "denied", "stdout": "", "stderr": "denied: ...", "truncated": false}`

En cas d'échec, le champ `kind` (absent en cas de succès) classe l'erreur :
`denied` (code 2, refus de sécurité), `limit` (code 3, limite dépassée :
timeout, quota, bornes) ou `fail` (code 1, erreur d'usage/I/O).

La console est stateless : chaque commande repart du `root`.

## Commandes disponibles

Whitelist v1 (voir [ROADMAP.md](../ROADMAP.md)) :
`cat <path...>`, `ls [path] [--all]`, `echo <text> [> path | >> path]`,
`grep <pattern> <path...> [--all]`, `sub <pattern> <repl> <path...>`,
`sed [-i] s/<pat>/<repl>/[g] <path...>` (alias sed restreint : sans `-i` affiche
le résultat sur stdout pour prévisualiser, avec `-i` réécrit les fichiers en
place ; seule la forme `s///` avec le flag `g` est supportée),
`http <METHOD> <url> [--data b] [--header k:v]` (v1 : `localhost` uniquement) et
`help [commande]` (liste les commandes disponibles et leurs syntaxes) sont
disponibles. Toute autre commande est refusée (`denied: unknown command`,
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
