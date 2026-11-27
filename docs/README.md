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
la-console --root <chemin> [--timeout-secs N] [--max-output-bytes N] [--trusted-file <chemin> --trusted-sha256 <hex>] [--sensibles-file <chemin>] [--secrets-file <chemin>]
```

La console tourne partout (macOS + Linux poste utilisateur) avec le confinement
pur Rust (voir [spec/security.md](../spec/security.md)) ; elle doit tourner comme
l'utilisateur propriétaire du `root`.

Sur Windows natif, le binaire compile et tourne en mode **fail-closed** (phase 1
de [spec/platform.md](../spec/platform.md)) : les commandes whitelist et
`resolve()` fonctionnent normalement, mais `trusted` (pas de shell) et les
limites backend de `trusted.toml` y sont refusés. Le déploiement Windows visé
reste la console lancée dans **WSL2** (voir
[spec/platforms.md](../spec/platforms.md)).

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
`grep [flags] <pattern> [path...]` (`-i -v -c -n …`, `-f FILE`, `--include/--exclude/--exclude-dir GLOB`, `--exclude-from FILE`, `--all`), `sub <pattern> <repl> <path...>`,
`sed [-i] s/<pat>/<repl>/[g] <path...>` (alias sed restreint : sans `-i` affiche
le résultat sur stdout pour prévisualiser, avec `-i` réécrit les fichiers en
place ; seule la forme `s///` avec le flag `g` est supportée) — et, sans chemin,
`… | sed s/<pat>/<repl>/[g]` transforme le flux du pipe en position > 0
(`sed -i` et `sub` restent interdits sur un flux),
`http <METHOD> <url> [--data b] [--header k:v]` (v1 : `localhost` uniquement),
les filtres de flux in-process `head [-n N]`, `tail [-n N]`, `wc [-l|-w|-c]`,
`sort [-r]`, `uniq [-c]`, `cut -d <sep> -f <n[,m...]>`, `tr <from> <to>` (lisent
l'entrée pipe/`<` sans chemin, bornés, UTF-8 strict, aucune écriture disque),
l'extracteur JSON `json <selector> [path...]` (sélecteur `a.b[0].c`, lit le flux
pipe/`<` sans chemin, profondeur bornée, parsing fail-closed),
`tee <path>` (position de flux uniquement, après `|` : copie le flux dans un
fichier via `FileSink` — resolve + sensibles + quota + masquage, validation
avant ouverture — et le passe inchangé à la suite du pipe ; aucune option) et
`help [commande]` (liste les commandes disponibles et leurs syntaxes) sont
disponibles. Toute autre commande est refusée (`denied: unknown command`,
code 2).

`trusted <nom> [args...]` exécute une commande définie par l'humain dans
`--trusted-file`, uniquement si le sha256 du fichier correspond à
`--trusted-sha256` (re-vérifié avant chaque exécution). Un seul format :
`trusted.toml` (extension `.toml` obligatoire, l'ancien `trusted.txt` v1 est
retiré) — manifeste TOML strict avec, par entrée `[commands.<nom>]`,
`command`, `description`, `no_path_check`, `timeout_secs`, `max_write_bytes`,
`mem_bytes`, `cpus`, `network`, et `flags` (allowlist des arguments `-...`
acceptés, chacun avec sa `description` ; tout flag non déclaré = `denied`).
L'exécution se fait dans un shell réduit : `cwd = root`,
environnement minimal (`HOME` hors du root), stdin fermé, **aucun
`ulimit`** — le timeout wall-clock + kill du groupe de processus est
appliqué par la console elle-même (`timeout_secs` par entrée, défaut
`--timeout-secs`). Chaque commande trusted est ensuite spawnée via le
**backend de confinement OS** (crate `nono` épinglée, voir
[spec/sandbox-backend.md](../spec/sandbox-backend.md)) : re-exec de notre
propre binaire (`__sandbox_helper <profil.json> -- <cmd…>`) qui applique le
sandbox — FS confinée au root en écriture, exec restreint au shell + PATH
(Linux, landlock), réseau `none` (défaut) — juste avant l'exec ; tout échec
→ exit code 125 → `denied` fail-closed. `network = "loopback"` marche sur
macOS (Seatbelt `localhost:*`) et est refusé `denied` sur Linux (les règles
réseau landlock sont par port, pas par IP — §8 de la spec) ; les limites
`network = "proxy"`, `max_write_bytes`, `mem_bytes`, `cpus` sont reportées à
une v3 et restent refusées fail-closed (`denied`) entre-temps (décision
2026-11-27). En pipe,
`trusted` n'est accepté qu'en
tête (`trusted x | grep …`) — jamais alimenté par un pipe, son stdin restant
fermé. Les arguments de chemin passent par `resolve()` + fichiers sensibles,
sauf `no_path_check` déclaré dans le manifeste.

## Documents de référence

- [spec/](../spec/README.md) — spécification complète : protocole, architecture, commandes, sécurité, stratégie de test, structure du dépôt ;
- [ROADMAP.md](../ROADMAP.md) — feuille de route : étapes 0 à 7, une PR indépendante et testable par étape.

## Développement

Gate « prêt pour PR » : `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
