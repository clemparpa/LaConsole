# Commandes de la-console

Règle absolue : **toute commande exécutée doit matcher la whitelist (ou
trusted), et tout chemin impliqué passe par `resolve()` + test fichiers
sensibles**, même après expansion de glob ou substitution de variable.

## Parsing

- Tokenisation via `shell-words` (quotes `"..."` / `'...'` style bash), puis
  interprétation **maison et cadrée** des seuls opérateurs autorisés (`&&`/`;`,
  pipes, globs `wax`, variables déclarées, redirections). Aucun appel à
  `sh -c` / `bash -c` pour les commandes whitelistées.

## Whitelist v1

| Élément | Autorisé ? | Détail |
|---|---|---|
| `cat <path>` | ✅ | `resolve()` + taille max |
| `ls [path]` | ✅ | `resolve()`, entrées bornées ; respecte `.gitignore` par défaut, `--all` pour tout lister |
| `echo <text> > <path>` | ✅ | `resolve()`, taille max, `>` seul opérateur de redirection en v1 (`>>` prévu) |
| `grep <pattern> <path...>` | ✅ | via crate `grep`, fichiers bornés ; respecte `.gitignore` par défaut, `--all` pour tout chercher — chaque fichier matché passe quand même par `resolve()` + bornes |
| `sub <pattern> <repl> <path>` (sed-like) | ✅ | substitution via `regex` uniquement, fichiers bornés |
| `http <METHOD> <url> [--data <body>] [--header k:v]` | ✅ | implémentation **Rust maison** (pas de binaire curl), crate `reqwest` + rustls côté console. Allowlist d'hôtes : v1 = `localhost`/`127.0.0.1`/`::1` uniquement, extensible via liste déclarée par l'humain. Blocage des IP de métadonnées cloud (169.254.169.254) et plages privées non déclarées. Timeout court, taille de réponse bornée, redirects revalidés contre l'allowlist. `--data` borné en taille |
| `&&` | ✅ | chaînage séquentiel, stop au 1er échec. **Les deux côtés doivent être whitelist ou trusted.** Jamais de vrai shell |
| `;` | ✅ | interprété comme `&&` (plus strict que bash : stop au 1er échec) |
| pipes `\|` | ✅ (prévu) | **whitelist uniquement, jamais avec `trusted`** ; la console unwrap le `stdout` de la commande de gauche et le passe en entrée de celle de droite |
| redirections `>`, `>>`, `2>`, `2>&1`, `&>` | ✅ | le chemin de destination passe par la **boucle de validation** (resolve + sensibles + bornes) avant toute exécution. `>>` = append autorisé |
| redirection `<` (stdin depuis fichier) | ⏳ reportée | à ouvrir plus tard avec le même pattern : boucle de validation identique + canal interne dédié (jamais le stdin du processus, qui appartient au protocole JSON) |
| globs `*`, `?`, `**` | ✅ | via `wax` ; **chaque fichier matché passe individuellement par `resolve()` + sensibles**, nb de matchs borné |
| variables `$VAR`, `${VAR}`, `$(VAR)` | ⚠️ restreint | uniquement des variables **déclarées par l'humain** (ex. `$ROOT`) ; `$(...)` accepté mais le contenu doit matcher `^[A-Za-z_][A-Za-z0-9_]*$` (nom de variable seule, jamais de sous-exécution) ; **pas d'affectation `FOO=bar`**, pas de variables d'état interne (`$?`, `$!`, `$0`...) |
| backticks | ❌ | jamais de sous-exécution de commande |
| `trusted <nom>` | ✅ | voir ci-dessous |
| tout le reste | ❌ | `unknown command`, fail-closed |

## Commandes trusted

- Définies par l'humain dans un fichier dédié du dépôt où tourne l'agent (ex.
  `trusted.txt`), que l'agent ne peut pas modifier (revu en PR, protégé par
  review humaine).
- Invoquées par l'agent via `trusted <nom>` ; la console ne parse pas le
  contenu, elle le passe tel quel à un vrai shell avec `cwd = root` et un
  environnement réduit (variables d'env minimales, `HOME` pointé hors du root).
- Leurs arguments de chemin passent par la boucle de validation (resolve +
  sensibles), **sauf flag explicite** déclaré par l'humain dans `trusted.txt`
  (ex. `trusted run-tests --no-path-check`) pour les commandes qui doivent
  légitimement toucher hors du root.
- Avant chaque exécution :
  1. **checksum** (sha256) du fichier de commandes trusted consigné ;
  2. **scan des changements** depuis la dernière exécution validée (diff du
     fichier + du code de test associé) pour détecter du code adversarial ;
  3. exécution uniquement si checksum attendu == checksum constaté et scan OK.
- Timeout par commande, `rlimit` sur le sous-processus.
