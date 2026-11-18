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
| `echo <text> [> path | >> path]` | ✅ | `resolve()`, taille max, `>` écrase, `>>` append |
| `grep [flags] <pattern> [path...]` | ✅ | via crate `grep`, fichiers bornés ; respecte `.gitignore` par défaut, `--all` pour tout chercher — chaque fichier matché passe quand même par `resolve()` + bornes ; flags : voir « Commande `grep` — flags » ci-dessous |
| `sub <pattern> <repl> <path>` (sed-like) | ✅ | substitution via `regex` uniquement, fichiers bornés |
| `sed [-i] s/<pat>/<repl>/[g] <path...>` | ✅ | alias sed **restreint** : voir ci-dessous |
| `http <METHOD> <url> [--data <body>] [--header k:v]` | ✅ | implémentation **Rust maison** (pas de binaire curl), crate `reqwest` + rustls côté console. Allowlist d'hôtes : v1 = `localhost`/`127.0.0.1`/`::1` uniquement, extensible via liste déclarée par l'humain. Blocage des IP de métadonnées cloud (169.254.169.254) et plages privées non déclarées. Timeout court, taille de réponse bornée, redirects revalidés contre l'allowlist. `--data` borné en taille |
| `&&` | ✅ | chaînage séquentiel, stop au 1er échec. **Les deux côtés doivent être whitelist ou trusted.** Jamais de vrai shell |
| `;` | ✅ | interprété comme `&&` (plus strict que bash : stop au 1er échec) |
| pipes `\|` | ✅ | whitelist, **plus `trusted` autorisé uniquement comme premier élément du pipe** (`trusted run-tests | grep ERROR`) ; toute autre position = `denied` au parse et le stdin de `trusted` reste fermé (aucun flux pipé ne lui est jamais fourni) ; la console unwrap le `stdout` de la commande de gauche et le passe en entrée de celle de droite |
| redirections `>`, `>>`, `2>`, `2>&1`, `&>` | ✅ | le chemin de destination passe par la **boucle de validation** (resolve + sensibles + bornes) avant toute exécution. `>>` = append autorisé |
| redirection `<` (stdin depuis fichier) | ✅ | le fichier source passe par la **boucle de validation** (resolve + sensibles + borne de lecture) avant exécution ; le contenu est lu en mémoire et passé comme entrée à la commande (jamais le stdin du processus, qui appartient au protocole JSON) |
| globs `*`, `?`, `**` | ✅ | via `wax` ; **chaque fichier matché passe individuellement par `resolve()` + sensibles**, nb de matchs borné |
| variables `$VAR`, `${VAR}`, `$(VAR)` | ⚠️ restreint | uniquement des variables **déclarées par l'humain** (ex. `$ROOT`) ; `$(...)` accepté mais le contenu doit matcher `^[A-Za-z_][A-Za-z0-9_]*$` (nom de variable seule, jamais de sous-exécution) ; **pas d'affectation `FOO=bar`**, pas de variables d'état interne (`$?`, `$!`, `$0`...) |
| backticks | ❌ | jamais de sous-exécution de commande |
| `trusted <nom>` | ✅ | voir ci-dessous |
| `help [commande]` | ✅ | lecture seule, sans effet de bord : liste les commandes du registre (avec toutes leurs syntaxes, y compris les formes bis) et les commandes `trusted` déclarées ; la source est le registre `COMMANDS` partagé avec le dispatcher, donc jamais désynchronisé |
| tout le reste | ❌ | `unknown command`, fail-closed |

## Alias `sed` (restreint)

- Syntaxes : `sed s/<pat>/<repl>/[g] <path...>` (affiche le contenu transformé
  sur stdout, **sans toucher aux fichiers** — prévisualisation) et
  `sed -i s/<pat>/<repl>/[g] <path...>` (réécrit les fichiers en place via
  `FileSink` : quota, masquage, bornes).
- Une seule expression `s` par invocation, délimiteur arbitraire non
  alphanumérique (ex. `s@a@b@g`), `\<delim>` échappé dans le pattern/repl.
- Flag autorisé : **`g` uniquement** (remplacement global). Sans `g` : première
  occurrence **par ligne** (comportement sed standard). Tout autre flag
  (`i`, `p`, `w`, `e`, …), toute autre commande (`d`, `y`, adresses `2d`, …),
  tout script multi-commandes (`s/a/b/;s/c/d/`) et toute option autre que
  `-i` (`-n`, `-E`, `-e`, …) = erreur `fail` (code 1) avec message précis
  indiquant la forme non supportée et la syntaxe acceptée.
- Le pattern est une **regex Rust** (`regex`, temps linéaire) compilée avec
  `(?m)` pour que `^`/`$` soient par ligne comme sed. Le remplacement accepte
  les références de groupes façon sed (`\1`…`\9`, traduites en `$1`…`$9`) et
  `&` (match entier, traduit en `$0`) ; `\&` = `&` littéral, `\\` = `\` littéral.
- Cibles : globs autorisés, chaque fichier passe par `resolve()` + sensibles +
  bornes de lecture ; en mode `-i` la réécriture passe par `FileSink`.

## Commande `grep` — flags (paquet A de whitelist-expansion : décision actée)

Syntaxe : `grep [flags] <pattern> [path...]` — sans `path`, lit l'entrée (pipe ou
redirection `<`). Le **dialecte est ERE** (expressions régulières étendues, moteur
`regex` Rust à temps linéaire) : `-E`/`--extended-regexp` est accepté comme no-op
documenté. Les flags courts se combinent (`-vi`) ; parsing strict : toute option
inconnue = `fail`. `-n`/`--line-number` est **toujours actif** et accepté aussi
comme no-op explicite. `-a`/`--all` garde son sens ripgrep (chercher aussi dans les
fichiers cachés et ceux ignorés par `.gitignore`) ; le `-a` de GNU grep
(`--text`, binaires lus comme du texte) n'est pas supporté — voir « à réfléchir ».

| Flag | Effet | Décision |
|---|---|---|
| `-F`, `--fixed-strings` | pattern littéral (aucune regex) | ✅ accepté |
| `-e PAT`, `--regexp=PAT` | déclare explicitement le pattern | ✅ accepté |
| `-E`, `--extended-regexp` | dialecte ERE = défaut | ✅ no-op documenté |
| `-i`, `--ignore-case` | insensible à la casse | ✅ accepté |
| `-v`, `--invert-match` | sélectionne les lignes qui ne matchent pas | ✅ accepté |
| `-w`, `--word-regexp` | mot entier | ✅ accepté |
| `-x`, `--line-regexp` | la ligne entière doit matcher | ✅ accepté |
| `-n`, `--line-number` | numéros de ligne | ✅ toujours actif ; no-op si tapé explicitement |
| `-c`, `--count` | compte les matchs par fichier | ✅ accepté (borné par `max_grep_matches`) |
| `-o`, `--only-matching` | n'affiche que la partie matchée | ✅ accepté |
| `-l`, `--files-with-matches` | noms des fichiers avec au moins un match | ✅ accepté |
| `-L`, `--files-without-match` | noms des fichiers sans match | ✅ accepté |
| `-m NUM`, `--max-count=NUM` | stop après NUM matchs par fichier | ✅ accepté, NUM borné |
| `-q`, `--quiet` | aucun stdout ; code 0 si match, 1 sinon | ✅ accepté |
| `-B N`, `-A N`, `-C N`, `-N` | N lignes de contexte avant/après/autour | ✅ accepté, N borné (ex. ≤ 100) |
| `--group-separator=SEP` | séparateur entre groupes de contexte | ✅ accepté avec `-B/-A/-C` (défaut `--`) |
| `-a`, `--all` | cherche partout (cachés + `.gitignore` ignoré) | ✅ déjà en v1 (sens ripgrep) |
| `-f FILE`, `--file=FILE` | patterns lus dans un fichier | 🤔 v2 : à étudier (`resolve()` + bornes) |
| `--include=GLOB`, `--exclude=GLOB`, `--exclude-dir=GLOB` | filtre sur noms de fichiers/dossiers | 🤔 v2 : à réfléchir (`.gitignore` + cachés restent la sécurité de base, même avec `--all`) |
| `--exclude-from=FILE` | exclusions depuis un fichier | 🤔 v2 (idem `-f`) |
| `-a`, `--text` (sens GNU) | binaires lus comme du texte (ex. images) | 🤔 v2 : à réfléchir ; conflit de sens avec notre `-a` = `--all` |
| `-G`, `-P`, `-z` | BRE / PCRE (ReDoS) / lignes séparées par `\0` | ❌ refusé `fail` |
| `-b`, `-h`, `--label` | offset octets / sans nom de fichier / renomme stdin | ❌ refusé (sortie toujours `fichier:ligne:...`) |
| `-R`, `-d`, `-D` | suit les symlinks / lit les dossiers / lit les devices | ❌ refusé fail-closed |
| `--binary-files=TYPE`, `-I` | politique binaire | ❌ fixée : arrêt sur `\0` (= `-I` implicite, toujours actif) |
| `--color`, `-U`, `-Z`, `-T`, `-s`, `--line-buffered`, `-V`, `--help` | cosmétiques / meta | ❌ refusé (pas de TTY, v1 Unix-only, `help grep` existe) |

Détails d'implémentation :

- Priorité des modes de sortie (comme GNU) : `-q` > `-l` > `-L` > `-c` > `-o` > lignes.
  `-l -L` ensemble → `-l` gagne ; `-q -c` → `-q` gagne (stdout vide, code seul).
- Formats de sortie : match `fichier:ligne:contenu`, ligne de contexte
  `fichier-ligne-contenu` (tiret), séparateur de groupe sur sa propre ligne (défaut
  `--`, modifiable par `--group-separator`, borné à 64 octets). Une ligne n'est jamais
  affichée deux fois (les groupes de contexte chevauchants sont fusionnés).
- `-B/-A/-C N` bornés à `MAX_CONTEXT_LINES` = 100 (`fail` au-delà). `-m NUM` s'applique
  **par fichier** ; `-m 0` = aucun match (code 1) ; la borne globale `max_grep_matches`
  s'applique toujours (dépassée → `limit`, code 3).
- Plusieurs `-e` = OU entre patterns ; si au moins un `-e` est donné, tous les arguments
  positionnels sont des chemins.
- `--` termine les options (permet un pattern commençant par `-`). `-` seul est refusé
  (`fail`) : sans chemin, l'entrée (pipe ou `<`) est lue automatiquement.
- Avant `--`, tout argument commençant par `-` (même s'il contient un wildcard) est
  traité comme une option : parsing strict, option inconnue ou refusée = `fail` avec
  message explicite.
- Code de sortie : 0 si au moins une ligne est sélectionnée (tous fichiers confondus),
  1 sinon. `-v` inverse la sélection avant tout mode de sortie ; `-v -o` produit donc un
  stdout vide mais code 0 si des lignes sont sélectionnées.

## Commandes trusted

- Définies par l'humain dans un fichier dédié du dépôt où tourne l'agent (ex.
  `trusted.txt`), que l'agent ne peut pas modifier (revu en PR, protégé par
  review humaine).
- **Format de `trusted.txt`** : une entrée par ligne,
  `<nom> [--no-path-check] = <commande shell>` ; lignes vides et `#` commentaires
  ignorés ; `<nom>` doit matcher `^[A-Za-z_][A-Za-z0-9_-]*$` ; `--no-path-check`
  est le seul flag autorisé en v1 ; nom dupliqué ou ligne mal formée = refus
  total (fail-closed). La console complète la commande avec `"$@"` : les
  arguments de l'agent sont passés tels quels, jamais réinterprétés.
- Invoquées par l'agent via `trusted <nom>` ; la console ne parse pas le
  contenu, elle le passe tel quel à un vrai shell avec `cwd = root` et un
  environnement réduit (variables d'env minimales, `HOME` pointé hors du root).
- En pipe, `trusted` n'est accepté qu'en **tête** (`trusted <nom> | <whitelist…>`) :
  sa sortie (bornée via `PipeSink`) alimente les commandes whitelist suivantes ;
  `whitelist | trusted …` et `a | trusted … | b` sont refusés au parse
  (`denied`), le stdin du shell trusted restant `null` — aucun octet pipé ne
  peut donc être interprété par le shell.
- Leurs arguments de chemin passent par la boucle de validation (resolve +
  sensibles), **sauf flag explicite** déclaré par l'humain dans `trusted.txt`
  (ex. `trusted run-tests --no-path-check`) pour les commandes qui doivent
  légitimement toucher hors du root.
- Avant chaque exécution :
  1. **checksum** (sha256) du fichier de commandes trusted consigné ;
  2. **scan des changements** depuis la dernière exécution validée (diff du
     fichier + du code de test associé) pour détecter du code adversarial ;
  3. exécution uniquement si checksum attendu == checksum constaté et scan OK.
- Timeout par commande (kill du sous-processus), limites du sous-processus via
  `ulimit` appliqué par le shell lui-même (`-t` CPU, `-f` taille de fichier =
  quota disque, toutes deux fail-closed ; `-v` mémoire 1 GiO en best-effort car
  RLIMIT_AS n'existe pas sur macOS/BSD) : les limites ne touchent que le
  sous-processus, jamais le processus console (pas de `setrlimit` global, donc
  pas besoin de `unsafe`/`pre_exec`).
- **Mode serveur** (voir [security.md](security.md)) : la cage ne contient pas de
  `/bin/sh` système ; si un busybox statique a été stagé
  (`--sandbox-busybox`), `trusted` s'exécute via `<busybox> sh -c` avec
  `PATH = /bin:/opt/la-console-tools/bin:/opt/la-console-tools/go/bin`,
  `HOME=/tmp`, `LD_LIBRARY_PATH` vers les libs stagées et `GOROOT` détecté si
  une toolchain go est dans `/opt/la-console-tools`. Sans busybox stagé,
  `trusted` = `denied` (fail-closed).
