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
| `sub <pattern> <repl> <path>` (sed-like) | ✅ | substitution via `regex` uniquement, fichiers bornés ; **fichier-only** : `denied` dans un pipe (après `|`) |
| `sed [-i] s/<pat>/<repl>/[g] <path...>`, et `… | sed s/<pat>/<repl>/[g]` (sans chemin, position > 0 du pipe) | ✅ | alias sed **restreint** : voir ci-dessous |
| `head [-n N] [path...]` / `tail [-n N] [path...]` | ✅ | filtres de flux (paquet B) : voir « Filtres de flux » ci-dessous |
| `wc [-l\|-w\|-c] [path...]` | ✅ | idem |
| `sort [-r] [path...]` / `uniq [-c] [path...]` | ✅ | idem |
| `cut -d <sep> -f <n[,m...]> [path...]` / `tr <from> <to> [path...]` | ✅ | idem |
| `json <selector> [path...]` | ✅ | extracteur JSON minimal (paquet D) : voir « Paquet D » ci-dessous |
| `tee <path>` (position de flux uniquement, après `\|`) | ✅ | paquet E : voir « Paquet E » ci-dessous |
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

### Paquet C de whitelist-expansion (décision actée) : `sed` sur flux

- `sed s/<pat>/<repl>/[g]` **sans opérande de chemin** transforme le flux
  d'entrée (pipe, ou redirection `<` qui a priorité) et écrit le résultat sur
  stdout. **Règle de position, enforce au parse** (`parse_pipe`) : accepté
  uniquement en **position > 0 d'un pipe** ; hors de cette position (commande
  seule, ou tête de pipe), `sed s/…/…/` sans chemin est rejeté au parse
  (`SedStreamNeedsPipe`, message d'usage) — il n'y a pas de stdin terminal dans
  ce protocole, donc rien à lire en position 0.
- `sed -i` exige au moins un chemin et est **refusé en position de flux**
  (`SedInPlaceInPipe` au parse) : la réécriture in-place ne passe que par
  `FileSink`, en commande autonome.
- `sub` reste **fichier uniquement** : `cat x | sub a b …` = `denied` au parse
  (`SubInPipe`, message explicite).
- Compatibilité : `sed s/a/b/ f.txt`, `sed -i s/a/b/ f.txt` et `sub` en tête de
  pipe inchangés ; `cat x | sed s/a/b/ > out.txt` fonctionne (redirection
  réservée au dernier élément du pipe, via `FileSink` : resolve + sensibles +
  quota + masquage, validation avant ouverture).
- Bornes : entrée déjà bornée en amont (`PipeSink` ≤ `max_output_bytes`,
  `read_bounded` pour `<`) ; sortie via `PipeSink`/`CallerSink` (troncature +
  masquage des secrets) ; UTF-8 strict (invalide = `fail`) ; pattern ERE à
  temps linéaire comme aujourd'hui (`(?m)`, `s///` + `g` uniquement).
- Invariant testé par proptest/fuzz : `pipe_has_stream_forbidden` — jamais de
  `sub` ni de `sed -i` après la tête d'un pipe, jamais de `sed` sans chemin
  hors position de flux.

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
| `-f FILE`, `--file=FILE` | patterns lus dans un fichier (un par ligne) | ✅ acceptés (paquet A3) : lecture via `read_bounded` (resolve + sensibles + `max_read_bytes`), UTF-8 strict, ≤ `max_grep_patterns`, ≤ 4096 o/ligne |
| `--include=GLOB`, `--exclude=GLOB`, `--exclude-dir=GLOB` | filtre sur noms de fichiers/dossiers (sémantique gitignore, voir détails ci-dessous) | ✅ acceptés (paquet A2) : bornés, récursif uniquement, sans effet sur la protection cachés/`.gitignore` |
| `--exclude-from=FILE` | exclusions depuis un fichier (un glob par ligne) | ✅ acceptés (paquet A3) : idem `-f` en lecture ; chaque ligne = un `--exclude`, comptée dans `max_grep_globs` |
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
- Filtres de fichiers `--include=GLOB` / `--exclude=GLOB` / `--exclude-dir=GLOB` (paquet A2) :
  - sémantique **gitignore** via `ignore::overrides` : un glob sans `/` matche le nom de
    fichier à n'importe quelle profondeur (`--include='*.rs'` matche `src/a.rs`) ; `*` ne
    traverse pas `/`, `**` si ; dernier glob matchant gagne (whitelist = include, `!` = exclude) ;
  - `--include` = whitelist : si au moins un `--include` est présent, seuls les fichiers
    matchant un include sont cherchés, moins les `--exclude` ;
  - `--exclude-dir` ne s'applique qu'aux **dossiers** (sous-arbre élagué) ; la racine de la
    recherche (depth 0) n'est jamais exclue ;
  - les filtres ne s'appliquent qu'en **recherche récursive** (target = dossier) : un fichier
    passé explicitement est toujours lu (après `resolve()` + bornes), comme GNU grep ;
  - ils sont appliqués via `filter_entry` **après** les filtres `hidden`/`.gitignore` du
    walker : `--include` ne peut donc jamais rendre visible un fichier caché ou ignoré
    sans `--all` (protection de base inchangée, fail-closed) ;
  - bornes : longueur d'un glob ≤ 256 octets (`MAX_GREP_GLOB_BYTES`, sinon `fail`), nombre
    total de globs ≤ `Limits::max_grep_globs` (64 par défaut, sinon `limit`), glob invalide
    (ex. `[` non fermé) = `fail` explicite ; les globs ne changent que la sélection, jamais
    l'accès (chaque fichier retenu repasse par `resolve()` + `check_read_bound`,
    `follow_links(false)`) ; formes `--include=GLOB` et `--include GLOB` acceptées.
- `-f FILE` / `--file=FILE` et `--exclude-from=FILE` (paquet A3) : le fichier est lu via
  `read_bounded`, donc `resolve()` (pas de sortie du root), refus des fichiers sensibles,
  fichier régulier uniquement et `max_read_bytes` ; UTF-8 strict (invalide = `fail`) ;
  lignes vides ignorées ; chaque ligne ≤ 4096 octets (`MAX_GREP_PATTERN_BYTES`, sinon `fail`) ;
  total ≤ `Limits::max_grep_patterns` (10 000 par défaut, sinon `limit`). Les patterns `-f`
  sont compilés comme les `-e` (ERE à temps linéaire, ou littéraux avec `-F`) : pattern
  invalide = `fail` ; `-f` + `-e` = union, et dès qu'un `-f` est donné tous les arguments
  positionnels sont des chemins ; `-f` sans aucun pattern (fichier vide) = `fail`.
  `--exclude-from=FILE` : chaque ligne non vide devient un glob `--exclude` (validé à la
  lecture, invalide = `fail`), et les globs du fichier sont comptés dans `max_grep_globs`.
  Fuite indirecte couverte : la sortie passe par `CallerSink` (masquage des secrets).
- `--` termine les options (permet un pattern commençant par `-`). `-` seul est refusé
  (`fail`) : sans chemin, l'entrée (pipe ou `<`) est lue automatiquement.
- Avant `--`, tout argument commençant par `-` (même s'il contient un wildcard) est
  traité comme une option : parsing strict, option inconnue ou refusée = `fail` avec
  message explicite.
- Code de sortie : 0 si au moins une ligne est sélectionnée (tous fichiers confondus),
  1 sinon. `-v` inverse la sélection avant tout mode de sortie ; `-v -o` produit donc un
  stdout vide mais code 0 si des lignes sont sélectionnées.

## Filtres de flux (paquet B de whitelist-expansion : décision actée)

Syntaxe commune : `<filtre> [flags] [path...]` — **sans `path`, le filtre lit
l'entrée** (pipe ou redirection `<`) ; avec des chemins (globs autorisés), il
lit la **concaténation** des fichiers via `read_bounded` (`resolve()` +
sensibles + `max_read_bytes`), comme `cat`. Règles communes : UTF-8 strict
(invalide = `fail`), toute option inconnue = `fail` (fail-closed), aucune
écriture disque, aucune exécution de code (in-process), sortie bornée via
`PipeSink`/`CallerSink` (troncature + masquage des secrets en bout de pipe).

| Commande | Sémantique | Bornes |
|---|---|---|
| `head [-n N]` (`-nN`, `--lines[=N]`) | N premières lignes (défaut 10) | N ≤ min(10 000, `max_stream_lines`) sinon `fail` ; streaming |
| `tail [-n N]` (idem) | N dernières lignes (défaut 10) | idem ; buffer circulaire de N lignes |
| `wc [-l\|-w\|-c]` (+ `--lines`/`--words`/`--bytes`/`--chars`) | compte les lignes (octets `\n`), les mots, les octets ; les 3 par défaut, sur une seule ligne séparée par des espaces | streaming |
| `sort [-r]` (`--reverse`) | tri lexicographique UTF-8, `-r` renverse ; chaque ligne de sortie est terminée par `\n` (comme GNU sort) | seules lignes bufferisées : ≤ `Limits::max_stream_lines` (100 000 par défaut, sinon `limit` code 3) |
| `uniq [-c]` (`--count`) | supprime les doublons **adjacents** ; `-c` préfixe le compte du run | streaming (une seule ligne retenue en mémoire) |
| `cut -d <sep> -f <n[,m...]>` (`--delimiter=`/`--fields=`) | champs 1-based ; `sep` = exactement 1 caractère (pas `\n`) ; ligne sans `sep` = affichée entière ; champ absent = vide | liste `-f` ≤ 256 champs sinon `fail` |
| `tr <from> <to>` | traduction de caractères ; plages simples `a-z`, échappements `\n \t \r \\` | sets expansés ≤ 1024 chars sinon `fail` ; `from` plus long que `to` → padding avec le dernier char de `to` (GNU) |

- `--` termine les options partout. Codes de sortie : 0 succès, 1 = `fail`
  (usage, option inconnue, fichier absent, UTF-8 invalide — message sur
  stderr), 2 = `denied` (chemin hors du root, fichier sensible), 3 = `limit`
  (borne dépassée, ex. `sort` au-delà de `max_stream_lines`).
- Les filtres ne lisent jamais hors du root et ne peuvent pas écrire : les
  redirections `>`/`>>` restent traitées par le dispatcher via `FileSink`
  (validation avant ouverture, quota, masquage), comme pour toute commande
  whitelist.

## Paquet D de whitelist-expansion (décision actée) : extracteur JSON minimal

Syntaxe : `json <selector> [path...]` — **sans `path`, lit l'entrée** (pipe ou
redirection `<`) ; avec des chemins (globs autorisés), parse chaque fichier via
`read_bounded` (`resolve()` + sensibles + `max_read_bytes`) et émet **une ligne
de sortie par source**.

- **Sélecteur** : un seul mot (quotable), ex. `body.items[0].name` ; `.` ou ``
  (vide) = document entier. Segments séparés par `.` (clé d'objet) et `[N]`
  (index de tableau). Parsing strict et fail-closed : segment vide (`a..b`),
  point terminal (`a.`), index vide/non numérique (`a[]`, `a[x]`, `a[-1]`),
  `]` dans une clé ou contenu après `]` sans `.` (`a[0]b`) = `fail` avec message
  explicite. Longueur bornée (4096 octets, `MAX_SELECTOR_BYTES`) et nombre de
  segments ≤ `Limits::max_json_depth` sinon `fail`.
- **Parsing JSON** : `serde_json` (fail-closed : JSON invalide, UTF-8 invalide
  ou profondeur > limite interne du parser = `fail`) ; profondeur du document
  vérifiée après parse ≤ `Limits::max_json_depth` (128 par défaut,
  `DEFAULT_MAX_JSON_DEPTH`, = limite de récursion de serde_json) sinon
  `limit` (code 3). Taille d'entrée déjà bornée en amont (`PipeSink` ≤
  `max_output_bytes`, `read_bounded` ≤ `max_read_bytes`).
- **Sémantique d'extraction** (style jq) : clé absente d'un objet → `null` ;
  index hors bornes d'un tableau → `null` ; indexer `null` → `null` ; indexer
  un autre type incompatible (ex. `.a` sur un nombre, `[0]` sur un objet) =
  `fail` (code 1) avec message explicite.
- **Sortie** : la valeur extraite sérialisée en JSON compact + `\n`
  (`"first"` pour une chaîne, `3` pour un nombre, `null`, …), via
  `PipeSink`/`CallerSink` (troncature + masquage des secrets en bout de pipe).
- **Aucune option** : tout premier argument commençant par `-` (même `-`
  seul) = `fail` « unsupported option » (fail-closed ; pas de `-r` en v1).
- Codes de sortie : 0 succès, 1 `fail` (usage, option, sélecteur invalide, JSON
  invalide, type incompatible, fichier absent — les autres fichiers continuent,
  message sur stderr), 2 `denied`, 3 `limit`.

## Paquet E de whitelist-expansion (décision actée) : `tee`

Syntaxe : `tee <path>` — **uniquement en position de flux** (après `|` dans un
pipe) : ce protocole n'a pas de stdin terminal, donc `tee` hors position de
flux (commande seule ou tête de pipe) est rejeté au parse (`TeeNeedsPipe`,
`denied` code 2). En dernière position de pipe, une redirection `>`/`>>` reste
possible : elle s'applique à la sortie passée à l'identique, via `FileSink`.

- **Sémantique** : copie le flux d'entrée (pipe, ou redirection `<` qui a
  priorité) dans le fichier cible **et** le passe **inchangé** à la suite du
  pipe : `cat app.log | tee copy.txt | grep ERROR` écrit `copy.txt` et affiche
  les lignes `ERROR`. Évite le fichier intermédiaire.
- **Écriture** : exactement comme une redirection `>` — via `FileSink`
  (`write_file`) : `resolve()` + fichiers sensibles + `max_write_bytes` +
  `DiskQuota` partagé avec les redirections de la même commande + masquage des
  secrets, **validation avant ouverture** (échec = aucun octet écrit, aucun
  fichier créé). Le flux transmis à la suite du pipe n'est pas masqué (comme
  `cat` : le masquage se fait en bout de pipe via `CallerSink`).
- **Aucune option** en v1 (`-a`/`--append` non supportés : toute option =
  `fail` « unsupported option ») ; exactement **un** opérande cible, et aucun
  glob autorisé dans la cible (`fail`).
- Codes de sortie : 0 succès, 1 `fail` (usage, option inconnue, glob dans la
  cible), 2 `denied` (chemin hors du root, fichier sensible), 3 `limit`
  (borne d'écriture `max_write_bytes` ou quota disque par commande).
- Invariant testé par proptest/fuzz : `pipe_has_stream_forbidden` — jamais de
  `tee` hors position de flux dans une entrée qui parse.

## Commandes trusted

- Définies par l'humain dans un fichier dédié du dépôt où tourne l'agent (ex.
  `trusted.toml`), que l'agent ne peut pas modifier (revu en PR, protégé par
  review humaine).
- **Format `trusted.toml`** (seul format accepté ; détection par extension :
  `.toml` uniquement — le v1 `trusted.txt` a été retiré, toute autre extension
  = refus fail-closed) : schéma strict (`deny_unknown_fields`, crate `toml`
  épinglée en direct), une table `[commands.<nom>]` par entrée, `<nom>` doit
  matcher `^[A-Za-z_][A-Za-z0-9_-]*$` ; champs : `command` (obligatoire),
  `description` (texte libre rendu par `help`), `no_path_check`,
  `timeout_secs`, `max_write_bytes`, `mem_bytes`, `cpus`,
  `network` (`none`/`loopback`/`proxy`), et `flags` = table
  `"<flag>" = { description = "..." }` (allowlist des arguments `-...` ;
  tout flag non déclaré = `denied`). La console complète la commande avec
  `"$@"` : les arguments de l'agent sont passés tels quels, jamais
  réinterprétés.
- Invoquées par l'agent via `trusted <nom>` ; la console ne parse pas le
  contenu, elle le passe tel quel à un vrai shell avec `cwd = root` et un
  environnement réduit (variables d'env minimales, `HOME` pointé hors du root).
- En pipe, `trusted` n'est accepté qu'en **tête** (`trusted <nom> | <whitelist…>`) :
  sa sortie (bornée via `PipeSink`) alimente les commandes whitelist suivantes ;
  `whitelist | trusted …` et `a | trusted … | b` sont refusés au parse
  (`denied`), le stdin du shell trusted restant `null` — aucun octet pipé ne
  peut donc être interprété par le shell.
- Leurs arguments de chemin passent par la boucle de validation (resolve +
  sensibles), **sauf `no_path_check = true`** déclaré par l'humain dans
  `trusted.toml` pour les commandes qui doivent légitimement toucher hors du
  root. Les arguments commençant par `-` doivent être déclarés dans `flags` ;
  les globs dans les arguments sont toujours refusés.
- Avant chaque exécution : **checksum** (sha256) du fichier de commandes
  trusted re-vérifié (exécution uniquement si checksum attendu == checksum
  constaté).
- **Plus d'`ulimit`** (décision v2 livrée) : le shell exécute `{command} "$@"`
  tel quel. Le timeout wall-clock + kill du **groupe de processus** est appliqué
  par la console elle-même : `timeout_secs` par entrée (défaut
  `--timeout-secs`), le fils étant spawné dans son propre groupe de processus
  (`process_group(0)`, kill du groupe à la deadline).
- Les limites `max_write_bytes` = quantité d'écriture disque, `mem_bytes`,
  `cpus`, `network` sont **par entrée** dans `trusted.toml`, appliquées par le
  backend OS (seatbelt / landlock / WSL2). Tant qu'aucun backend n'est
  disponible, une entrée qui en déclare une est refusée `denied` (fail-closed) ;
  une entrée sans limite déclarée garde le comportement v1 (réseau joignable,
  périmètre = revue humaine + checksum) — voir [platforms.md](platforms.md) §4
  et [plugins.md](plugins.md).
- `help` liste les entrées trusted avec leurs limites déclarées.

## Commande `git` (whitelist, planifiée v2)

- **Read-only d'abord**, in-process via la crate `git2` (libgit2 — nouvelle
  dépendance à auditer via `cargo deny`, toolchain C requise) : `git status`,
  `git diff [-- <path...>]`, `git log [-n N] [-- <path...>]`, `git show <rev>`,
  `git branch [-a]`, `git rev-parse <rev>`. Alternative à trancher : spawn du
  binaire `git` épinglé par sha256 avec sous-commandes fixées et args validés
  (mécanisme plugin, moins « in-process »).
- Règles communes : `cwd = root` (le dépôt = le root), tous les chemins
  d'arguments passent par `resolve()` + sensibles, sortie via
  `CallerSink`/`PipeSink` (bornée, masquage des secrets), composable en pipe
  comme les filtres de flux, timeout par commande, **aucun réseau**
  (`push`/`pull`/`fetch`/`clone` = `trusted` uniquement).
- **Mutations** (`add`, `commit`, `checkout`, `rebase`, `push`…) : restent
  `trusted` (déclarées par l'humain, épinglées sha256) en v2 ; un sous-ensemble
  whitelist pourra être décidé plus tard.
