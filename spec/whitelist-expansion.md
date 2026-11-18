# Élargissement de la whitelist — filtres de flux pour l'agent (brouillon — discussion v2)

> Statut : **brouillon soumis à revue**. Objectif : rendre l'agent autonome sur le
> filtrage et la transformation de sorties (`head`/`tail`, `sort`, `uniq`, `wc`,
> `cut`, `tr`, flags `grep` utiles, `sed` sur flux) **sans** élargir la surface
> d'attaque : toute commande ajoutée reste in-process, confinée, bornée et testée,
> et `trusted` (revu en PR, épinglé sha256) reste l'échappatoire certifié pour tout
> le reste, composable en tête de pipe depuis la PR #30.

## Pourquoi (constats sur le code actuel)

- Sur un flux pipe, seules `cat` et `grep` lisent l'entrée : `sed` et `sub`
  ignorent `_input` et exigent des chemins de fichiers (`commands/sed.rs:15`,
  `commands/sub.rs:6`). `cat log | sed s/a/b/` ne transforme donc **pas** le flux.
- `grep` n'accepte que `--all`/`-a` ; toute autre option est un `fail`
  (`commands/grep.rs:20-24`) : pas de `-v` (inverser = supprimer les lignes de
  bruit), pas de `-i`, pas de `-c`. Les numéros de ligne sont déjà affichés par
  défaut (`path:ligne:` sur fichiers, `(stdin):ligne:` sur flux).
- Aucun `head`/`tail`/`sort`/`uniq`/`wc`/`cut`/`tr`/extracteur JSON en whitelist
  (registre `COMMANDS`, `commands/mod.rs`).
- La troncature automatique début+fin (`CallerSink`, flag `truncated`) borne déjà
  les grosses sorties, mais ne remplace pas « prendre les N dernières lignes d'un
  log ».
- La pagination (`less`) n'a pas de sens ici : le protocole est une ligne JSON par
  requête, pas un terminal. Elle est remplacée par `head`/`tail` + la troncature.

## Principes (inchangés)

- Fail-closed, `#![forbid(unsafe_code)]`, aucun accès disque hors du `root`
  (`resolve()` + sensibles), regex à temps linéaire (crates `regex`/`grep`),
  bornes centralisées dans `Limits`, timeout par commande, masquage des secrets
  en sortie (`CallerSink`/`FileSink`).
- **Règle d'or** : on n'ajoute une commande whitelist que si le besoin est fréquent
  et la sémantique simple à borner. Sinon : `trusted` (ex. `trusted tail50 = tail -n 50`)
  puis `trusted tail50 logs/app.log | grep ERROR`.
- Chaque paquet ci-dessous = une PR dédiée, testable, CI verte (cf. `ROADMAP.md`).

## Propositions (par paquets)

### A. Flags `grep` — décision actée

Décision actée, documentée dans `spec/commands.md` (section « Commande `grep` — flags ») :
acceptés `-F`, `-e`, `-E` (no-op : le dialecte est ERE), `-i`, `-v`, `-w`, `-x`, `-c`, `-o`,
`-l`, `-L`, `-m NUM` (borné), `-q`, `-B/-A/-C NUM` (borné) + `--group-separator`, `-n`
(no-op : toujours actif), `-a/--all` (sens ripgrep, déjà en v1) ; refusés `-P` (PCRE,
ReDoS), `-G` (BRE), `-z`, `-b`, `-h`, `--label`, `-R`, `-d`, `-D`, `--binary-files` et
les cosmétiques ; à réfléchir en v2 : `-f`, `--include`/`--exclude`/`--exclude-from`/
`--exclude-dir`, `-a` binaire (sens GNU, conflit avec `-a` = `--all`).
- Combinaisons de flags courts autorisées (`-vi`), parsing strict : toute option
  inconnue reste un `fail`. `-c` reste borné par `max_grep_matches`.

### B. Filtres de flux whitelist (nouveaux, in-process)

Chaque commande lit l'entrée pipe/`<` (comme `grep` sans chemin) **et** des
chemins optionnels ; entrée bornée (`read_bounded` / `PipeSink` ≤ `max_output_bytes`),
sortie via `PipeSink`/`CallerSink` :

| Commande | Sémantique | Bornes |
|---|---|---|
| `head [-n N]` | N premières lignes (défaut 10) | N borné (ex. 10 000), streaming |
| `tail [-n N]` | N dernières lignes (défaut 10) | buffer circulaire de N lignes borné |
| `wc [-l \|-w \|-c]` | compte lignes/mots/octets (les 3 par défaut) | streaming |
| `sort [-r]` | tri lexicographique UTF-8 (renversé avec `-r`) | nb max de lignes en mémoire (nouveau `Limits::max_stream_lines`, ex. 100 000) |
| `uniq [-c]` | dédoublonne les lignes **adjacentes** (préfixe de compte avec `-c`) | idem |
| `cut -d <sep> -f <n[,m…]>` | extrait des champs (séparateur 1 caractère) | champs bornés, streaming |
| `tr <from> <to>` | traduction de caractères (plages `a-z` simples) | streaming, UTF-8 valide exigé |

Règles communes : UTF-8 invalide = `fail` (comme `sed` aujourd'hui) ; aucune
option inconnue acceptée ; aucune écriture disque (sauf `tee`, paquet E) ; aucune
exécution de code.

### C. `sed` sur flux (pas `sub`)

- `sed s/<pat>/<repl>/[g]` **sans opérande de chemin** transforme le flux d'entrée
  (pipe ou redirection `<`) et écrit le résultat sur stdout. Règle de parse :
  accepté uniquement en **position > 0 d'un pipe** (le parseur connaît la position
  dans `parse_pipe`) ; hors pipe, `sed s/…/…/` sans chemin reste une erreur
  d'usage (comportement actuel). `sed -i` exige au moins un chemin et est refusé
  en position de flux (réécriture in-place = `FileSink` uniquement).
- `sub <pat> <repl> <path...>` reste **fichier uniquement** (in-place) ;
  `cat x | sub a b` = `denied` avec message explicite.
- Compatibilité : `sed s/a/b/ f.txt` et `sed -i s/a/b/ f.txt` inchangés ;
  `cat x | sed s/a/b/ > out.txt` fonctionne (redirection réservée au dernier
  élément du pipe, via `FileSink`).

### D. Extracteur JSON minimal (optionnel, phase tardive)

- `json <path...>` lit un flux/fichier JSON (`serde_json`, déjà dépendance) et
  extrait un champ, ex. `http GET http://127.0.0.1:8080/x | json body .items[0].name`.
- Bornes : profondeur JSON max, taille d'entrée déjà bornée ; parsing fail-closed.

### E. `tee` (optionnel)

- `tee <path>` copie le flux vers un fichier via `FileSink` (resolve + sensibles
  + quota + masquage, validation **avant** ouverture) **et** vers la suite du pipe.
  Évite le fichier intermédiaire. Chemin validé avant toute exécution.

## Hors scope (restent `trusted` ou refusés)

`awk` (mini-langage = grande surface), `jq` complet, `less` (pas de TTY), `xargs`,
toute exécution arbitraire, `find` non borné, etc. → commandes `trusted` certifiées,
composables en tête de pipe (PR #30).

## Sécurité (par paquet)

- **A** : aucun nouveau vecteur — la regex reste à temps linéaire ; `-v` ne change
  que la sélection, pas la lecture.
- **B** : entrée déjà bornée en amont ; pas d'accès disque hors `resolve()` ;
  `sort`/`uniq` bornés en mémoire (`max_stream_lines`) ; UTF-8 invalide = `fail`.
- **C** : règle de position enforce au parse ; `-i` interdit sur flux ; toute
  réécriture passe par `FileSink` (jamais d'ouverture directe).
- **D/E** : `serde_json` fail-closed + profondeur bornée ; `tee` = `FileSink`, donc
  les mêmes garanties que `>`/`>>`.

## Tests (cf. spec/testing.md)

- Unitaires par commande et par borne ; proptest « jamais hors du root », « jamais
  d'option inconnue acceptée », « jamais de `-i` sur flux » ; e2e de pipes
  (`http … | json … | grep …`, `trusted build | tail -20 | grep ERROR`) ;
  fuzz `parse_input` (nouvelle règle de position pour `sed`) ; mutation testing
  ciblé sur le parser via le nightly existant.

## Phases proposées

1. Ce document, revu et validé (cette PR) ;
2. Paquet A — flags `grep` ✅ implémenté (décision actée dans `spec/commands.md` : `-F -e -E -i -v -w -x -n -c -o -l -L -m -q -B/-A/-C` acceptés) ;
2b. Paquet A2 — `--include`/`--exclude`/`--exclude-dir` ✅ implémenté (branche `vibe/grep-globs-a2-3cc883`, décision dans `spec/commands.md` : sémantique gitignore via `ignore::overrides` + `filter_entry` appliqué après `hidden`/`.gitignore` — les filtres ne peuvent jamais désactiver la protection de base ; bornés : 64 globs max, 256 octets/glob, glob invalide = `fail` ; récursif uniquement) ;
2c. Paquet A3 — `-f`/`--file` (patterns) et `--exclude-from` (globs) ✅ implémenté (même branche, décision dans `spec/commands.md`) : lecture via `read_bounded` (resolve + sensibles + `max_read_bytes`), UTF-8 strict, lignes vides ignorées, `max_grep_patterns` = 10 000, 4096 o/ligne, globs du fichier comptés dans `max_grep_globs`) ;
3. Paquet B — filtres de flux (`head`/`tail`/`wc`/`sort`/`uniq`/`cut`/`tr`) ✅ implémenté (branche `vibe/stream-filters-b-c4cd4a`, décision actée dans `spec/commands.md` « Filtres de flux » : `Limits::max_stream_lines` = 100 000, `head`/`tail` N ≤ min(10 000, `max_stream_lines`), `cut` ≤ 256 champs, `tr` sets ≤ 1024 chars) ;
4. Paquet C — `sed` sur flux (règle de position au parse) ;
5. Paquets D (`json`) et E (`tee`) uniquement si un besoin mesuré les justifie.
