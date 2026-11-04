# Architecture de la-console

La console n'est pas « une boucle qui exécute des commandes » : c'est un
**pipeline de validation composable**, appliqué à trois niveaux imbriqués.
Toute donnée (commande, chemin, sortie) passe par les mêmes gardes, quel que
soit le niveau auquel elle se trouve.

## Vue d'ensemble

```mermaid
flowchart TD
    A[ligne JSON {op: exec, cmd}] --> P[1. VALIDATION ENTRÉE<br/>parse shell-words<br/>expansion variables/globs]
    P --> V[2. BOUCLE DE VALIDATION CHEMINS<br/>resolve() + sensibles + bornes<br/>pour chaque chemin impliqué]
    V -->|ok| X[exécution avec timeout]
    V -->|denied| R1[réponse JSON erreur]
    X --> S[3. VALIDATION SORTIE<br/>troncature, masquage secrets, formatage]
    S -->|flux interne pipe/redirection| X2[commande suivante de la chaîne]
    S -->|sortie finale| R2[réponse JSON {ok, code, stdout, stderr}]
```

## Les trois niveaux de validation

### Niveau 1 — Validation de l'entrée (la commande elle-même)

- Tokenisation (`shell-words`), puis interprétation cadrée des opérateurs
  autorisés (`&&`/`;`, pipes, redirections, globs `wax`, variables déclarées).
- Résultat : un **arbre de commandes** (pas une chaîne) — chaque nœud est une
  commande whitelist ou trusted ; chaque branche passe ensuite individuellement
  par les niveaux 2 et 3.

### Niveau 2 — Boucle de validation des chemins (composable)

La boucle centrale, appliquée **à chaque chemin de chaque nœud de l'arbre** :

1. `resolve(root, input)` → confinement (canonicalize, `..`, symlinks) ;
2. test fichiers sensibles (regex sur le chemin relatif) ;
3. bornes (taille lecture/écriture, nb de matchs de glob, quota root).

C'est la même boucle pour un `cat`, une destination de `>`, un glob expansé,
un argument de commande trusted. Aucune exception.

### Niveau 3 — Validation de la sortie

Avant qu'une sortie ne quitte la console (ou ne parte dans un pipe) :

- troncature à `max_output_bytes` (début + fin, flag `truncated`) ;
- masquage des secrets connus (ex. token → `***`) ;
- formatage : **flux brut** entre commandes internes (pipes/redirections),
  **JSON `{ok, code, stdout, stderr}`** uniquement vers l'appelant.

## Composition

- `a && b` : deux nœuds, chacun passe par les 3 niveaux ; stop au 1er échec.
- `a | b` : la sortie validée (niveau 3, flux brut) de `a` devient l'entrée de
  `b` ; `b` repasse par les 3 niveaux. Whitelist uniquement, jamais trusted.
- `a > f` : `f` est validé par la boucle niveau 2 **avant** l'exécution de `a` ;
  la sortie écrite est aussi bornée.

## Interface d'écriture unique (Sink)

Pour éviter toute faille, **toute écriture passe par une seule interface**
(abstraction `Sink` en Rust, ex. trait avec `write(bytes) -> Result<usize>`).
Il existe exactement trois implémentations, et aucun autre code ne doit écrire
directement :

| Sink | Destination | Validations appliquées |
|---|---|---|
| `FileSink` | fichier dans le root (redirections `>`/`>>`) | niveau 2 (resolve + sensibles + bornes + quota) **avant ouverture**, puis masquage secrets + borne de taille pendant l'écriture |
| `CallerSink` | réponse JSON vers l'appelant (stdout du processus) | niveau 3 (troncature, masquage secrets) |
| `PipeSink` | flux brut vers la commande suivante (pipe interne) | troncature uniquement, pas de masquage (flux interne) |

Règles :

- `FileSink` ouvre le fichier **uniquement après** validation complète du chemin
  (resolve + sensibles + bornes) — jamais l'inverse ;
- le masquage des secrets est appliqué dans `FileSink` et `CallerSink`, jamais
  dans `PipeSink` ;
- aucune commande (whitelist ou trusted) n'a le droit d'ouvrir un fichier en
  écriture directement : tout passe par `Sink`.

## Règle d'or

> Toute donnée qui entre, touche au disque, ou sort passe par une validation
> explicite. Il n'y a pas de « chemin rapide ».
