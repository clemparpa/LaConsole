# Plugins (brouillon — discussion v2)

> Statut : **brouillon soumis à revue**. Aucune implémentation derrière pour
> l'instant. Objectif : un mécanisme de « plugins » (ex. lancer des conteneurs
> OCI) où le **harnais de l'agent déclare la politique** (fichiers revus par un
> humain, épinglés par sha256, comme `trusted.txt`) mais où **la console conserve
> la validation, le confinement, les limites et le kill de l'exécution** — jamais
> délégués au harnais.

## Principe absolu

Un plugin est un **sous-processus épinglé**, jamais du code chargé dans le
processus console :

- ❌ pas de bibliothèque dynamique chargée dans le binaire (`dlopen`/`.so`) :
  un bug du plugin tournerait avec les privilèges de la console *à l'intérieur*
  de la frontière de confinement — évasion directe ;
- ✅ un exécutable séparé, déclaré dans un manifeste épinglé par sha256 et
  **re-vérifié avant chaque exécution** par la console elle-même (même modèle
  que `trusted.txt`, `trusted.rs`).

## Surface protocole : proche de la syntaxe standard

Pour ne pas dépayser l'agent (LLM), un plugin s'invoque **comme l'outil standard
qu'il encapsule**, dans le champ `cmd` du protocole ligne par ligne existant —
aucun nouveau format :

```json
{"op": "exec", "cmd": "docker run --rm alpine echo hi"}
```

- Le premier mot de `cmd` est le **nom standard de l'outil** déclaré dans le
  manifeste (ex. `docker`, `podman`, `git`) — la console le mappe vers le binaire
  épinglé. L'agent retrouve une syntaxe familière (sous-commandes, flags usuels).
- Réponse : **exactement le contrat v1**, une ligne JSON
  (`{ok, code, kind?, stdout, stderr, truncated}`), inchangé.
- La console n'accepte qu'un **sous-ensemble allowlisté** de la syntaxe réelle :
  toute sous-commande, tout flag ou toute valeur hors de la liste déclarée =
  erreur `fail` (code 1) avec message précis indiquant la forme acceptée (même
  esprit que l'alias `sed` restreint, `spec/commands.md`).

## Manifeste `plugins.txt`

Fichier dédié du dépôt où tourne l'agent, lu via `--plugins-file <path>` et
épinglé via `--plugins-sha256 <hex>` (miroir de `--trusted-file` /
`--trusted-sha256`). Une entrée par ligne, champs `clé: valeur` séparés par des
espaces :

```
# <nom-outil> = <binaire-absolu> ; sous-commandes: ... ; flags: ... ; network: none|localhost ; limits: ...
docker = /opt/la-console-plugins/docker-crun ; subcommands: run, ps, images ; flags: --rm, --name, -v, --network, -e, --memory, --cpus ; network: none ; limits: mem=512m,cpus=1,pids=100
```

- `<nom-outil>` matche `^[A-Za-z_][A-Za-z0-9_-]*$` et doit ressembler au nom
  usuel de l'outil pour rester familier à l'agent ;
- nom dupliqué, ligne mal formée, binaire hors d'un répertoire autorisé =
  refus total au chargement (**fail-closed**) ;
- lignes vides et `#` commentaires ignorés ;
- avant **chaque** exécution : relecture du manifeste, comparaison sha256 contre
  `--plugins-sha256` ; mismatch = `denied` (code 2), aucune exécution.

## Règles d'exécution (toutes appliquées par la console)

- **argv reconstruit, jamais de chaîne shell** : `[binaire épinglé] + [argv
  prefixe déclaré] + [args validés]` ; les args de l'agent sont passés tels
  quels en position finale, jamais réinterprétés par un shell ;
- **sous-commandes et flags allowlistés** : parsing maison des args façon CLI
  standard (`sous-commande`, `--flag`, `--flag=valeur`, `-f`) ; tout le reste
  = `fail` avec la syntaxe acceptée ;
- **args de chemin** (ex. `-v <src>:<dst>`, chemins de build context) :
  `resolve()` + fichiers sensibles, sauf flag explicite `--no-path-check`
  déclaré par l'humain dans le manifeste ; chaque chemin résolu doit rester
  sous le `root` ;
- **autres args** : validés contre le schéma déclaré (type/pattern), jamais
  libres ;
- environnement réduit (`PATH`, `LANG`, `HOME` hors du root), `cwd = root`,
  **stdin = null** (le stdin du processus appartient au protocole JSON) ;
- **sortie** : `stdout`/`stderr` du plugin passent par `CallerSink` (masquage
  des secrets, troncature à `max_output_bytes`) avant la réponse JSON ;
- **limites** : timeout par invocation (`run_with_timeout`, défaut 30 s) avec
  `kill()` du **groupe de processus entier** (un runtime de conteneurs forke —
  tuer le seul leader laisserait tourner le conteneur) ; `ulimit` sur le
  sous-processus (`-v` mémoire, `-t` CPU + grâce, `-f` = quota disque) ; limites
  déclarées dans le manifeste (`mem`, `cpus`, `pids`) injectées dans la config
  générée pour le runtime (ex. `--memory`, `--pids-limit` du conteneur) — deux
  couches, defense in depth ;
- **quota disque** : `DiskQuota` partagé entre tous les `FileSink` de
  l'invocation, comme pour les commandes whitelist ;
- **réseau** : `network: none` par défaut ; `localhost` = allowlist
  `localhost`/`127.0.0.1`/`::1` comme `http` v1. Aucun pull d'image : les images
  doivent être pré-stagées dans la cage ;
- **pipes** : ❌ v1, un plugin ne participe à aucun pipe (comme `trusted`) ;
  `;`/`&&` autorisé uniquement si les deux côtés sont whitelist ou plugin ;
  **redirections de sortie** `>`/`>>` vers un chemin du root, via `FileSink`
  validé (resolve + sensibles + bornes) avant ouverture.

## Mode serveur (cage)

- Les binaires de plugins (et leurs dépendances ELF, via `ldd`) sont stagés dans
  la cage en read-only (réutilise la machinerie de staging de la v2 étape 2 :
  `--sandbox-tools-dir` / nouveau `--sandbox-plugins-dir`), puis remountés
  read-only au démarrage — si le remount échoue, la console refuse de démarrer
  (fail-closed, exit 2) ;
- sans binaire stagé pour un plugin déclaré, ce plugin = `denied` (fail-closed),
  comme `trusted` sans busybox ;
- dans la cage, `--root /` : tout chemin de l'agent est résolu sous la racine de
  la cage.

## Répartition des responsabilités

| Rôle | Harnais de l'agent | la-console |
|---|---|---|
| Déclare la politique (manifeste, sha256, revue humaine) | ✅ | lit + re-vérifie |
| Valide les args (resolve, sensibles, schéma) | ❌ | ✅ |
| Confinement (root / cage userns+chroot) | ❌ | ✅ |
| Limites (timeout, mémoire, disque, sortie) et kill | ❌ | ✅ |
| Exécution du binaire | ❌ | ✅ (sous-processus, jamais in-process) |
| Journalisation (op, plugin, sha256, code/kind dans la réponse) | ❌ | ✅ |

Règle : la console doit rester **fail-closed même si le harnais ment** sur le
manifeste — d'où la re-vérification sha256 côté console avant chaque exécution.

## Menaces couvertes (rappel)

- plugin épinglé par erreur/malveillance → revue humaine + sha256 + re-vérif ;
- fork bomb / fuite de processus → limite `pids` + kill du groupe de processus ;
- évasion réseau → `network: none` par défaut, allowlist localhost sinon ;
- écriture disque hors bornes → confinement root + `DiskQuota` + `ulimit -f` ;
- contournement du manifeste par l'agent → manifeste hors du root, sha256
  vérifié à chaque exécution, args jamais réinterprétés.

## Phases proposées

1. Ce document, revu et validé (cette PR) ;
2. Implémentation : `plugins.rs` (parse manifeste, sha256, schéma d'args,
   exécution) en réutilisant `TrustedRegistry` / `run_with_timeout` / `DiskQuota`
   ; `help` liste aussi les plugins déclarés ;
3. `trusted` reste en place (cas particulier « plugin shell ») ; migration
   éventuelle plus tard.
