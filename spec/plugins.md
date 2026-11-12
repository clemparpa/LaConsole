# Plugins (brouillon — discussion v2)

> Statut : **brouillon soumis à revue**. Aucune implémentation derrière pour
> l'instant. Objectif : un mécanisme de « plugins » (ex. lancer des conteneurs
> OCI) où le **harnais de l'agent déclare la politique** (fichier revu par un
> humain, épinglé par sha256, comme `trusted.txt`) mais où **la console conserve
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
- La console n'accepte qu'un **sous-ensemble allowlisté** de la syntaxe réelle,
  défini **par sous-commande** dans le manifeste : toute sous-commande, tout
  flag ou toute valeur hors de la liste déclarée = erreur `fail` (code 1) avec
  message précis indiquant la forme acceptée (même esprit que l'alias `sed`
  restreint, `spec/commands.md`).

## Manifeste `plugins.json`

Fichier JSON dédié du dépôt où tourne l'agent, lu via `--plugins-file <path>`
et épinglé via `--plugins-sha256 <hex>` (miroir de `--trusted-file` /
`--trusted-sha256`). Document JSON unique, schéma strict :

```json
{
  "plugins": [
    {
      "tool": "docker",
      "bin": "/opt/la-console-plugins/docker-crun",
      "network": "none",
      "limits": { "mem": "512m", "cpus": 1, "pids": 100 },
      "subcommands": {
        "run": {
          "flags": ["--rm", "--name", "--network", "-e", "--memory", "--cpus"],
          "path_flags": ["-v", "--mount"]
        },
        "ps": { "flags": ["-a", "--format"] },
        "images": { "flags": ["-a"] }
      }
    }
  ]
}
```

Schéma d'une entrée :

| Champ | Obligatoire | Règle |
|---|---|---|
| `tool` | ✅ | matche `^[A-Za-z_][A-Za-z0-9_-]*$`, nom usuel de l'outil ; doublon = refus total |
| `bin` | ✅ | chemin absolu du binaire épinglé, dans un répertoire autorisé ; c'est lui qui est exécuté |
| `network` | ✅ | `"none"` (défaut recommandé) ou `"localhost"` (allowlist `localhost`/`127.0.0.1`/`::1`, comme `http` v1) |
| `limits` | ❌ | objet `{ "mem": "512m", "cpus": 1, "pids": 100 }`, injecté dans la config générée pour le runtime |
| `no_path_check` | ❌ | `true` = l'humain autorise ce plugin à toucher hors du root (défaut `false`) |
| `subcommands` | ✅ | map nom de sous-commande → schéma d'args (voir ci-dessous) |

Schéma d'une sous-commande :

| Champ | Obligatoire | Règle |
|---|---|---|
| `flags` | ✅ | allowlist des flags acceptés (`--flag`, `--flag=valeur`, `-f`) |
| `path_flags` | ❌ | flags dont la **valeur est un chemin** (ex. `-v src:dst`) → chaque chemin passe par `resolve()` + sensibles |

Règles de parsing (fail-closed) :

- `serde_json` (déjà dépendance de la console, aucune nouvelle crate) avec
  `deny_unknown_fields` : tout champ/sous-champ non prévu = refus ;
- JSON invalide, champ manquant, `tool` dupliqué, `bin` hors du répertoire
  autorisé = **refus total au chargement** ;
- avant **chaque** exécution : relecture du fichier brut et comparaison sha256
  contre `--plugins-sha256` ; mismatch = `denied` (code 2), aucune exécution ;
- le manifeste vit **hors du root** (dépôt de l'agent) : l'agent ne peut pas le
  modifier.

Pourquoi JSON et pas YAML : pas de nouvelle dépendance, pas de footguns de
parser (ancres, coercition de types), et les schémas **par sous-commande**
sont naturellement imbriqués.

## Règles d'exécution (toutes appliquées par la console)

- **argv reconstruit, jamais de chaîne shell** : `[binaire épinglé] + [argv
  prefixe déclaré] + [args validés]` ; les args de l'agent sont passés tels
  quels en position finale, jamais réinterprétés par un shell ;
- **args validés contre le schéma de la sous-commande invoquée** : sous-commande
  et flags doivent être dans l'allowlist ; `path_flags` → `resolve()` +
  sensibles (sauf `no_path_check: true` déclaré par l'humain) ; valeurs des
  autres flags validées (type/pattern) ; le reste = `fail` avec la syntaxe
  acceptée ;
- environnement réduit (`PATH`, `LANG`, `HOME` hors du root), `cwd = root`,
  **stdin = null** (le stdin du processus appartient au protocole JSON) ;
- **sortie** : `stdout`/`stderr` du plugin passent par `CallerSink` (masquage
  des secrets, troncature à `max_output_bytes`) avant la réponse JSON ;
- **limites** : timeout par invocation (`run_with_timeout`, défaut 30 s) avec
  `kill()` du **groupe de processus entier** (un runtime de conteneurs forke —
  tuer le seul leader laisserait tourner le conteneur) ; `ulimit` sur le
  sous-processus (`-v` mémoire, `-t` CPU + grâce, `-f` = quota disque) ; limites
  `limits` du manifeste injectées dans la config du runtime (ex. `--memory`,
  `--pids-limit`) — deux couches, defense in depth ;
- **quota disque** : `DiskQuota` partagé entre tous les `FileSink` de
  l'invocation, comme pour les commandes whitelist ;
- **réseau** : `network: "none"` par défaut ; aucun pull d'image — les images
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
- évasion réseau → `network: "none"` par défaut, allowlist localhost sinon ;
- écriture disque hors bornes → confinement root + `DiskQuota` + `ulimit -f` ;
- contournement du manifeste par l'agent → manifeste hors du root, sha256
  vérifié à chaque exécution, args jamais réinterprétés.

## Phases proposées

1. Ce document, revu et validé (cette PR) ;
2. Implémentation : `plugins.rs` (parse JSON strict, sha256, schéma d'args par
   sous-commande, exécution) en réutilisant `TrustedRegistry` /
   `run_with_timeout` / `DiskQuota` ; `help` liste aussi les plugins déclarés ;
3. `trusted` reste en place (cas particulier « plugin shell ») ; migration
   éventuelle plus tard.
