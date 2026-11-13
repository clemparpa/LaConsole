# Plugins (brouillon — discussion v2)

> Statut : **brouillon soumis à revue**. Aucune implémentation derrière pour
> l'instant. Objectif : un mécanisme de « plugins » (ex. piloter un navigateur,
> lancer des conteneurs OCI) où le **harnais de l'agent déclare la politique**
> (fichier revu par un humain, épinglé par sha256, comme `trusted.txt`) mais où
> **la console conserve la validation, le confinement, les limites et le kill
> de l'exécution** — jamais délégués au harnais.

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
  manifeste (ex. `browser`, `docker`) — la console le mappe vers le binaire
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
      "bin": "/opt/la-console-plugins/crun-run",
      "network": "none",
      "images": ["alpine@sha256:abc123…"],
      "limits": { "mem": "512m", "cpus": 1, "pids": 100 },
      "subcommands": {
        "run": {
          "flags": ["--rm", "--name", "-e", "-v", "--read-only"],
          "path_flags": ["-v"]
        },
        "ps": { "flags": ["-a"] }
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
| `network` | ✅ | `"none"` ou `"localhost"` (allowlist `localhost`/`127.0.0.1`/`::1`, comme `http` v1). En mode **user**, seul `"none"` est accepté en v1 |
| `images` | ❌ | allowlist d'images épinglées par digest (`name@sha256:…`) ; tout le reste = `denied` |
| `url_hosts` | ❌ | allowlist de hosts pour un arg URL (ex. plugin navigateur) ; validation par la console avant spawn |
| `limits` | ❌ | objet `{ "mem": "512m", "cpus": 1, "pids": 100 }`, injecté dans le spec/config généré(e) |
| `no_path_check` | ❌ | `true` = l'humain autorise ce plugin à toucher hors du root (défaut `false`) |
| `subcommands` | ✅ | map nom de sous-commande → schéma d'args (voir ci-dessous) |

Schéma d'une sous-commande :

| Champ | Obligatoire | Règle |
|---|---|---|
| `flags` | ✅ | allowlist des flags acceptés (`--flag`, `--flag=valeur`, `-f`) |
| `path_flags` | ❌ | flags dont la **valeur est un chemin** (ex. `-v src:dst`) → chaque chemin passe par `resolve()` + sensibles |
| `url_arg` | ❌ | position de l'arg URL, validé contre `url_hosts` |

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

## Abstraction `Sandbox` : un seul point de confinement, choisi au démarrage

Plus de distinction `user`/`server` exposée : au démarrage, la console **se
confine elle-même** avec le backend le plus fort disponible sur l'OS, puis
spawne plugins et `trusted` à travers la même abstraction. Le reste du code ne
sait pas quel backend tourne ; la distinction user/server devient un détail
interne (quel backend a été retenu).

Ordre de sélection (auto) :

1. **Linux** : cage userns+chroot (`unshare --user --map-root-user --mount
   --root <root>`, re-exec avec marqueur anti-boucle) si
   `kernel.unprivileged_userns_clone=1` — backend le plus fort, celui des
   déploiements serveur (hors du root, les chemins n'existent pas pour le
   processus) ;
2. **Linux** : Landlock appliqué in-process au début de `main()` (hérité par
   les threads de commandes et les processus fils) ;
3. **macOS** : re-exec via `sandbox-exec -p '<profil généré>'` ;
4. aucun backend → **refus de démarrer (exit 2), fail-closed**, sauf flag
   explicite `--allow-no-sandbox` (opt-out documenté, debug local uniquement).

```rust
trait Sandbox {
    /// Confine le processus console lui-même (appelé au démarrage).
    fn confine_self(root: &Path, policy: &Policy) -> io::Result<SandboxBackend>;
    /// Spawn un sous-processus (plugin/trusted) — hérite du confinement courant.
    fn spawn(&self, cmd: &mut Command, policy: &Policy) -> io::Result<Child>;
}
```

La cage garde tout son sens même avec Landlock : confinement **structurel**
(mount namespace + chroot + userns) vs simple contrôle d'accès (Landlock,
Seatbelt) — deux forces complémentaires, la cage restant le backstop ultime
contre un bug de logique dans `resolve()`.

**Fail-closed absolu** : aucun backend applicable → exit 2 au démarrage, sauf
`--allow-no-sandbox`. **Aucun privilège requis nulle part** (jamais de root) :

| Backend | Prérequis | Privilège |
|---|---|---|
| `Cage` (serveur) | Linux, `kernel.unprivileged_userns_clone=1` (sysctl ; sinon mode serveur refusé, exit 2) | aucun (userns non privilégié) |
| `Seatbelt` (macOS user) | `sandbox-exec` présent (livré avec macOS) | aucun — applique le profil à son propre fils |
| `Landlock` (Linux user) | noyau ≥ 5.13 (réseau : ABI v4, noyau ≥ 6.7) ; syscalls non bloqués (ex. pas sous seccomp restrictif) | aucun — auto-restriction via `no_new_privs` |
| `Userns` (Linux user) | comme `Cage`, par invocation | aucun si sysctl OK, sinon indisponible → `denied` |

Détails des backends :

- **Seatbelt** : profil généré par la console à partir de `--root` et de la
  politique réseau, deny-by-default :
  `(version 1)(deny default)(allow file-read* (subpath "<root>"))(allow file-write* (subpath "<root>"))(deny network*)`.
  Les règles réseau de Seatbelt sont all-or-nothing (pas de « localhost
  only ») → en mode user, `network` des plugins = `"none"` uniquement.
- **Landlock** : règles FS = accès restreint au root (lecture/écriture), réseau
  selon `network` (`"none"` = aucun droit `BIND_TCP`/`CONNECT_TCP` quand l'ABI
  le permet). Les restrictions sont **héritées par fork/exec** : même un
  processus détaché (`setsid`) reste confiné.
- **Cage** : appliquée une fois au démarrage (re-exec de toute la console dans
  `unshare --user --map-root-user --mount --root <root>`) ; les spawns suivants
  héritent du confinement, le binaire du plugin étant stagé dans la cage en
  read-only (les flags `--sandbox-busybox` / `--sandbox-tools-dir` ne
  s'appliquent qu'à ce backend). Avec les autres backends, le binaire du
  plugin vit sur le host au chemin déclaré et c'est le wrapper qui confine le
  processus à chaque spawn.

## Règles d'exécution (toutes appliquées par la console)

- **argv reconstruit, jamais de chaîne shell** : `[binaire épinglé] + [argv
  prefixe déclaré] + [args validés]` ; les args de l'agent sont passés tels
  quels en position finale, jamais réinterprétés par un shell ;
- **args validés contre le schéma de la sous-commande invoquée** : sous-commande
  et flags dans l'allowlist ; `path_flags` → `resolve()` + sensibles (sauf
  `no_path_check: true`) ; `url_arg` → host dans `url_hosts` ; images → digest
  dans `images` ; le reste = `fail` avec la syntaxe acceptée ;
- environnement réduit (`PATH`, `LANG`, `HOME` hors du root), `cwd = root`,
  **stdin = null** (le stdin du processus appartient au protocole JSON) ;
- **spawn via `Sandbox`** (section précédente) avec la politique du manifeste ;
- **sortie** : `stdout`/`stderr` du plugin passent par `CallerSink` (masquage
  des secrets, troncature à `max_output_bytes`) avant la réponse JSON ;
- **limites** : timeout par invocation (`run_with_timeout`, défaut 30 s) avec
  `kill()` du **groupe de processus entier** + cleanup du cgroup quand le
  plugin est un runtime de conteneurs (tuer le seul leader laisserait tourner
  le conteneur) ; `ulimit` sur le sous-processus (`-v` mémoire, `-t` CPU +
  grâce, `-f` = quota disque) ; `limits` du manifeste injectées dans le spec
  OCI/config généré(e) (`mem`, `cpus`, `pids`, `no-new-privileges`, seccomp par
  défaut, rootfs read-only si demandé) — deux couches, defense in depth ;
- **quota disque** : `DiskQuota` partagé entre tous les `FileSink` de
  l'invocation, comme pour les commandes whitelist ;
- **réseau** : `"none"` par défaut ; aucun pull d'image — les images doivent
  être pré-stagées et épinglées par digest ;
- **pipes** : ❌ v1, un plugin ne participe à aucun pipe (comme `trusted`) ;
  `;`/`&&` autorisé uniquement si les deux côtés sont whitelist ou plugin ;
  **redirections de sortie** `>`/`>>` vers un chemin du root, via `FileSink`
  validé (resolve + sensibles + bornes) avant ouverture.

## Deux couches de défense (rappel)

| Couche | Protège contre |
|---|---|
| Validation d'entrée (`resolve()`, schéma, allowlists, sha256) | **l'agent** (entrée non fiable) |
| Bac à sable OS (`Sandbox`) | **le processus plugin lui-même** compromis/malveillant (ex. 0-day navigateur) : lecture/écriture hors du root impossible, même pour un fils détaché |

## Exemples d'usage

- **`browser open https://example.com --timeout 10`** (navigateur headless épinglé,
  `url_hosts: ["example.com"]`) : le DOM revient en `stdout` masqué/tronqué.
  Menace couverte : page malveillante + 0-day Chromium → le processus compromis
  ne peut lire que le root, pas `~/.ssh` ni les credentials du host.
- **`docker run --rm -v /data:/work alpine@sha256:abc… cat /work/f.txt`** :
  image épinglée par digest, `-v` `resolve()`-é sous le root, spec OCI généré
  par la console (`network: none`, limites, caps droppées), runtime spawné via
  `Sandbox`, kill du groupe + cgroup au timeout.

## Répartition des responsabilités

| Rôle | Harnais de l'agent | la-console |
|---|---|---|
| Déclare la politique (manifeste, sha256, revue humaine) | ✅ | lit + re-vérifie |
| Valide les args (resolve, sensibles, schéma) | ❌ | ✅ |
| Confinement (`Sandbox`: cage/Seatbelt/Landlock, fail-closed) | ❌ | ✅ |
| Limites (timeout, mémoire, disque, sortie) et kill | ❌ | ✅ |
| Exécution du binaire | ❌ | ✅ (sous-processus, jamais in-process) |
| Journalisation (op, plugin, sha256, code/kind dans la réponse) | ❌ | ✅ |

Règle : la console doit rester **fail-closed même si le harnais ment** sur le
manifeste — d'où la re-vérification sha256 côté console avant chaque exécution.

## Menaces couvertes (rappel)

- plugin épinglé par erreur/malveillance → revue humaine + sha256 + re-vérif ;
- processus plugin compromis (0-day) → `Sandbox` : FS = root seul, réseau selon
  politique, limites ; fork bomb/fuite → limite `pids` + kill du groupe ;
- évasion réseau → `network: "none"` par défaut ; images pré-stagées uniquement ;
- écriture disque hors bornes → confinement root + `DiskQuota` + `ulimit -f` ;
- contournement du manifeste par l'agent → manifeste hors du root, sha256
  vérifié à chaque exécution, args jamais réinterprétés.

## Phases proposées

1. Ce document, revu et validé (cette PR) ;
2. Module `sandbox.rs` : trait `Sandbox` unifié (`confine_self` au démarrage +
   `spawn`), sélection auto du backend (cage / Landlock / Seatbelt),
   fail-closed par défaut + `--allow-no-sandbox` ; tests par plateforme ;
3. `plugins.rs` : parse JSON strict, sha256, schéma d'args par sous-commande,
   spawn via `Sandbox`, exécution — en réutilisant `TrustedRegistry` /
   `run_with_timeout` / `DiskQuota` ; `help` liste aussi les plugins déclarés ;
4. `trusted` reste en place (cas particulier « plugin shell ») ; migration
   éventuelle plus tard.
