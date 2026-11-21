# Intégration agent & commandes autorisées (brouillon — discussion v2)

> Statut : **brouillon soumis à revue**. Objectif : un **binaire Rust unique**,
> appelable à la volée, qu'on branche facilement sur les agents existants
> (**pi**, **mistral-vibe**, etc.) — **prioritairement sur macOS**, Linux en
> second.

## Objectif

la-console est un **sous-processus** de l'agent : une ligne JSON par requête sur
stdin (`{"op": "exec", "cmd": "ls src"}`), une ligne JSON de réponse sur stdout
(`{ok, code, kind?, stdout, stderr, truncated}`) — exactement le pattern d'appel
d'outils de pi / mistral-vibe. Un thin wrapper par agent suffit (pas besoin de
MCP pour commencer).

Deux familles de commandes :

1. **Commandes de base**, écrites en Rust, sécurisées — ✅ livrées en v1 :
   `cat`, `ls`, `echo`, `grep`, `sub`, `sed`, `http`, `help`, toutes in-process
   (`#![forbid(unsafe_code)]`), confinées par `resolve()` + sensibles + sinks +
   bornes ;
2. **Commandes autorisées par l'utilisateur**, inscrites dans le repo de l'agent
   (revue humaine en PR, épinglées sha256 comme `trusted.txt`), et **composables
   avec les commandes de base** — ex. `trusted run-tests | grep ERROR` pour lire
   des logs illisibles. `trusted` existe (v1) avec `;`/`&&` ; **le pipe
   `trusted → whitelist` est livré 🚧 (cette PR, tête de pipe uniquement,
   jamais l'inverse)** : stdin du shell trusted toujours `null`, sortie bornée
   via `PipeSink` (troncature) puis `CallerSink` en sortie finale.

Au-delà de `trusted` (shell), un **plugin** = binaire épinglé par l'utilisateur,
déclaré dans `plugins.json`, invoqué avec la **syntaxe standard de l'outil**
pour ne pas dépayser le LLM.

## Hors scope v1

- ❌ Windows (WSL2 « à voir » plus tard) ;
- ❌ VM / conteneurs OCI en v1 (reportés) — le sandbox OS natif suffit sur
  macOS/Linux.

## Manifeste `plugins.json`

Fichier JSON du dépôt de l'agent, lu via `--plugins-file <path>`, épinglé via
`--plugins-sha256 <hex>` (miroir de `--trusted-file`). Schéma strict
(`serde_json` déjà dépendance, `deny_unknown_fields`, fail-closed), schémas
d'args **par sous-commande** :

```json
{
  "plugins": [
    {
      "tool": "browser",
      "bin": "/opt/la-console-plugins/chromium-headless",
      "network": "proxy",
      "url_hosts": ["example.com"],
      "limits": { "mem": "1g", "cpus": 2, "pids": 200 },
      "subcommands": {
        "open": { "flags": ["--timeout"], "url_arg": 1 }
      }
    }
  ]
}
```

| Champ | Règle |
|---|---|
| `tool` | nom usuel de l'outil (`^[A-Za-z_][A-Za-z0-9_-]*$`), doublon = refus total |
| `bin` | chemin absolu du binaire épinglé, répertoire autorisé |
| `network` | `"none"` (défaut) / `"proxy"` (proxy localhost + allowlist de domaines) |
| `images`, `url_hosts` | allowlists d'images (digest) / de hosts d'URL, validées par la console avant spawn |
| `limits` | `{ mem, cpus, pids }` injectées dans la config générée + rlimits |
| `no_path_check` | `true` si l'humain autorise hors-root (défaut `false`) |
| `subcommands` | map sous-commande → `{ flags: [...], path_flags: [...], url_arg: n }` |

- `path_flags` → chaque chemin passe par `resolve()` + sensibles ;
- avant **chaque** exécution : relecture du manifeste brut + comparaison sha256 ;
  mismatch = `denied`, aucune exécution ;
- manifeste **hors du root** : l'agent ne peut pas le modifier.

## Manifeste TOML des commandes trusted (`trusted.toml`, v2)

Remplace le format ligne `trusted.txt` (v1) par un **TOML strict**, toujours
épinglé par `--trusted-sha256` et re-vérifié avant **chaque** exécution :

```toml
# trusted.toml — revu en PR par l'humain, hors du root de l'agent
[commands.build]
command = "cargo build --release"

[commands.test-e2e]
command = "npm run test:e2e"
no_path_check = false                 # flag optionnel (défaut false)
timeout_secs = 600                    # optionnel, défaut = --timeout-secs global
max_write_bytes = 256 * 1024 * 1024   # quota d'écriture disque de la commande
mem_bytes = 4 * 1024 * 1024 * 1024    # optionnel, appliqué par le backend OS
network = "none"                      # none (défaut) | loopback | proxy (allowlist de domaines)
```

| Champ | Règle |
|---|---|
| `command` | obligatoire ; passé tel quel au shell du backend, complété par `"$@"` (args jamais réinterprétés) |
| `no_path_check` | bool, défaut `false` ; sinon les args-chemins passent par `resolve()` + sensibles |
| `timeout_secs` | défaut = limite globale ; kill du processus (et du groupe) à la deadline |
| `max_write_bytes` | **quantité d'écriture disque** de la commande, appliquée par le backend OS (FS deny hors répertoires déclarés) |
| `mem_bytes`, `cpus` | appliqués par le backend OS (seatbelt/landlock/WSL2) — **plus par `ulimit`** (voir [platforms.md](platforms.md) §4) |
| `network` | `none` = deny réseau ; `loopback` ; `proxy` = proxy localhost + allowlist de domaines |

- Schéma strict (`deny_unknown_fields`, crate TOML épinglée, fail-closed) ;
  nom `^[A-Za-z_][A-Za-z0-9_-]*$`, doublon = refus total.
- Détection par extension : `.toml` = v2 ; `.txt` = format v1 (compat lecture
  le temps de la migration).
- `help` liste les entrées avec leurs limites.

## Confinement : abstraction `Sandbox`, backends OS natifs (priorité macOS)

Un seul trait, le reste du code ne sait pas quel OS tourne derrière. Chaque
sous-processus (plugin/trusted) est spawné via un **helper arg0** (notre binaire
re-execqué : `la-console __sandbox_helper <profil.json> -- <cmd…>`) qui applique
le confinement **dans l'enfant juste avant exec** — jamais dans le harness
(lui-même, qui doit garder accès aux manifestes et au stdio) :

- **macOS (prioritaire)** : profil SBPL généré + `sandbox-exec -p` (API
  publique, zéro FFI/`unsafe` chez nous ; même approche que Codex/Chrome).
  Réseau : `deny network*`, ou loopback seul vers le proxy à allowlist
  (pattern Claude Code) ;
- **Linux** : crate `landlock` officielle (+ `seccompiler` optionnel) dans le
  helper ; namespaces via userns si le sysctl l'autorise ; le mode serveur
  garde la cage userns+chroot (backend le plus fort) ;
- **Windows** : la console entière tourne dans une **WSL2** (VM utilitaire) —
  même patron que le mode serveur Linux ; ponts host (interop `.exe`,
  `/mnt/c`, réseau NAT, socket docker) désactivés sauf déclaration explicite ;
  cf. [platforms.md](platforms.md) §3 ;
- crate `nono` (Apache-2.0) comme alternative cross-platform unique dans le
  helper, à auditer/épingler une fois (0.x).

**Décision v2 : les `ulimit` du shell trusted sont retirés** (non portables —
`ulimit -v` absent sur macOS — et `-v` borne l'address space virtuel, pas la
RSS réelle). Les limites par entrée du manifeste TOML (`timeout_secs`,
`max_write_bytes`, `mem_bytes`, `cpus`, `network`) sont appliquées par le
backend OS ; le timeout wall-clock + kill reste appliqué par la console
elle-même. Voir [platforms.md](platforms.md) §4.

**Fail-closed par spawn** : backend inapplicable (vieux noyau, sandbox-exec
absent…) → `denied`, jamais de mode dégradé. **Aucun privilège requis** (jamais
de root). La cage userns+chroot du mode serveur reste le backend le plus fort
pour les déploiements serveur (hors du root, les chemins n'existent pas).

Règles d'exécution communes : argv reconstruit sans shell, args validés contre
le schéma de la sous-commande, env réduit, `cwd = root`, stdin null, sortie via
`CallerSink` (masquage + troncature), timeout avec kill du **groupe de
processus**, quota disque `DiskQuota`, pipes ❌ en v1 pour les plugins (le pipe
`trusted → whitelist` reste le delta composabilité, au-dessus).

## Répartition des responsabilités

Le **harnais déclare la politique** (manifeste, sha256, revue humaine) ; la
**console applique tout** : validation des args, confinement, limites, kill,
masquage — jamais délégué au harnais, fail-closed même si le harnais ment.

## Phases proposées

1. Ce document, revu et validé (PR #29) ;
2. ✅ (cette PR) Le delta composabilité : pipe `trusted → whitelist` borné (tête de pipe uniquement) ;
3. `sandbox.rs` (helper arg0, backends Seatbelt/Landlock, fail-closed) puis
   `plugins.rs` (manifeste JSON strict, spawn sandboxé) ; `help` liste les
   plugins déclarés ;
4. Manifeste `trusted.toml` (section ci-dessus) + retrait des `ulimit`,
   limites par entrée appliquées par le backend (cf. [platforms.md](platforms.md) §4) ;
5. Couche d'abstraction plateforme `platform.rs` (macOS/Windows, plus de
   spécifique Linux) puis backends : seatbelt (macOS), WSL2 (Windows) ;
6. Commandes `git` whitelist read-only (cf. [commands.md](commands.md)).
