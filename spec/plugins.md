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
   (revue humaine en PR, épinglées sha256 comme `trusted.toml`), et **composables
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

> Note (décision 2026-11-27) : les plugins sont hors v2 (zéro code, backlog) ;
> quand ils seront livrés (v3+), `network: "proxy"` et `limits` suivront le
> même descoping que `trusted.toml` : `none`/`loopback` d'abord, le reste
> `denied` fail-closed tant que non livré (plan
> [sandbox-backend.md](sandbox-backend.md)).

- `path_flags` → chaque chemin passe par `resolve()` + sensibles ;
- avant **chaque** exécution : relecture du manifeste brut + comparaison sha256 ;
  mismatch = `denied`, aucune exécution ;
- manifeste **hors du root** : l'agent ne peut pas le modifier.

## Manifeste TOML des commandes trusted (`trusted.toml`, v2) — ✅ livré

Format **TOML strict**, toujours épinglé par `--trusted-sha256` et re-vérifié
avant **chaque** exécution. Détection par extension : `.toml` uniquement —
le format v1 `trusted.txt` a été retiré, toute autre extension = refus
fail-closed.

> Statut : `command`, `no_path_check` et `timeout_secs` sont appliqués par la
> console dès maintenant (timeout wall-clock + kill du groupe de processus).
> `network = "none"` / `"loopback"` seront appliqués par le backend OS (crate
> `nono`, plan [sandbox-backend.md](sandbox-backend.md)) ; `network` non
> déclaré = comportement v1 (réseau joignable) jusqu'à l'arrivée du backend,
> puis défaut **`none`**. `network = "proxy"`, `max_write_bytes`, `mem_bytes`,
> `cpus` restent validés au parse mais **refusés `denied` à l'exécution**
> (fail-closed, reportés à une v3 — décision 2026-11-27, cf.
> [platforms.md](platforms.md) §4).

```toml
# trusted.toml — revu en PR par l'humain, hors du root de l'agent
[commands.build]
command = "cargo build --release"
description = "Compile le projet en release"

[commands.build.flags]
"--locked" = { description = "Utilise le Cargo.lock figé" }
"-j" = {}

[commands.test-e2e]
command = "npm run test:e2e"
no_path_check = false                 # optionnel (défaut false)
timeout_secs = 600                    # optionnel, défaut = --timeout-secs global (console)
max_write_bytes = 268435456           # reporté v3 : refusé `denied` tant que non livré
mem_bytes = 4294967296                # idem (v3)
network = "none"                      # none (défaut) | loopback : appliqués par le backend nono en v2 ; "proxy" = v3, refusé `denied`
```

| Champ | Règle |
|---|---|
| `command` | obligatoire ; passé tel quel au shell du backend, complété par `"$@"` (args jamais réinterprétés) |
| `description` | texte libre rendu par `help` (recommandé pour la revue humaine) |
| `flags` | table `"<flag>" = { description = "..." }` : allowlist des arguments `-...` acceptés (`-v`, `--release`, `--jobs=4` ; nom validé `^-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*(=...)?$`) ; tout `-...` non déclaré = `denied` fail-closed, même avec `no_path_check` ; les flags ne passent pas par `resolve()` |
| `no_path_check` | bool, défaut `false` ; sinon les args-chemins passent par `resolve()` + sensibles |
| `timeout_secs` | défaut = limite globale ; kill du processus (et du groupe) à la deadline |
| `max_write_bytes` | **quantité d'écriture disque** de la commande — reporté v3 (décision 2026-11-27) : refusé `denied` fail-closed tant que non livré |
| `mem_bytes`, `cpus` | idem — reportés v3 (rlimits `nix`/cgroups, non couverts par nono hors cgroups Linux) ; **plus par `ulimit`** (voir [platforms.md](platforms.md) §4) |
| `network` | `none` (défaut dès le backend) / `loopback` : appliqués par le backend nono en v2 (plan [sandbox-backend.md](sandbox-backend.md)) ; `proxy` = proxy localhost + allowlist de domaines → reporté v3, refusé `denied` |

- Schéma strict (`deny_unknown_fields`, crate `toml` épinglée en direct,
  fail-closed) ; nom `^[A-Za-z_][A-Za-z0-9_-]*$`, doublon = refus total (le
  parseur TOML refuse déjà les tables dupliquées).
- Détection par extension : `.toml` seul format accepté (le `.txt` v1 est
  retiré).
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
- **Linux** : landlock (noyau ≥ 5.13) dans le helper, via la crate `nono` ;
- **Windows** : la console entière tourne dans une **WSL2** (VM utilitaire) —
  même patron que le mode serveur Linux ; ponts host (interop `.exe`,
  `/mnt/c`, réseau NAT, socket docker) désactivés sauf déclaration explicite ;
  cf. [platforms.md](platforms.md) §3 ;
- ✅ **décision actée (2026-11-24)** : crate `nono` (Apache-2.0) retenue comme
  backend de confinement unique (Landlock/Seatbelt/WSL2), via la couche
  d'abstraction `src/sandbox_backend.rs` — voir [platforms.md](platforms.md) §3.
  Version épinglée, auditée avant chaque bump ; un breaking change ne touche que
  ce module.

**✅ Décision v2 livrée : les `ulimit` du shell trusted sont retirés** (non portables —
`ulimit -v` absent sur macOS — et `-v` borne l'address space virtuel, pas la
RSS réelle). Le timeout wall-clock + kill reste appliqué par la console
elle-même. **Scope backend (décision 2026-11-27)** : en v2, seuls
`network = "none"`/`"loopback"` sont appliqués par le backend OS (crate
`nono`, plan [sandbox-backend.md](sandbox-backend.md)) ; `network = "proxy"`,
`max_write_bytes`, `mem_bytes`, `cpus` restent refusés `denied` fail-closed
(reportés v3). Voir [platforms.md](platforms.md) §4.

**Fail-closed par spawn** : backend inapplicable (vieux noyau, sandbox-exec
absent…) → `denied`, jamais de mode dégradé. **Aucun privilège requis** (jamais
de root).

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
3. `src/sandbox_backend.rs` (helper arg0 `__sandbox_helper`, backend `nono`,
   fail-closed) puis `plugins.rs` (manifeste JSON strict, spawn sandboxé) ;
   `help` liste les plugins déclarés ;
4. ✅ Manifeste `trusted.toml` + retrait des `ulimit` livrés : `timeout_secs`
   et `no_path_check` appliqués par la console (kill du groupe de processus) ;
   `network = "none"`/`"loopback"` seront appliqués par le backend nono
   (phase 3, plan [sandbox-backend.md](sandbox-backend.md)) ;
   `network = "proxy"`, `max_write_bytes`/`mem_bytes`/`cpus` restent refusés
   fail-closed (reportés v3, décision 2026-11-27) ;
5. Couche d'abstraction plateforme `platform.rs` (macOS/Windows, plus de
   spécifique Linux) puis backends : seatbelt (macOS), WSL2 (Windows) ;
6. Commandes `git` whitelist read-only (cf. [commands.md](commands.md)).
