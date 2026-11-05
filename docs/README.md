# la-console — vue d'ensemble

**la-console** est une fausse console, volontairement très limitée et très sûre,
destinée à être pilotée par un agent (IA) sans risque de sortie de son périmètre.
L'agent envoie des commandes en texte — une ligne JSON par commande sur stdin —
et la console répond en JSON, une ligne par réponse sur stdout.

## Principes

- **Périmètre absolu** : tout accès fichier est confiné sous un répertoire `root` donné.
- **Opérations limitées** : seules quelques commandes whitelistées sont disponibles, plus des commandes « trusted » validées par un humain.
- **Fail-closed** : au doute, refuser. Aucun `unsafe` en v1.

## Lancement et protocole

```
la-console --root <chemin>
```

- Entrée : `{"op": "exec", "cmd": "ls src"}`
- Sortie : `{"ok": true, "code": 0, "stdout": "...", "stderr": "", "truncated": false}`
- Refus : `{"ok": false, "code": 2, "stdout": "", "stderr": "denied: ...", "truncated": false}`

La console est stateless : chaque commande repart du `root`.

## Commandes disponibles

Whitelist v1 en cours de déploiement (une commande par PR, voir
[ROADMAP.md](../ROADMAP.md)) : `cat <path>` est disponible. Toute autre commande
est refusée (`denied: unknown command`, code 2).

## Documents de référence

- [spec/](../spec/README.md) — spécification complète : protocole, architecture, commandes, sécurité, stratégie de test, structure du dépôt ;
- [ROADMAP.md](../ROADMAP.md) — feuille de route : étapes 0 à 7, une PR indépendante et testable par étape.

## Développement

Gate « prêt pour PR » : `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
