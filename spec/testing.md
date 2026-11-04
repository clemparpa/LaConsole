# Stratégie de test et outillage

La console est une fonction entrée texte → réponse JSON : tout se teste sans
infrastructure. TDD systématique.

## Outillage local (boucle de dev)

| Check | Commande | Temps estimé |
|---|---|---|
| Format | `cargo fmt --all` (check : `-- --check`) | < 1 s |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 5–20 s incrémental |
| Tests unitaires | `cargo test -p la-console --lib` | 2–10 s |
| Tests d'intégration / e2e | `cargo test -p la-console --test '*'` | 5–30 s |

Gate « prêt pour PR » : fmt + clippy + `cargo test` complet ≈ 30 s à 1 min en
incrémental. `#![forbid(unsafe_code)]` dans `lib.rs` pour traduire « aucun
`unsafe` en v1 » en contrainte compilateur.

## Niveaux de test

- **Tests unitaires** (`#[test]` + `cargo test`), `tempfile` en dev-dependency.
- **Property-based (`proptest`)** sur les invariants de sécurité :
  - « pour tout chemin généré, `resolve()` ne renvoie jamais rien hors du root » ;
  - « pour toute entrée générée, le parser ne produit jamais de branche `trusted`
    dans un pipe, ni de sous-exécution ».
- **Tests d'évasion** dans `crates/la-console/tests/evasion.rs` : `..`,
  symlinks (avant/après canonicalize), chemins absolus, unicode, `//`, trailing
  slashes, NUL bytes, hardlinks.
- **Tests e2e** : spawn du vrai binaire
  (`env!("CARGO_BIN_EXE_la-console")`) avec `--root` sur un `tempfile`, envoi
  de lignes JSON sur stdin, assertion sur la réponse JSON
  `{ok, code, stdout, stderr, truncated}` — teste le contrat réel appelant ↔
  console. Scénarios de bout en bout (plusieurs commandes dans une même session,
  timeouts, troncature, masquage de secrets) au niveau workspace dans `tests/`.
- **Fuzzing (`cargo-fuzz`, libFuzzer coverage-guided)** sur deux cibles :
  `parse_input` (parser shell-words + opérateurs) et `resolve_path` (`resolve()`
  sur un root temporaire), entrées aléatoires (bytes, unicode, chemins
  bizarres) pour trouver crashes et évasions du root. Corpus seedé avec des cas
  réalistes + les vecteurs d'évasion connus. Les crashers trouvés sont committés
  comme tests de régression.
- **Mutation testing (`cargo mutants`)** sur `resolve.rs` et le parser : vérifie
  que les tests tuent vraiment les mutations (un mutant qui survit = un trou de
  couverture, potentiellement un vecteur d'évasion non détecté). `mutants.out/`
  est dans le `.gitignore`.
- **Couverture (`cargo llvm-cov`)** avec seuil sur les modules sécurité.
- **Licences / advisories (`cargo deny` + `cargo audit`)** et `cargo shear`
  (dépendances inutilisées) pour garder la surface minimale et auditable.
- **Vérification formelle (Kani/Prusti)** : envisagée en v2 pour prouver des
  invariants du parser ; pas en v1 car le risque principal vient de
  l'interaction avec le vrai filesystem.

## CI (GitHub Actions)

Deux niveaux, selon le coût :

- **Gate à chaque PR** (runners GitHub-hosted, rapides) : `cargo fmt --check`,
  `clippy -D warnings`, `cargo test` complet (matrice ubuntu + macOS, car
  `resolve()` dépend du filesystem), `llvm-cov` avec seuil, `deny`/`audit`,
  **fuzz borné ~5 min** sur parser + `resolve()`. Les tests d'évasion sont
  obligatoires avant merge.
- **Nightly** : fuzz long (30 min+) et `cargo mutants` avec seuil de score sur
  les mutants survivants. Sur un dépôt **public**, les runners hosted sont
  gratuits ; sur un dépôt **privé**, ces jobs chers peuvent tourner sur un
  runner self-hosted (jamais sur un dépôt public : risque d'exécution de code
  par des PR de forks).

## Vérification formelle

Kani/Prusti envisagé en v2 ; pas en v1 (voir ci-dessus).
