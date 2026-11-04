# Spécification de la-console

**la-console** est une fausse console : un programme volontairement très limité
et très sûr, destiné à être piloté par un agent (IA) sans risque de sortie de
son périmètre. L'agent envoie des commandes en texte, la console répond en JSON.

Ce dossier est la spécification complète et autonome du projet : il peut être
copié tel quel dans le dépôt public du projet.

## Objectifs

1. **Périmètre absolu** : tout accès fichier est confiné sous un `root` donné.
   Aucune commande ne doit pouvoir lire/écrire hors de ce root, par quelque moyen
   que ce soit (`..`, symlinks, chemins absolus, encodages, etc.).
2. **Opérations limitées** : seules quelques commandes whitelistées sont
   disponibles, plus des commandes « trusted » définies et validées par un humain.
3. **Fail-closed** : au doute, refuser. Aucun « chemin rapide ».

## Principes directeurs

- La console n'est pas « une boucle qui exécute des commandes » : c'est un
  **pipeline de validation composable** appliqué à trois niveaux (entrée,
  chemins, sortie).
- Toute donnée qui entre, touche au disque, ou sort passe par une validation
  explicite.
- Aucun `unsafe` en v1.
- Pas de dépendance réseau dans la console.
- Une seule fonction de résolution de chemins, testée agressivement.

## Sommaire

| Document | Contenu |
|---|---|
| [protocol.md](protocol.md) | Interface externe : CLI, protocole ligne par ligne stdin/stdout, format JSON des réponses |
| [architecture.md](architecture.md) | Pipeline de validation à 3 niveaux, interface d'écriture unique (Sink) |
| [commands.md](commands.md) | Whitelist des commandes, commandes trusted, règles de parsing |
| [security.md](security.md) | Modèle de menaces, confinement (`resolve()`), fichiers sensibles, masquage des secrets, vecteurs d'évasion |
| [testing.md](testing.md) | Stratégie de test et outillage : fmt, clippy, tests unitaires, proptest, e2e, fuzzing, mutation testing, CI |
| [structure.md](structure.md) | Structure du dépôt et dépendances figées |
