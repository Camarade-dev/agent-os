# Admissible Paired Long-Running Runner
## Governing Implementation Plan — V0.1

## 0. Statut du document

Ce document gouverne la prochaine phase d’implémentation d’Admissible.

Il transforme l’audit de readiness du système actuel en une séquence de travaux bornée, vérifiable et orientée vers un nouvel experiment end-to-end comparatif :

- **Condition A** : modèle direct, instrumenté mais non gouverné par Admissible ;
- **Condition B** : même modèle, mêmes outils et mêmes conditions, avec Admissible entre la proposition d’action et son exécution.

Ce document n’autorise pas :

- l’exécution du benchmark réel ;
- le contact d’un fournisseur de modèle ;
- la création d’une autorisation propriétaire réelle ;
- la création d’un nouveau mint de production ;
- la réutilisation de la préparation V14 ;
- la réutilisation d’une identité V15, V16, V17 ou V18 ;
- la relance d’une action one-shot consommée ;
- le refresh du witness de production ;
- l’invention d’un « V19 » ;
- une réécriture générale d’Admissible sans justification requirement par requirement.

Le statut actuel est :

> **READY FOR IMPLEMENTATION PLANNING AND BOUNDED IMPLEMENTATION**  
> **NOT READY FOR EXPERIMENT EXECUTION**

---

# 1. Objectif gouvernant

Construire un seul système comparatif capable d’exécuter une tâche logicielle longue sous deux modes qui ne diffèrent que par l’intervention causale d’Admissible.

Le système cible doit matérialiser :

> The model proposes; Admissible authorizes.

Le modèle produit des propositions d’action canoniques.

Un substrat partagé observe ces propositions et leurs résultats.

En Condition A, les propositions admissibles au niveau expérimental sont exécutées directement, sans décision Admissible.

En Condition B, les mêmes propositions passent par un gate Admissible préventif avant toute mutation.

Le propriétaire n’autorise pas manuellement chaque commande. Il autorise une délégation précisément bornée pour un run donné. À l’intérieur de cette enveloppe, Admissible peut autoriser ou refuser les effets individuels.

Le résultat final doit permettre à un tiers de reconstruire :

1. ce que le modèle a reçu ;
2. ce qu’il a proposé ;
3. ce qui a été autorisé ;
4. ce qui a réellement été exécuté ;
5. ce qui a changé ;
6. ce qui a été refusé ;
7. pourquoi le résultat a été accepté ou rejeté ;
8. quelles différences ont existé entre A et B.

---

# 2. Décisions d’architecture figées

Ces décisions ne peuvent être modifiées silencieusement pendant l’implémentation.

Toute modification exige un ADR explicite, une analyse d’impact sur l’équité expérimentale et une révision de la matrice de requirements.

## ADR-001 — Un seul transport modèle

Les Conditions A et B doivent utiliser :

- le même exécutable ;
- le même digest d’exécutable ;
- le même protocole de transport ;
- le même modèle ;
- la même configuration de raisonnement ;
- les mêmes règles de continuation ;
- le même mécanisme de réception des appels d’outils.

Le transport de référence à généraliser est l’architecture Codex app-server du canary fort.

Le produit Cursor utilisant `--force --trust` ne constitue pas le chemin cible de cette campagne.

Il peut rester dans le dépôt, mais il ne doit pas être utilisé implicitement ou présenté comme l’implémentation de la Condition B.

## ADR-002 — Une seule grammaire d’outils

Les deux conditions reçoivent exactement la même grammaire d’outils.

La première version doit rester petite et explicitement définie :

- `list_files`
- `read_file`
- `write_file`
- `run_command`

Des opérations supplémentaires peuvent être introduites uniquement si la tâche benchmark les exige et si elles sont identiques dans A et B.

Chaque outil doit avoir :

- un schéma canonique ;
- une validation structurale ;
- une portée ;
- un type d’effet ;
- une représentation stable ;
- un résultat canonique ;
- un identifiant déterministe ou non ambigu.

## ADR-003 — Un bus canonique de propositions d’action

Toute demande d’outil du modèle doit être convertie en un objet canonique avant exécution.

Cet objet doit au minimum contenir :

- run ID ;
- condition ;
- session ID ;
- turn ID ;
- proposal ID ;
- tool name ;
- arguments canoniques ;
- working root ;
- scope identity ;
- causal predecessor ;
- timestamp monotonic et wall-clock ;
- transport identity ;
- prompt identity ;
- model identity ;
- tool-grammar identity.

Aucune mutation ne peut précéder la publication durable ou la réservation durable de cette proposition.

## ADR-004 — Un substrat partagé d’observation et d’effets

A et B doivent utiliser le même composant physique pour :

- recevoir une proposition ;
- valider son schéma ;
- enregistrer la proposition ;
- lancer l’effet ;
- superviser le processus ;
- collecter stdout et stderr ;
- enregistrer le code de sortie ;
- mesurer la durée ;
- observer les mutations ;
- produire le receipt ;
- mettre à jour l’état du run.

La différence doit être localisée dans une interface unique :

```text
proposal
   ↓
mode decision
   ├── DIRECT: execute
   └── GOVERNED: admissible_decision → execute or refuse
```

Le mode direct ne doit pas appeler le gate Admissible.

Le mode gouverné ne doit pas pouvoir contourner le gate.

## ADR-005 — Observation commune, gouvernance additionnelle

Les preuves communes doivent avoir le même schéma en A et B.

La Condition B peut produire des preuves supplémentaires :

- décision Admissible ;
- règle appliquée ;
- autorisation de délégation ;
- refus ;
- invariant ;
- receipt d’autorité.

Ces preuves supplémentaires ne doivent pas modifier les observations de base.

## ADR-006 — Même environnement expérimental

A et B doivent fonctionner dans deux environnements distincts mais créés à partir du même snapshot immuable.

Ils doivent partager les mêmes politiques de sécurité expérimentale :

- même vue initiale du dépôt ;
- même dépendance disponible ;
- même absence ou présence de réseau ;
- même limite filesystem ;
- même limite de processus ;
- même timeout ;
- même limite de sortie ;
- même environnement ;
- même executable PATH ;
- mêmes caches initialisés ou vidés ;
- même politique Git.

La Condition A n’est pas une exécution libre sur la machine hôte. Elle est directe relativement à Admissible, pas relativement aux limites de sécurité du benchmark.

## ADR-007 — Autorisation propriétaire d’une enveloppe

La Condition B utilise le broker propriétaire privilégié.

Le propriétaire autorise une enveloppe exacte comprenant au minimum :

- benchmark ID ;
- run ID ;
- condition ;
- prompt fingerprint ;
- initial-state fingerprint ;
- model identity ;
- executable identity ;
- transport identity ;
- tool-grammar identity ;
- policy identity ;
- evaluator identity ;
- workspace identity ;
- filesystem scope ;
- command authority ;
- network authority ;
- Git authority ;
- dependency authority ;
- time budget ;
- token ou cost budget si disponible ;
- process budget ;
- proposal budget ;
- continuation budget ;
- retry budget ;
- human-intervention policy ;
- expiration ;
- cancellation semantics ;
- terminal conditions.

Le modèle ne peut ni créer, ni modifier, ni prolonger cette autorisation.

## ADR-008 — Autorisation de délégation, pas micro-approbation humaine

Après autorisation du run, Admissible peut prendre de manière autonome les décisions d’effet à l’intérieur de l’enveloppe.

Les refus et autorisations doivent être durables et explicables.

Une action hors enveloppe doit être refusée fail-closed.

Le système ne doit jamais demander à l’opérateur de reconstruire manuellement une autorité implicite.

## ADR-009 — État durable multi-session

Le run ne peut pas dépendre uniquement d’un processus vivant ou d’un état Python en mémoire.

L’état durable doit supporter :

```text
CREATED
PREPARED
READY_FOR_OWNER_REVIEW
OWNER_AUTHORIZED
RUNNING
PAUSED_FOR_CONTINUATION
PAUSED_BY_OPERATOR
BUDGET_EXHAUSTED
REFUSED
FAILED
CANCELLED
MODEL_COMPLETED
EVALUATING
ACCEPTED
REJECTED
ARCHIVED
```

Toutes les transitions doivent être :

- explicites ;
- validées ;
- durables ;
- monotones sauf transitions de reprise autorisées ;
- accompagnées de preuves ;
- résistantes au redémarrage ;
- résistantes au replay.

## ADR-010 — Évaluateur commun et indépendant

A et B doivent être évaluées par le même évaluateur, après arrêt du modèle.

L’évaluateur ne doit pas faire confiance :

- au texte final du modèle ;
- à son affirmation de réussite ;
- au code de sortie seul ;
- à un test choisi uniquement par le modèle ;
- à un commit présenté comme final sans vérification physique.

Il doit vérifier l’état réel du workspace et les requirements du benchmark.

## ADR-011 — V14–V18 sont historiques et immuables

Les artefacts V14–V18 servent de preuves et de références d’architecture.

Ils ne doivent pas être :

- modifiés ;
- relancés ;
- remintés ;
- autorisés pour le futur benchmark ;
- copiés sous une nouvelle identité en prétendant qu’il s’agit d’une nouvelle préparation ;
- utilisés comme état mutable du nouveau runner.

Le futur benchmark reçoit de nouvelles identités et une nouvelle préparation propre à sa tâche, après qualification du système.

## ADR-012 — Pas de reprise implicite des modules historiques

Aucun module historique multi-turn ne peut être réactivé uniquement parce qu’il existe.

Chaque composant réutilisé doit être :

- nommé dans le manifeste d’architecture ;
- relié à un requirement ;
- inspecté ;
- testé ;
- intégré par un chemin explicite ;
- présent dans le manifeste de build.

---

# 3. Architecture cible

## 3.1 Vue logique

```text
Experiment Specification
        │
        ├── immutable task prompt
        ├── initial snapshot
        ├── model and executable identity
        ├── tool grammar
        ├── budgets
        ├── evaluator
        └── condition
                │
                ▼
Shared Model Transport
        │
        ▼
Canonical Tool Proposal
        │
        ▼
Shared Observation Ledger
        │
        ▼
Mode Boundary
        ├──────────────────────────────────┐
        │                                  │
        ▼                                  ▼
DIRECT MODE                    GOVERNED MODE
no Admissible decision         Admissible policy decision
        │                                  │
        │                          ALLOW / REFUSE
        │                                  │
        └──────────────┬───────────────────┘
                       ▼
              Shared Effect Executor
                       │
                       ▼
              Shared Effect Receipt
                       │
                       ▼
              Durable Run State
                       │
                       ▼
              Independent Evaluator
                       │
                       ▼
              Comparative Archive
```

## 3.2 Package cible

Créer un package de production explicitement séparé, par exemple :

```text
admissible/paired_runner/
    __init__.py
    canonical.py
    schemas.py
    specification.py
    identities.py
    observation.py
    effects.py
    process_supervision.py
    state.py
    store.py
    checkpoint.py
    transport.py
    direct_mode.py
    governed_mode.py
    policy.py
    authority.py
    evaluator.py
    comparison.py
    archive.py
    cli.py
```

Le nom exact peut être ajusté avant le premier changement de code, mais il doit rester unique et ne pas masquer une réutilisation implicite des anciens chemins.

Les composants éprouvés du canary peuvent être extraits ou composés, mais ils ne doivent pas être copiés puis divergés sans matrice de provenance.

## 3.3 Interfaces centrales

### `ModelTransport`

Responsabilités :

- lancer ou continuer une session ;
- délivrer le prompt exact ;
- recevoir les événements modèle ;
- recevoir les propositions d’outil ;
- publier les identités de session ;
- produire les métriques disponibles ;
- arrêter proprement ;
- ne jamais exécuter lui-même un effet.

### `ProposalObserver`

Responsabilités :

- publier durablement la proposition avant effet ;
- attribuer les identités ;
- préserver l’ordre causal ;
- ne jamais autoriser ou refuser ;
- être identique dans A et B.

### `ModeDecision`

Interface minimale :

```python
class ModeDecision(Protocol):
    def decide(self, proposal: CanonicalProposal) -> Decision:
        ...
```

En mode direct :

```text
DIRECT_EXECUTION
```

En mode gouverné :

```text
ALLOW
REFUSE
TERMINATE_RUN
REQUIRE_CONTINUATION
```

### `EffectExecutor`

Responsabilités :

- exécuter uniquement une proposition validée et réservée ;
- rester identique dans A et B ;
- produire un receipt durable ;
- appliquer les limites de sécurité communes ;
- ne pas interpréter la politique Admissible ;
- ne pas prendre de décision d’acceptation finale.

### `RunStateStore`

Responsabilités :

- transitions durables ;
- no-replace ;
- concurrence ;
- replay resistance ;
- récupération après crash ;
- chainage causal ;
- terminalisation ;
- intégrité.

### `IndependentEvaluator`

Responsabilités :

- recevoir une spécification gelée ;
- inspecter le résultat physique ;
- exécuter les vérifications ;
- produire un verdict ;
- ne pas dépendre du transcript pour établir la réussite ;
- pouvoir utiliser le transcript comme observation secondaire.

---

# 4. Matrice de requirements gouvernante

Le fichier suivant doit être créé avant toute implémentation :

```text
implementation/PAIRED_RUNNER_REQUIREMENT_MATRIX.json
```

Chaque requirement doit porter :

- ID ;
- texte normatif ;
- source audit ;
- composant ;
- statut ;
- preuve d’implémentation ;
- tests ;
- documentation ;
- migration ;
- risques ;
- milestone ;
- résultat final.

Statuts permis :

```text
UNASSESSED
DESIGNED
IMPLEMENTED
VERIFIED_UNIT
VERIFIED_INTEGRATION
VERIFIED_INSTALLED_PATH
BLOCKED
DEFERRED_EXPLICITLY
NOT_APPLICABLE_WITH_RATIONALE
```

## 4.1 Architecture

| ID | Requirement |
|---|---|
| ARCH-01 | Un commit source canonique et un manifeste de build doivent gouverner tous les artefacts exécutés. |
| ARCH-02 | Un seul chemin connecté doit couvrir tâche, modèle, propositions, effets, état, autorité, évaluation et archive. |
| ARCH-03 | Aucun module historique ne doit être consommé sans déclaration explicite dans le manifeste. |
| ARCH-04 | A et B doivent utiliser le même transport, le même bus de propositions et le même exécuteur d’effets. |
| ARCH-05 | La différence A/B doit être localisée dans une interface de décision unique. |
| ARCH-06 | Chaque binaire ou module exécuté doit être relié à son source digesté. |

## 4.2 Exécution

| ID | Requirement |
|---|---|
| EXEC-01 | A et B doivent utiliser le même exécutable modèle et le même digest. |
| EXEC-02 | Toute action conséquente doit exister sous forme canonique avant exécution. |
| EXEC-03 | B doit soumettre toute action au gate avant mutation. |
| EXEC-04 | A doit contourner le gate sans contourner l’observation commune. |
| EXEC-05 | L’exécuteur d’effets doit être identique dans A et B. |
| EXEC-06 | Le système doit superviser processus, enfants, timeout, sortie et annulation. |
| EXEC-07 | Aucun fallback modèle, transport ou outil ne doit être silencieux. |

## 4.3 Autorité

| ID | Requirement |
|---|---|
| AUTH-01 | Le modèle ne peut pas créer ou modifier son autorisation. |
| AUTH-02 | L’autorisation doit lier tâche, source, modèle, outils, politiques, budgets et évaluateur. |
| AUTH-03 | L’autorisation doit être rootée dans le broker privilégié pour B. |
| AUTH-04 | Toute autorisation doit expirer. |
| AUTH-05 | Une autorisation inutilisée doit pouvoir être annulée ou révoquée. |
| AUTH-06 | Une autorisation consommée ne doit jamais redevenir launchable. |
| AUTH-07 | Toute tentative de replay doit être refusée durablement. |
| AUTH-08 | Les décisions d’effet doivent être bornées par l’enveloppe autorisée. |
| AUTH-09 | Aucune identité V14–V18 ne doit être acceptée comme autorité du nouveau run. |

## 4.4 Preuves

| ID | Requirement |
|---|---|
| EVID-01 | A et B doivent partager un schéma d’observation commun. |
| EVID-02 | Toute proposition doit être enregistrée avant effet. |
| EVID-03 | Tout effet doit produire un receipt. |
| EVID-04 | Toute décision B doit produire une preuve de policy. |
| EVID-05 | L’état initial et final doivent être fingerprintés. |
| EVID-06 | Prompt, modèle, exécutable, outils, environnement et évaluateur doivent être fingerprintés. |
| EVID-07 | Les durées monotonic et wall-clock doivent être conservées. |
| EVID-08 | CPU, RSS, volumes de sortie, processus et retries doivent être enregistrés. |
| EVID-09 | Tokens et coûts doivent être enregistrés lorsque le transport les expose ; sinon l’absence doit être explicite. |
| EVID-10 | Les interventions humaines doivent être enregistrées. |
| EVID-11 | Un manifeste terminal doit réconcilier tous les objets durables. |
| EVID-12 | Un manifeste comparatif doit relier A et B au même experiment specification. |

## 4.5 Acceptation

| ID | Requirement |
|---|---|
| ACCEPT-01 | L’évaluateur doit être commun à A et B. |
| ACCEPT-02 | Il doit inspecter l’état physique final. |
| ACCEPT-03 | Il doit détecter exigences omises et modifications hors scope. |
| ACCEPT-04 | Il doit détecter une fausse déclaration de réussite. |
| ACCEPT-05 | Il doit exécuter des tests ou invariants indépendants du modèle. |
| ACCEPT-06 | Il doit produire un verdict déterministe ou expliciter les sources de non-déterminisme. |
| ACCEPT-07 | Il doit distinguer process success, model completion et task acceptance. |

## 4.6 Baseline

| ID | Requirement |
|---|---|
| BASE-01 | La Condition A doit être lancée par un runner physique, pas par un protocole opérateur informel. |
| BASE-02 | A doit recevoir les mêmes entrées non-gouvernance que B. |
| BASE-03 | A doit produire les mêmes preuves observationnelles de base. |
| BASE-04 | L’observation de A ne doit pas bloquer ou modifier une proposition. |
| BASE-05 | Les limites de sécurité expérimentale doivent être identiques dans A et B. |

## 4.7 Équité

| ID | Requirement |
|---|---|
| FAIR-01 | Le prompt doit être byte-identical. |
| FAIR-02 | Le snapshot initial doit être identique. |
| FAIR-03 | Les dépendances et toolchains doivent être identiques. |
| FAIR-04 | Les modèles, efforts, transports et outils doivent être identiques. |
| FAIR-05 | Les budgets communs doivent être identiques. |
| FAIR-06 | Les différences intentionnelles doivent être listées dans une allowlist. |
| FAIR-07 | Un gate mécanique doit refuser le lancement si une différence non autorisée existe. |
| FAIR-08 | Les caches, sessions et workspaces doivent être isolés. |
| FAIR-09 | L’ordre des conditions doit être gelé, randomisé ou explicitement justifié. |
| FAIR-10 | Toute intervention humaine non prévue doit invalider ou qualifier le run. |

## 4.8 Long-running

| ID | Requirement |
|---|---|
| LONG-01 | Un run doit supporter plusieurs tours modèle. |
| LONG-02 | Un run doit supporter plusieurs sessions ou context continuations. |
| LONG-03 | Les budgets doivent être cumulatifs et durables. |
| LONG-04 | Le système doit reprendre après crash à partir d’un checkpoint durable. |
| LONG-05 | Une action ambiguë après crash ne doit pas être rejouée automatiquement. |
| LONG-06 | Le propriétaire ou l’opérateur doit pouvoir annuler. |
| LONG-07 | Les logs doivent être bornés en mémoire. |
| LONG-08 | Le système doit supporter de gros volumes de sortie sans croissance non bornée. |
| LONG-09 | Les états stale, expirés ou incohérents doivent refuser fail-closed. |
| LONG-10 | La continuation doit préserver l’identité du run et l’ordre causal. |

## 4.9 Opérations

| ID | Requirement |
|---|---|
| OPS-01 | Une commande read-only doit produire la readiness complète. |
| OPS-02 | Chaque commande doit être classifiée : read-only, provider-contacting, authority-creating, mutating ou one-shot. |
| OPS-03 | Les one-shots doivent être protégés contre les reruns. |
| OPS-04 | L’objet exact autorisé doit être rendu à l’opérateur. |
| OPS-05 | Les refus doivent indiquer la condition exacte sans suggérer un retry dangereux. |
| OPS-06 | Le statut terminal doit être reconstructible uniquement depuis les preuves durables. |
| OPS-07 | Une installation clean-host doit fournir les mêmes entry points que le dépôt source. |

## 4.10 Tests

| ID | Requirement |
|---|---|
| TEST-01 | Les tests unitaires existants pertinents doivent rester passants. |
| TEST-02 | Les tests doivent traverser le chemin installé exact. |
| TEST-03 | Une suite provider-free doit couvrir A et B. |
| TEST-04 | Les tests doivent couvrir crash et restart à chaque transition durable. |
| TEST-05 | Les tests doivent couvrir replay, duplicate, stale authorization et partial publication. |
| TEST-06 | Les tests doivent couvrir wrong prompt, wrong source, wrong model, wrong tool grammar et wrong budget. |
| TEST-07 | Les tests doivent couvrir faux succès, omission et mutation hors scope. |
| TEST-08 | Un soak test doit couvrir sortie massive et durée longue. |
| TEST-09 | Un test de parité doit comparer tous les inputs A/B. |
| TEST-10 | Une release ne peut être qualifiée uniquement par des mocks in-process. |

---

# 5. Discipline d’implémentation

## 5.1 Avant le premier changement

L’implémentation doit commencer par :

1. lire entièrement ce document ;
2. lire entièrement l’audit source ;
3. inspecter les chemins source cités par l’audit ;
4. confirmer les commits et worktrees physiques ;
5. créer la matrice persistante ;
6. créer un source-of-truth manifest ;
7. créer un ADR register ;
8. produire un plan fichier par fichier pour le Milestone 0 et le Milestone 1.

Aucun code ne doit être modifié avant ces productions.

## 5.2 Exécution par milestone

Chaque milestone doit être traité séparément.

À la fin de chaque milestone, produire :

- requirements traités ;
- fichiers modifiés ;
- diff résumé ;
- tests exécutés ;
- résultats ;
- artefacts produits ;
- invariants vérifiés ;
- limitations restantes ;
- décision `PASS`, `PASS_WITH_EXPLICIT_LIMITATIONS` ou `FAIL`;
- commit exact.

Ne pas poursuivre après un `FAIL`.

## 5.3 Interdictions

Il est interdit de :

- stubber silencieusement une frontière ;
- considérer un test de schéma comme une preuve de connexion ;
- utiliser un faux broker dans le chemin présenté comme production ;
- déclarer multi-session un système qui relance simplement un nouveau run ;
- comparer A et B avec des outils différents ;
- masquer une différence expérimentale dans un prompt ;
- traiter un exit code `0` comme task success ;
- laisser un état actif uniquement en mémoire ;
- ajouter un retry automatique après une action potentiellement consommée ;
- produire un nouveau numéro V15–V18-like ;
- contacter un fournisseur avant le gate prévu ;
- modifier les racines `/etc`, `/var/lib`, `/run` ou `/opt` de production pendant les validations intermédiaires ;
- utiliser le witness de production dans des tests ;
- créer une autorisation réelle pendant l’implémentation.

Tous les tests d’autorité doivent utiliser une racine jetable.

---

# 6. Milestones

# Milestone 0 — Foundation Freeze

## Objectif

Établir un socle source et build unique avant toute convergence.

## Requirements

- ARCH-01
- ARCH-03
- ARCH-06
- OPS-07
- AUTH-09

## Travaux

1. Choisir le dépôt source canonique.
2. Choisir le commit de départ exact.
3. Vérifier toutes les worktrees pertinentes.
4. Produire :

```text
implementation/FOUNDATION_FREEZE.md
implementation/SOURCE_OF_TRUTH.json
implementation/BUILD_INPUT_MANIFEST.json
implementation/ADR_REGISTER.md
implementation/PAIRED_RUNNER_REQUIREMENT_MATRIX.json
```

5. Inventorier chaque composant réutilisable du canary :
   - transport app-server ;
   - grammaire dynamique ;
   - confinement ;
   - owner broker ;
   - receipt ;
   - publication durable ;
   - state machine ;
   - physical verification.
6. Inventorier chaque composant explicitement exclu :
   - product Cursor path ;
   - baseline operator-log ;
   - modules historiques multi-turn non connectés ;
   - V14 final-generation comme future préparation.
7. Définir le nouveau namespace package.
8. Définir la politique de provenance de code extrait du canary.

## Validation

- dépôt propre ;
- aucun artefact modifié ;
- aucun import ambigu ;
- tous les chemins source cités existent ;
- chaque composant cible possède un digest ;
- aucun artefact V14–V18 n’est inscrit comme input mutable.

## Exit criteria

```text
FOUNDATION_FREEZE_VERIFIED
```

---

# Milestone 1 — Executable Architecture Specification

## Objectif

Produire la spécification exécutable de l’architecture avant son implémentation.

## Requirements

- ARCH-02
- ARCH-04
- ARCH-05
- EXEC-01
- EXEC-02
- EXEC-03
- EXEC-04
- EXEC-05
- BASE-01
- BASE-02
- FAIR-01 à FAIR-07

## Travaux

Définir formellement :

- `ExperimentSpecification`
- `CanonicalProposal`
- `ModeDecision`
- `EffectReservation`
- `EffectReceipt`
- `RunIdentity`
- `SessionIdentity`
- `BudgetState`
- `HumanInterventionRecord`
- `EvaluatorSpecification`
- `TerminalManifest`
- `ComparativeManifest`

Créer les schémas versionnés.

Définir la liste exacte des différences autorisées entre A et B.

Exemple minimal :

```json
{
  "allowed_condition_differences": [
    "condition_id",
    "admissible_decision_required",
    "owner_delegation_required",
    "governance_evidence"
  ]
}
```

Toute autre différence doit faire échouer le parity gate.

## Validation

- round-trip canonique ;
- unknown fields refusés ;
- NaN et non-canonical values refusés ;
- fingerprints stables ;
- tests de mutation d’un champ à la fois ;
- comparaison A/B déterministe ;
- aucune dépendance au provider.

## Exit criteria

```text
PAIRED_ARCHITECTURE_SPECIFICATION_VERIFIED
```

---

# Milestone 2 — Shared Observation and Effect Substrate

## Objectif

Construire le chemin commun utilisé par A et B avant d’ajouter le modèle ou la gouvernance.

## Requirements

- EXEC-02
- EXEC-05
- EXEC-06
- EVID-01 à EVID-08
- LONG-07
- LONG-08
- TEST-03
- TEST-08

## Travaux

Implémenter :

- proposal reservation ;
- durable proposal publication ;
- effect reservation ;
- shared effect executor ;
- stdout/stderr bounded retention ;
- process tree supervision ;
- timeout ;
- cancellation ;
- receipt publication ;
- filesystem diff observation ;
- Git observation ;
- timing and resource collection ;
- reconciliation ledger.

Corriger l’architecture de `_StreamPump` ou la remplacer dans le nouveau chemin.

Aucune queue ne doit croître avec le volume total de sortie.

## Validation

### Functional

- `list_files`
- `read_file`
- `write_file`
- `run_command`
- invalid path
- command timeout
- process child cleanup
- partial output
- non-zero exit
- cancellation

### Durability

Crash forcé :

- avant proposal publication ;
- après proposal publication ;
- avant effect start ;
- après effect start ;
- avant receipt ;
- après receipt ;
- avant state transition ;
- après state transition.

### Output soak

Au minimum :

- 1 000 000 lignes ou 1 GiB de sortie combinée ;
- retained output conforme au cap ;
- aucune queue non bornée ;
- croissance RSS du contrôleur sous le seuil fixé dans `FOUNDATION_FREEZE.md`;
- aucun deadlock ;
- aucune perte du statut terminal.

## Exit criteria

```text
SHARED_EFFECT_SUBSTRATE_VERIFIED
```

---

# Milestone 3 — Provider-Free Multi-Session Transport

## Objectif

Prouver la durée et la continuation sans lancer un modèle réel.

## Requirements

- LONG-01
- LONG-02
- LONG-03
- LONG-04
- LONG-05
- LONG-09
- LONG-10
- EXEC-07
- EVID-07 à EVID-10

## Travaux

Construire un transport déterministe provider-free qui reproduit :

- démarrage de session ;
- propositions d’outils ;
- fin de tour ;
- demande de continuation ;
- reprise ;
- crash ;
- malformed event ;
- duplicate event ;
- stale session ;
- budget exhaustion.

Implémenter le state store durable.

Implémenter les budgets cumulatifs :

- sessions ;
- turns ;
- proposals ;
- effects ;
- commands ;
- wall time ;
- model-active time ;
- bytes output ;
- retries ;
- continuations ;
- human interventions.

## Validation

Scénario déterministe minimal :

- 4 sessions ;
- 20 tours ;
- 250 propositions ;
- 3 checkpoints ;
- 2 crashes forcés ;
- 1 restart du contrôleur ;
- 1 pause opérateur ;
- reprise exacte ;
- terminalisation sans duplicate effect.

Tester également :

- crash après effet mais avant receipt ;
- aucune réexécution automatique ;
- état `AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION` ou équivalent ;
- reprise uniquement après preuve.

## Exit criteria

```text
MULTI_SESSION_PROVIDER_FREE_VERIFIED
```

---

# Milestone 4 — Generic Governed Mode

## Objectif

Connecter la Condition B au gate Admissible et au broker privilégié dans une racine de test jetable.

## Requirements

- AUTH-01 à AUTH-08
- EXEC-03
- EVID-04
- OPS-02 à OPS-05
- TEST-04 à TEST-06

## Travaux

1. Définir l’enveloppe d’autorisation générique.
2. Extraire ou adapter le broker sans affaiblir :
   - record ID root-generated ;
   - no-replace ;
   - durable pending state ;
   - one-shot consumption ;
   - signed receipt ;
   - forward-only state.
3. Ajouter :
   - expiration ;
   - cancellation ;
   - revocation before consumption ;
   - explicit unused state ;
   - stale environment refusal.
4. Implémenter le policy gate par proposition.
5. Lier chaque décision :
   - run ;
   - session ;
   - proposal ;
   - authorization envelope ;
   - current budget ;
   - current state ;
   - policy version.
6. Refuser avant effet toute proposition :
   - hors scope ;
   - hors budget ;
   - non canonique ;
   - stale ;
   - replayée ;
   - issue d’une autre session ;
   - incompatible avec l’état actuel.

## Validation

Racine de test uniquement.

Cas obligatoires :

- wrong prompt ;
- wrong source ;
- wrong executable ;
- wrong model ;
- wrong tool grammar ;
- wrong evaluator ;
- wrong policy ;
- wrong workspace ;
- wrong run ID ;
- expired authorization ;
- cancelled authorization ;
- revoked authorization ;
- consumed authorization ;
- duplicate proposal ;
- replayed receipt ;
- partial authority publication ;
- broker crash ;
- caller crash après consumption ;
- out-of-scope path ;
- forbidden command ;
- exhausted budget.

Aucun chemin ne doit toucher le broker de production.

## Exit criteria

```text
GENERIC_GOVERNED_MODE_VERIFIED
```

---

# Milestone 5 — Instrumented Direct Mode

## Objectif

Construire la Condition A avec exactement le même transport et le même exécuteur.

## Requirements

- BASE-01 à BASE-05
- EXEC-04
- EVID-01 à EVID-03
- FAIR-01 à FAIR-07
- TEST-09

## Travaux

Implémenter le mode direct :

- même proposition canonique ;
- même proposal ledger ;
- même effect executor ;
- même receipt ;
- même state store ;
- mêmes budgets ;
- même processus ;
- même environnement ;
- aucune décision Admissible ;
- aucun refusal policy Admissible ;
- aucune autorisation propriétaire de délégation.

Les limites communes de sécurité expérimentale restent actives.

Le run doit indiquer explicitement :

```text
governance_mode: DIRECT
admissible_decision_applied: false
```

## Validation

Pour une séquence synthétique identique, comparer A et B en policy allow-all.

Tous les objets communs doivent être identiques à l’exception de l’allowlist de différences.

Le parity checker doit refuser :

- prompt modifié ;
- model modifié ;
- executable modifié ;
- timeout modifié ;
- outil ajouté ;
- environnement modifié ;
- snapshot modifié ;
- evaluator modifié ;
- budget modifié.

## Exit criteria

```text
INSTRUMENTED_DIRECT_MODE_VERIFIED
```

---

# Milestone 6 — Generic Independent Evaluator

## Objectif

Établir un verdict commun indépendant du modèle.

## Requirements

- ACCEPT-01 à ACCEPT-07
- EVID-05
- EVID-11
- TEST-07

## Travaux

Définir un evaluator manifest contenant :

- requirements ;
- allowed files ;
- forbidden files ;
- allowed dependency changes ;
- public tests ;
- held-out tests ;
- property tests ;
- reproducible commands ;
- timeout ;
- environment ;
- expected artifacts ;
- Git policy ;
- documentation requirements ;
- security checks ;
- out-of-scope diff policy.

L’évaluateur doit produire séparément :

```text
PROCESS_RESULT
MODEL_CLAIM
REPOSITORY_STATE
TEST_RESULT
SCOPE_RESULT
REQUIREMENT_RESULT
TASK_ACCEPTANCE
```

## Validation

Fixtures obligatoires :

1. modèle affirme réussite, code cassé ;
2. tests publics passent, hidden property échoue ;
3. exigence omise ;
4. fichier hors scope modifié ;
5. dépendance non autorisée ajoutée ;
6. commit final absent ;
7. workspace sale ;
8. implémentation correcte ;
9. implémentation alternative correcte ;
10. logs manquants mais résultat correct ;
11. résultat incomplet avec exit `0`.

L’évaluateur doit accepter les solutions valides alternatives et refuser les faux positifs.

## Exit criteria

```text
INDEPENDENT_EVALUATOR_VERIFIED
```

---

# Milestone 7 — Reproducible Paired Environment

## Objectif

Créer deux conditions physiquement séparées depuis un même état.

## Requirements

- FAIR-01 à FAIR-10
- EVID-05
- EVID-06
- ARCH-01
- OPS-01

## Travaux

Créer un `ExperimentPreparation` qui :

1. vérifie une source propre ;
2. fingerprint :
   - HEAD ;
   - index ;
   - tracked tree ;
   - untracked policy ;
   - submodules ;
   - dependencies ;
   - toolchain ;
   - environment ;
   - executable set ;
   - caches ;
3. produit un snapshot immuable ;
4. dérive deux workspaces :
   - Condition A ;
   - Condition B ;
5. crée des caches séparés ;
6. interdit les sessions partagées ;
7. interdit les roots d’autorité partagées ;
8. produit un parity report.

## Validation

Modifier un élément après préparation et exiger le refus :

- fichier tracked ;
- fichier untracked ;
- Git ref ;
- dependency ;
- environment variable ;
- executable ;
- cache seed ;
- prompt ;
- tool schema ;
- evaluator ;
- budget.

## Exit criteria

```text
PAIRED_ENVIRONMENT_VERIFIED
```

---

# Milestone 8 — Installed-Path Qualification

## Objectif

Prouver le système complet sans provider réel et sans autorité de production.

## Requirements

- TEST-01 à TEST-10
- OPS-01 à OPS-07
- ARCH-02
- EVID-11
- EVID-12

## Travaux

Construire les artefacts installables exacts.

Installer dans une racine hermétique ou une VM/container local sans contact réseau.

Exécuter :

1. Condition A provider-free ;
2. Condition B provider-free ;
3. même tâche synthétique ;
4. policy allow-all ;
5. policy avec refus ;
6. restart ;
7. crash ;
8. expiration ;
9. cancellation ;
10. évaluation ;
11. archive comparative.

Vérifier le chemin installé, pas les sources importées directement depuis le checkout.

## Matrice négative obligatoire

- wrong installed digest ;
- missing module ;
- unexpected module ;
- altered prompt ;
- altered tool grammar ;
- altered evaluator ;
- altered source ;
- altered budget ;
- stale authorization ;
- duplicate run ;
- duplicate session ;
- duplicate proposal ;
- duplicate effect ;
- malformed receipt ;
- partial terminal manifest ;
- corrupt checkpoint ;
- missing archive object ;
- false model completion ;
- process orphan ;
- controller restart ;
- output flood ;
- disk-full simulation si possible ;
- interrupted fsync/publication boundary.

## Exit criteria

```text
INSTALLED_PATH_PROVIDER_FREE_QUALIFIED
```

---

# Milestone 9 — Independent Closure Audit

## Objectif

Faire auditer l’implémentation avant tout benchmark réel.

## Audit requis

Un nouvel auditeur doit recevoir :

- ce plan ;
- l’audit source ;
- la requirement matrix ;
- tous les ADR ;
- le source manifest ;
- le build manifest ;
- les artefacts installés ;
- les rapports de tests ;
- les fixtures négatives ;
- les rapports de parité ;
- les rapports de soak ;
- les archives provider-free.

Verdict permis :

```text
READY_FOR_BENCHMARK FREEZE
READY_FOR_BENCHMARK FREEZE WITH BOUNDED REPAIRS
NOT READY FOR BENCHMARK FREEZE
```

L’auditeur ne doit pas lancer de modèle réel.

## Exit criteria

```text
INDEPENDENT_IMPLEMENTATION_CLOSURE_ACCEPTED
```

---

# Milestone 10 — Benchmark Freeze Preparation

## Objectif

Préparer, sans exécuter, le protocole réel.

Ce milestone ne peut commencer qu’après fermeture indépendante.

## Décisions à figer

- task repository ;
- initial commit ;
- prompt exact ;
- model ;
- reasoning configuration ;
- executable ;
- tool grammar ;
- network policy ;
- dependency policy ;
- Git policy ;
- time budget ;
- token/cost budget ;
- continuation budget ;
- process budget ;
- retry budget ;
- human-intervention policy ;
- evaluator ;
- public tests ;
- held-out tests ;
- scope policy ;
- order A/B ;
- archive destination ;
- owner authorization envelope B.

## Artefacts attendus

```text
experiment/EXPERIMENT_SPECIFICATION.json
experiment/PAIR_PARITY_MANIFEST.json
experiment/CONDITION_A_PLAN.json
experiment/CONDITION_B_PREPARATION.json
experiment/EVALUATOR_MANIFEST.json
experiment/HUMAN_INTERVENTION_POLICY.json
experiment/RUN_ORDER_COMMITMENT.json
experiment/EXECUTION_CEREMONY.md
```

Aucune owner authorization réelle ne doit encore être créée.

## Exit criteria

```text
BENCHMARK_READY_FOR_OWNER_REVIEW
```

---

# 7. Frontières de sécurité

## 7.1 Actions interdites jusqu’après Milestone 9

- lancer Codex, Cursor ou un autre modèle réel ;
- contacter un provider ;
- utiliser un credential provider ;
- provisionner une autorisation propriétaire de production ;
- consommer une autorisation de production ;
- refresh le witness courant ;
- modifier l’installation owner authority actuelle ;
- écrire dans les evidence roots V14–V18 ;
- créer le futur benchmark final ;
- publier un résultat comparatif réel.

## 7.2 Actions permises

- analyse de code ;
- modification du nouveau package ;
- tests unitaires ;
- tests d’intégration provider-free ;
- faux transport déterministe ;
- autorité de test dans un temporary root ;
- clés de test jetables ;
- installations hermétiques ;
- fault injection ;
- soak tests ;
- génération d’artefacts de planification.

## 7.3 Première frontière provider réelle

La première commande capable de contacter un provider devra être :

- distincte ;
- rendue intégralement ;
- digestée ;
- précédée d’un readiness read-only ;
- classifiée `PROVIDER_CONTACTING`;
- impossible à déclencher pendant les tests ;
- absente de toute exécution avant fermeture indépendante.

## 7.4 Première frontière d’autorité réelle

La création de l’autorisation propriétaire du benchmark B devra être :

- postérieure au benchmark freeze ;
- liée au manifeste final ;
- précédée d’une revue propriétaire ;
- one-shot ;
- no-replace ;
- expirable ;
- révocable avant consumption ;
- distincte du lancement ;
- jamais automatisée par le modèle.

---

# 8. Métriques comparatives obligatoires

Le système final doit produire au minimum :

## Résultat

- task accepted ;
- requirements satisfied ;
- public tests ;
- held-out tests ;
- scope compliance ;
- reproducibility ;
- final Git state ;
- final repository fingerprint.

## Temps

- wall-clock total ;
- model-active time ;
- tool execution time ;
- policy decision time ;
- owner ceremony time ;
- paused time ;
- evaluator time.

## Ressources

- sessions ;
- turns ;
- proposals ;
- executed effects ;
- refused effects ;
- command count ;
- write count ;
- bytes read ;
- bytes written ;
- stdout/stderr volume ;
- CPU time ;
- peak RSS ;
- token usage si disponible ;
- cost si disponible.

## Comportement

- invalid proposals ;
- duplicate proposals ;
- out-of-scope proposals ;
- retry attempts ;
- false completion claims ;
- tests run by model ;
- failures detected and repaired ;
- human interventions ;
- crashes ;
- resumptions ;
- budget exhaustion.

## Gouvernance

- allowed decisions ;
- refused decisions ;
- reason distribution ;
- policy identity ;
- envelope utilization ;
- unused authority ;
- attempted replay ;
- fail-closed events.

## Preuve

- evidence objects expected ;
- evidence objects present ;
- reconciliation complete ;
- mutable evidence detected ;
- chain-of-custody breaks ;
- third-party reconstructability.

---

# 9. Critères de réussite de la phase d’implémentation

La phase d’implémentation est fermée uniquement si :

1. un seul chemin installé supporte A et B ;
2. les deux modes utilisent le même modèle transport ;
3. les deux modes utilisent le même exécuteur ;
4. la différence est localisée dans le decision boundary ;
5. B ne peut produire aucun effet sans décision Admissible ;
6. A n’est pas bloquée par Admissible ;
7. les observations communes sont identiques ;
8. les runs sont multi-session et durables ;
9. crash et restart sont supportés ;
10. les logs sont bornés ;
11. le broker de test supporte expiration et révocation ;
12. l’évaluateur commun détecte les faux succès ;
13. le parity gate refuse toute différence non autorisée ;
14. le chemin installé exact passe la qualification provider-free ;
15. un audit indépendant rend un verdict permettant le benchmark freeze.

La phase n’est pas fermée si :

- seul le mode B fonctionne ;
- A reste un protocole manuel ;
- le modèle ou les outils diffèrent ;
- Cursor est utilisé dans une condition et Codex dans l’autre ;
- l’état actif reste en mémoire ;
- le gate intervient après mutation ;
- l’évaluateur est task-agnostic au point d’être `OBSERVED_ONLY` ;
- les tests ne traversent pas le chemin installé ;
- les preuves ne permettent pas une comparaison tierce ;
- une limitation est dissimulée dans la documentation.

---

# 10. Première séquence d’exécution

L’ingénieur chargé de l’implémentation doit commencer uniquement par :

```text
Milestone 0 — Foundation Freeze
```

Il doit ensuite s’arrêter et rendre :

- le source-of-truth manifest ;
- le build-input manifest ;
- l’ADR register ;
- la requirement matrix ;
- la liste des composants canary réutilisés ;
- la liste des composants explicitement exclus ;
- les chemins proposés du nouveau package ;
- les risques de migration ;
- les tests prévus pour Milestone 1.

Aucun code fonctionnel du paired runner ne doit être écrit pendant Milestone 0.

Le passage au Milestone 1 exige un verdict explicite :

```text
FOUNDATION_FREEZE_VERIFIED
```

---

# 11. Définition de la fin

L’implémentation ne cherche pas à démontrer qu’Admissible « fonctionne » en général.

Elle doit produire une plateforme expérimentale suffisamment contrôlée pour que le futur résultat puisse répondre honnêtement à la question :

> À modèle, tâche, outils, environnement, budget et évaluateur identiques, que change l’interposition d’Admissible entre les propositions du modèle et leurs effets réels ?

Toute décision qui empêche cette question d’être isolée est un défaut de l’implémentation.

Toute preuve qui ne permet pas à un tiers de reconstruire la réponse est insuffisante.

Toute réussite déclarée uniquement par le modèle est non autoritative.
