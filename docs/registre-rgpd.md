# Registre des activités de traitement — fiche pré-remplie (RGPD, art. 30)

> Fiche à intégrer au registre des traitements de l'organisation pour le
> traitement « passerelle de sécurisation des flux IA (SENTINEL) ».
> Les champs `[À compléter]` relèvent de votre organisation.

| Rubrique (art. 30(1)) | Contenu |
|:---|:---|
| **Nom du traitement** | Inspection et pseudonymisation des requêtes sortantes vers des services d'IA générative (passerelle SENTINEL) |
| **Responsable du traitement** | `[À compléter — raison sociale, coordonnées]` |
| **Délégué à la protection des données** | `[À compléter — nom, contact]` |
| **Finalités** | 1. Prévenir la transmission de données personnelles et confidentielles à des fournisseurs d'IA tiers ; 2. Pseudonymiser les données identifiantes avant transmission (FPE) ; 3. Tracer les décisions de sécurité à des fins d'audit et de conformité (AI Act, RGPD) ; 4. Documenter les transferts par fournisseur (registre Shadow AI) |
| **Base de licitation** | `[À compléter — typiquement : intérêt légitime (sécurité des données, art. 6(1)(f)) ; à valider par le DPO]` |
| **Catégories de personnes concernées** | Employés utilisateurs de la passerelle ; tiers mentionnés dans les prompts (clients, patients, contacts) |
| **Catégories de données traitées** | Identité (noms), coordonnées (emails, téléphones), données bancaires (IBAN, cartes), NIR, identifiants d'entreprise (SIRET), secrets techniques (clés API), contenus de documents internes. Les données détectées sont **pseudonymisées ou bloquées avant tout envoi** ; leurs valeurs sont conservées chiffrées (clé dérivée par entité) dans le vault et le journal d'audit |
| **Destinataires** | Interne : RSSI/équipe sécurité (dashboard, rapports). Externe : fournisseurs d'IA configurés (OpenAI, Anthropic, Groq, Mistral) — qui ne reçoivent **que des données pseudonymisées** ; le juge local (Ollama) s'exécute sur l'infrastructure interne |
| **Transferts hors UE** | Possibles selon le fournisseur appelé (OpenAI, Anthropic, Groq : États-Unis). Documentés en continu par le registre Shadow AI (fournisseur, région, volumes). Encadrement contractuel : `[À compléter — DPA / clauses contractuelles types]` |
| **Durées de conservation** | Tokens FPE : TTL configurable (`vault_ttl_hours`, défaut 24 h). Journal d'audit : `[À compléter — recommandation : ≥ 6 mois, aligné AI Act art. 26(6)]`. Effacement d'une entité : crypto-shredding (destruction de sa clé de chiffrement) |
| **Mesures de sécurité (art. 32)** | Pseudonymisation FPE ; chiffrement au repos (Fernet) ; journal d'audit chaîné HMAC-SHA256 à intégrité vérifiable ; clés API clients stockées hachées, révocables, avec rate-limiting ; authentification du dashboard ; cloisonnement multi-tenant des corpus ; comparaison de secrets en temps constant |
