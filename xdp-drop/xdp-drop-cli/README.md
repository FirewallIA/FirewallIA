# 🧪 Tests Unitaires pour xdp-drop-cli

Tests unitaires complets pour le CLI du firewall XDP.

## 📋 Structure des Tests

### 1. **Tests de Parsing CLI** (Clap)
- ✅ Commande `status`
- ✅ Commande `list-rules`
- ✅ Commande `create-rule` (avec tous les paramètres)
- ✅ Commande `create-rule` (avec valeurs par défaut)
- ✅ Commande `delete-rule`
- ✅ Commande `traffic-stats` (avec différentes périodes)
- ✅ Validation des arguments requis
- ✅ Gestion des erreurs de parsing

### 2. **Tests de Validation des Données**
- ✅ Création de `RuleData`
- ✅ Règles avec wildcards (`*`)
- ✅ Formats d'IP valides (IPv4, CIDR)
- ✅ Formats de ports valides
- ✅ Actions valides (allow, deny, drop, reject)
- ✅ Protocoles valides (TCP, UDP, ICMP, any)

### 3. **Tests des Cas Limites**
- ✅ Nom de règle vide
- ✅ Nom de règle très long (255 caractères)
- ✅ ID de règle à zéro
- ✅ ID de règle négatif
- ✅ Différentes périodes pour les statistiques

### 4. **Tests de Régression**
- ✅ Compatibilité rétroactive des commandes
- ✅ Formats d'adresse serveur variés

##  Installation

### 1. Intégrer les tests dans votre projet

Placez le fichier `main_tests.rs` dans le dossier approprié :

```bash
cd FirewallIA/xdp-drop/xdp-drop-cli
mkdir -p tests
cp main_tests.rs tests/
```

### 2. Modifier le fichier `main.rs`

Pour rendre les fonctions testables, ajoutez `pub` aux fonctions :

```rust
// Avant
async fn handle_get_status(...) -> anyhow::Result<()> { ... }

// Après (pour les tests)
pub async fn handle_get_status(...) -> anyhow::Result<()> { ... }
```

Ou créez un module `lib.rs` séparé avec les fonctions publiques.

### 3. Mettre à jour `Cargo.toml`

Ajoutez les dépendances de test :

```toml
[dev-dependencies]
tokio-test = "0.4"
```

## 🔧 Exécution des Tests

### Tests basiques (parsing CLI)

```bash
cargo test
```

### Tests avec sortie détaillée

```bash
cargo test -- --nocapture
```

### Tests spécifiques

```bash
# Tester uniquement le parsing CLI
cargo test test_cli

# Tester la validation des données
cargo test test_rule_data

# Tester les cas limites
cargo test test_delete_rule
```


##  Exemple de Sortie

```
running 25 tests
test tests::test_cli_status_command ... ok
test tests::test_cli_list_rules_command ... ok
test tests::test_cli_create_rule_command_full ... ok
test tests::test_cli_create_rule_with_defaults ... ok
test tests::test_cli_delete_rule_command ... ok
test tests::test_cli_traffic_stats_default ... ok
test tests::test_cli_traffic_stats_custom_range ... ok
test tests::test_cli_invalid_command ... ok
test tests::test_cli_missing_required_args ... ok
test tests::test_rule_data_creation ... ok
test tests::test_rule_data_with_wildcards ... ok
test tests::test_valid_ipv4_formats ... ok
test tests::test_valid_port_formats ... ok
test tests::test_valid_actions ... ok
test tests::test_valid_protocols ... ok
test tests::test_rule_data_empty_name ... ok
test tests::test_rule_data_long_name ... ok
test tests::test_delete_rule_zero_id ... ok
test tests::test_delete_rule_negative_id ... ok
test tests::test_traffic_stats_various_ranges ... ok
test tests::test_cli_backward_compatibility ... ok
test tests::test_server_addr_formats ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured
```

## ✅ Checklist pour les PR

Avant de soumettre une PR :

- [ ] Tous les tests passent (`cargo test`)
- [ ] Les nouveaux tests couvrent les nouvelles fonctionnalités
- [ ] Les tests sont documentés
- [ ] Pas de warnings (`cargo clippy`)
- [ ] Code formaté (`cargo fmt`)

## 🤔 Questions Fréquentes

**Q : Les tests sont lents ?**
A : Non, ces tests sont très rapides (< 1 seconde). Pas de I/O ni de réseau.

**Q : Dois-je tester chaque combinaison de paramètres ?**
A : Non. Les tests actuels couvrent les cas principaux. Ajoutez des tests quand vous trouvez des bugs.

## 📄 Licence

Même licence que le projet FirewallIA principal.