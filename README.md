# 📘 Guide d'installation --- FirewallIA sur Debian

## 1. Pré-requis

Installer une distribution Debian classique (version stable
recommandée).

------------------------------------------------------------------------

## 2. Installation des dépendances système

Passer en root puis installer les paquets nécessaires :

``` bash
su -
apt update
apt install git cargo curl build-essential pkg-config libssl-dev protobuf-compiler
```

------------------------------------------------------------------------

## 3. Récupération du projet

``` bash
git clone https://github.com/FirewallIA/FirewallIA.git
cd FirewallIA
```

------------------------------------------------------------------------

## 4. Installation de bpf-linker

``` bash
cargo install bpf-linker
```

### En cas d'erreur de compilation

Exemple :

    error: failed to compile bpf-linker v0.9.15, intermediate artifacts can be found at /tmp/...

#### Solution

Installer Rust via rustup :

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Si Rust est déjà installé via apt :

``` bash
apt remove rustc
```

Charger l'environnement :

``` bash
source $HOME/.cargo/env
```

Mettre à jour Rust et forcer une version compatible :

``` bash
rustup update stable
rustup install 1.86.0
rustup override set 1.86.0
```

Vérifier les versions :

``` bash
rustc --version
cargo --version
```

Installer les composants nécessaires :

``` bash
rustup component add rust-src --toolchain nightly
cargo install cargo-generate
```

------------------------------------------------------------------------

## 5. Installation des dépendances eBPF

``` bash
apt update
apt install build-essential linux-headers-$(uname -r) libelf-dev linux-headers-amd64
```

------------------------------------------------------------------------

## 6. Lancer le programme

``` bash
RUST_LOG=info cargo run -- --int enp0s8
```

------------------------------------------------------------------------

## 7. Création de la base de données

### Installation de Docker

Documentation officielle :
https://docs.docker.com/engine/install/debian/

### Lancer PostgreSQL

``` bash
docker run \
  --name postgres-container \
  -e POSTGRES_PASSWORD=monmotdepasse \
  -d \
  -p 5432:5432 \
  -v /chemin/vers/volume:/var/lib/postgresql/data \
  postgres
```

Connexion au conteneur :

``` bash
docker exec -it postgres-container psql -U postgres
```

------------------------------------------------------------------------

## 8. Configuration PostgreSQL

Créer l'utilisateur et la base :

``` sql
CREATE USER postgres WITH PASSWORD 'postgres';
CREATE DATABASE firewall OWNER postgres;
ALTER USER postgres WITH PASSWORD 'postgres';
```

Se connecter à la base :

``` sql
\c firewall
```

Créer la table `rules` :

``` sql
CREATE TABLE rules (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    source_port INT,
    dest_port INT,
    action VARCHAR(10) NOT NULL,
    protocol VARCHAR(10),
    usage_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

------------------------------------------------------------------------

## 9. Lancer le projet avec la base de données

``` bash
RUST_LOG=info cargo run -- --int enp0s8
```
