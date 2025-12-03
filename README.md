# 📘 Guide d'installation -- FirewallIA sur Debian 

1. Pré-requis Installer
une Debian classique (version stable recommandée).

2.  Installation des dépendances su - root apt update apt install git
    cargo curl build-essential pkg-config libssl-dev protobuf-compiler

3.  Récupération du projet git clone
    https://github.com/FirewallIA/FirewallIA.git

4.  Installation de bpf-linker cargo install bpf-linker

⚠️ En cas d'erreur : Exemple : error: failed to compile bpf-linker
v0.9.15, intermediate artifacts can be found at
/tmp/cargo-installDRpx0Nn

➡️ Solution : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs
\| sh \# (si Rust est déjà installé via apt : apt remove rustc)

source \$HOME/.cargo/env rustup update stable rustup install 1.86.0
rustup override set 1.86.0

Vérification des versions rustc --version cargo --version

Ajout des composants rustup component add rust-src --toolchain nightly
cargo install cargo-generate

5.  Installation des dépendances supplémentaires apt update && apt
    install build-essential linux-headers-\$(uname -r) libelf-dev
    linux-headers-amd64

6.  Lancer le programme RUST_LOG=info cargo run -- --int enp0s8

7.  Création de la base de données Installation de Docker 👉 Suivre la
    documentation officielle : Installer Docker sur Debian Lancer un
    conteneur PostgreSQL docker run --name postgres-container -e
    POSTGRES_PASSWORD=monmotdepasse -d -p 5432:5432 -v
    /chemin/vers/volume:/var/lib/postgresql/data postgres

Connexion au conteneur docker exec -it postgres-container psql -U
postgres

8.  Configuration de la base PostgreSQL CREATE USER postgres WITH
    PASSWORD 'postgres';

CREATE DATABASE firewall OWNER postgres; ALTER USER postgres WITH
PASSWORD 'postgres';

-- Connexion à la base `\c f`{=tex}irewall

Création de la table rules CREATE TABLE rules ( id SERIAL PRIMARY KEY,
-- Identifiant unique de la règle source_ip VARCHAR(45) NOT NULL, --
Adresse IP source (IPv4/IPv6) dest_ip VARCHAR(45) NOT NULL, -- Adresse
IP de destination (IPv4/IPv6) source_port INT, -- Port source
(optionnel) dest_port INT, -- Port de destination (optionnel) action
VARCHAR(10) NOT NULL, -- Action ('allow', 'deny', etc.) protocol
VARCHAR(10), -- Protocole (TCP, UDP, ICMP, etc.) usage_count INT DEFAULT
0, -- Nombre d'utilisations created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP, -- Date de création updated_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP -- Date de mise à jour );

9.  Lancer le projet avec la base de données RUST_LOG=info cargo run --
    --int enp0s8
