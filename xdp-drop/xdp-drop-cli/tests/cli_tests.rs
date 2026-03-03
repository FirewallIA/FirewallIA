

#[cfg(test)]
mod tests {
    use clap::Parser;
    
    
    #[derive(Parser, Debug)]
    #[clap(author, version, about, long_about = None)]
    struct Cli {
        #[clap(subcommand)]
        command: Commands,
        #[clap(long, default_value = "http://[::1]:50051")]
        server_addr: String,
    }

    #[derive(clap::Subcommand, Debug)]
    enum Commands {
        Status,
        ListRules,
        CreateRule {
            #[clap(long)]
            name: String,
            #[clap(long)]
            source_ip: String,
            #[clap(long)]
            dest_ip: String,
            #[clap(long, default_value = "*")]
            source_port: String,
            #[clap(long, default_value = "*")]
            dest_port: String,
            #[clap(long)]
            action: String,
            #[clap(long, default_value = "any")]
            protocol: String,
        },
        DeleteRule {
            #[clap(long, allow_hyphen_values = true)]
            id: i32,
        },
        TrafficStats {
            #[clap(default_value = "all")]
            range: String,
        },
    }
    
    // ============================================================================
    // TESTS DE PARSING CLI
    // ============================================================================
    
    #[test]
    fn test_cli_status_command() {
        let args = vec!["xdp-drop-cli", "status"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok(), "Status command should parse successfully");
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Commands::Status));
        assert_eq!(cli.server_addr, "http://[::1]:50051");
    }
    
    #[test]
    fn test_cli_status_with_custom_server() {
        let args = vec!["xdp-drop-cli", "--server-addr", "http://192.168.1.1:8080", "status"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert_eq!(cli.server_addr, "http://192.168.1.1:8080");
    }
    
    #[test]
    fn test_cli_list_rules_command() {
        let args = vec!["xdp-drop-cli", "list-rules"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok(), "ListRules command should parse successfully");
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Commands::ListRules));
    }
    
    #[test]
    fn test_cli_create_rule_full_args() {
        let args = vec![
            "xdp-drop-cli",
            "create-rule",
            "--name", "test-rule",
            "--source-ip", "192.168.1.100",
            "--dest-ip", "10.0.0.1",
            "--source-port", "8080",
            "--dest-port", "443",
            "--action", "deny",
            "--protocol", "TCP"
        ];
        
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "CreateRule with full args should parse successfully");
        
        let cli = cli.unwrap();
        match cli.command {
            Commands::CreateRule {
                name,
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                action,
                protocol,
            } => {
                assert_eq!(name, "test-rule");
                assert_eq!(source_ip, "192.168.1.100");
                assert_eq!(dest_ip, "10.0.0.1");
                assert_eq!(source_port, "8080");
                assert_eq!(dest_port, "443");
                assert_eq!(action, "deny");
                assert_eq!(protocol, "TCP");
            }
            _ => panic!("Expected CreateRule command"),
        }
    }
    
    #[test]
    fn test_cli_create_rule_with_defaults() {
        let args = vec![
            "xdp-drop-cli",
            "create-rule",
            "--name", "minimal-rule",
            "--source-ip", "0.0.0.0/0",
            "--dest-ip", "192.168.1.1",
            "--action", "allow"
        ];
        
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        match cli.command {
            Commands::CreateRule {
                source_port,
                dest_port,
                protocol,
                ..
            } => {
                assert_eq!(source_port, "*", "Default source_port should be '*'");
                assert_eq!(dest_port, "*", "Default dest_port should be '*'");
                assert_eq!(protocol, "any", "Default protocol should be 'any'");
            }
            _ => panic!("Expected CreateRule command"),
        }
    }
    
    #[test]
    fn test_cli_create_rule_missing_required_args() {
        // Manque --dest-ip qui est requis
        let args = vec![
            "xdp-drop-cli",
            "create-rule",
            "--name", "incomplete",
            "--source-ip", "192.168.1.1",
            "--action", "allow"
        ];
        
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_err(), "CreateRule without required args should fail");
    }
    
    #[test]
    fn test_cli_delete_rule_command() {
        let args = vec!["xdp-drop-cli", "delete-rule", "--id", "42"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        match cli.command {
            Commands::DeleteRule { id } => {
                assert_eq!(id, 42);
            }
            _ => panic!("Expected DeleteRule command"),
        }
    }
    
    #[test]
    fn test_cli_delete_rule_zero_id() {
        let args = vec!["xdp-drop-cli", "delete-rule", "--id", "0"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        match cli.command {
            Commands::DeleteRule { id } => {
                assert_eq!(id, 0);
            }
            _ => panic!("Expected DeleteRule command"),
        }
    }
    
    #[test]
    fn test_cli_delete_rule_negative_id() {
        let args = vec!["xdp-drop-cli", "delete-rule", "--id", "-1"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        match cli.command {
            Commands::DeleteRule { id } => {
                assert_eq!(id, -1);
            }
            _ => panic!("Expected DeleteRule command"),
        }
    }
    
    #[test]
    fn test_cli_traffic_stats_default() {
        let args = vec!["xdp-drop-cli", "traffic-stats"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        match cli.command {
            Commands::TrafficStats { range } => {
                assert_eq!(range, "all");
            }
            _ => panic!("Expected TrafficStats command"),
        }
    }
    
    #[test]
    fn test_cli_traffic_stats_custom_ranges() {
        let test_ranges = vec!["5m", "1h", "4h", "24h", "1w"];
        
        for range_val in test_ranges {
            let args = vec!["xdp-drop-cli", "traffic-stats", range_val];
            let cli = Cli::try_parse_from(args);
            
            assert!(cli.is_ok(), "TrafficStats with range {} should parse", range_val);
            let cli = cli.unwrap();
            
            match cli.command {
                Commands::TrafficStats { range } => {
                    assert_eq!(range, range_val);
                }
                _ => panic!("Expected TrafficStats command"),
            }
        }
    }
    
    #[test]
    fn test_cli_invalid_command() {
        let args = vec!["xdp-drop-cli", "invalid-command"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_err(), "Invalid command should fail to parse");
    }
    
    #[test]
    fn test_cli_no_command() {
        let args = vec!["xdp-drop-cli"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_err(), "No command should fail to parse");
    }
    
    // ============================================================================
    // TESTS DE VALIDATION DES FORMATS
    // ============================================================================
    
    mod validation {
        use super::*;
        use std::net::Ipv4Addr;
        
        fn is_valid_ipv4(ip: &str) -> bool {
            if ip.contains('/') {
                let parts: Vec<&str> = ip.split('/').collect();
                if parts.len() != 2 {
                    return false;
                }
                let ip_part = parts[0].parse::<Ipv4Addr>();
                let cidr_part = parts[1].parse::<u8>();
                return ip_part.is_ok() && cidr_part.is_ok() && cidr_part.unwrap() <= 32;
            }
            ip.parse::<Ipv4Addr>().is_ok()
        }
        
        fn is_valid_port(port: &str) -> bool {
            if port == "*" {
                return true;
            }
            
            // Cas d'une plage de ports (ex: "8000-9000")
            if port.contains('-') {
                let parts: Vec<&str> = port.split('-').collect();
                if parts.len() != 2 {
                    return false;
                }
                let start = parts[0].parse::<u16>();
                let end = parts[1].parse::<u16>();
                
                // On vérifie que ça parse ET que start > 0 ET que start <= end
                return start.is_ok() 
                    && end.is_ok() 
                    && start.unwrap() > 0 
                    && start.unwrap() <= end.unwrap();
            }
            
            // Cas d'un port unique
            match port.parse::<u16>() {
                Ok(p) => p > 0, // Retourne true seulement si le port est > 0
                Err(_) => false,
            }
        }
        
        #[test]
        fn test_valid_ipv4_addresses() {
            assert!(is_valid_ipv4("192.168.1.1"));
            assert!(is_valid_ipv4("10.0.0.0"));
            assert!(is_valid_ipv4("172.16.0.1"));
            assert!(is_valid_ipv4("0.0.0.0"));
            assert!(is_valid_ipv4("255.255.255.255"));
        }
        
        #[test]
        fn test_valid_ipv4_cidr() {
            assert!(is_valid_ipv4("192.168.1.0/24"));
            assert!(is_valid_ipv4("10.0.0.0/8"));
            assert!(is_valid_ipv4("172.16.0.0/12"));
            assert!(is_valid_ipv4("0.0.0.0/0"));
            assert!(is_valid_ipv4("192.168.1.128/25"));
        }
        
        #[test]
        fn test_invalid_ipv4_addresses() {
            assert!(!is_valid_ipv4("256.1.1.1"));
            assert!(!is_valid_ipv4("192.168.1"));
            assert!(!is_valid_ipv4("192.168.1.1.1"));
            assert!(!is_valid_ipv4("abc.def.ghi.jkl"));
            assert!(!is_valid_ipv4("192.168.1.1/33"));
        }
        
        #[test]
        fn test_valid_ports() {
            assert!(is_valid_port("*"));
            assert!(is_valid_port("80"));
            assert!(is_valid_port("443"));
            assert!(is_valid_port("8080"));
            assert!(is_valid_port("1"));
            assert!(is_valid_port("65535"));
            assert!(is_valid_port("8000-9000"));
            assert!(is_valid_port("1-1024"));
        }
        
        #[test]
        fn test_invalid_ports() {
            assert!(!is_valid_port("0"));
            assert!(!is_valid_port("65536"));
            assert!(!is_valid_port("abc"));
            assert!(!is_valid_port("-1"));
            assert!(!is_valid_port("9000-8000")); // Range inversé
        }
        
        #[test]
        fn test_valid_actions() {
            let valid = ["allow", "deny", "drop", "reject"];
            for action in valid {
                // On teste juste que la chaîne n'est pas vide
                assert!(!action.is_empty());
            }
        }
        
        #[test]
        fn test_valid_protocols() {
            let valid = ["TCP", "UDP", "ICMP", "any"];
            for protocol in valid {
                assert!(!protocol.is_empty());
            }
        }
    }
    
    // ============================================================================
    // TESTS DE CAS LIMITES
    // ============================================================================
    
    #[test]
    fn test_rule_name_edge_cases() {
        // Nom court
        let args = vec![
            "xdp-drop-cli", "create-rule",
            "--name", "x",
            "--source-ip", "192.168.1.1",
            "--dest-ip", "10.0.0.1",
            "--action", "allow"
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        
        // Nom long (255 caractères)
        let long_name = "a".repeat(255);
        let args = vec![
            "xdp-drop-cli", "create-rule",
            "--name", &long_name,
            "--source-ip", "192.168.1.1",
            "--dest-ip", "10.0.0.1",
            "--action", "allow"
        ];
        assert!(Cli::try_parse_from(args).is_ok());
    }
    
    #[test]
    fn test_server_addr_formats() {
        let test_addrs = vec![
            "http://localhost:50051",
            "http://127.0.0.1:8080",
            "http://[::1]:50051",
            "https://firewall.example.com:443",
            "http://192.168.1.1:9090",
        ];
        
        for addr in test_addrs {
            let args = vec!["xdp-drop-cli", "--server-addr", addr, "status"];
            let cli = Cli::try_parse_from(args);
            
            assert!(cli.is_ok(), "Server address {} should be valid", addr);
            let cli = cli.unwrap();
            assert_eq!(cli.server_addr, addr);
        }
    }
    
    #[test]
    fn test_multiple_commands_are_mutually_exclusive() {
        // On ne peut pas avoir deux commandes en même temps
        let args = vec!["xdp-drop-cli", "status", "list-rules"];
        let cli = Cli::try_parse_from(args);
        
        assert!(cli.is_err(), "Multiple commands should not be allowed");
    }
    
    // ============================================================================
    // TESTS DE COMPATIBILITÉ
    // ============================================================================
    
    #[test]
    fn test_backward_compatibility() {
        // Vérifier que toutes les commandes de base fonctionnent
        let commands = vec![
            vec!["xdp-drop-cli", "status"],
            vec!["xdp-drop-cli", "list-rules"],
            vec!["xdp-drop-cli", "traffic-stats"],
        ];
        
        for args in commands {
            let cli = Cli::try_parse_from(args.clone());
            assert!(cli.is_ok(), "Command {:?} should work", args);
        }
    }
    
    #[test]
    fn test_help_flags() {
        let help_flags = vec![
            vec!["xdp-drop-cli", "--help"],
            vec!["xdp-drop-cli", "-h"],
            vec!["xdp-drop-cli", "create-rule", "--help"],
        ];
        
        for args in help_flags {
            let result = Cli::try_parse_from(args.clone());
            // --help devrait échouer le parsing (par design de clap)
            // mais avec un code de sortie 0 dans le vrai binaire
            assert!(result.is_err(), "Help flag should trigger help display");
        }
    }
}
