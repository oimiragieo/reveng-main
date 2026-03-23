
def get_translator(lang="en"):
    translations = {
        "en": {
            "description": "REVENG - Universal Reverse Engineering Platform",
            "epilog": "For more information, visit: https://github.com/oimiragieo/reveng-main",
            "version_help": "Show version information and exit",
            "commands_help": "Available commands",
            "lang_help": "Interface language (en, pt-br)",
            
            "analyze_help": "Analyze a binary file",
            "analyze_desc": "Run comprehensive binary analysis on the specified file",
            "binary_path_help": "Path to binary file (auto-detected if not provided)",
            
            "serve_help": "Start web interface server",
            "serve_desc": "Launch the REVENG web interface for interactive analysis",
            "host_help": "Host to bind the server to (default: localhost)",
            "port_help": "Port to bind the server to (default: 3000)",
            "reload_help": "Enable auto-reload for development",
            
            "ask_help": "Ask natural language questions about a binary",
            "ask_desc": "Use AI to answer questions about binary behavior and functionality",
            "question_help": 'Natural language question (e.g., "What does this binary do?")',
            "binary_path_opt_help": "Path to binary file (optional if analysis results provided)",
            "results_help": "Path to previous analysis results JSON file",
            "conversational_help": "Enable conversational mode for follow-up questions",
            
            "ai_help": "AI Assistant for interactive binary analysis",
            "ai_desc": "Start an interactive AI assistant session for comprehensive binary analysis",
            "analysis_type_help": "Type of analysis to perform (default: comprehensive)",
            "goals_help": "Analysis goals (e.g., understand_functionality find_vulnerabilities assess_threats)",
            "interactive_help": "Enable interactive mode for follow-up questions",
            
            "triage_help": "Rapid threat assessment (<30 seconds)",
            "triage_desc": "Perform instant triage analysis for incident response",
            "bulk_help": "Triage multiple files in batch",
            "format_help": "Output format (default: text)",
            
            "vt_lookup_help": "Lookup file hash on VirusTotal",
            "vt_lookup_desc": "Enrich analysis with VirusTotal threat intelligence",
            "api_key_help": "VirusTotal API key (or set VT_API_KEY environment variable)",
            
            "vt_submit_help": "Submit file to VirusTotal for analysis",
            "vt_submit_desc": "Upload binary to VirusTotal and wait for results",
            "wait_help": "Wait for analysis to complete",
            
            "yara_gen_help": "Generate YARA rule from binary",
            "yara_gen_desc": "Create YARA detection rule based on binary characteristics",
            "rule_name_help": "Custom name for YARA rule",
            "output_help": "Path to save output file",
            
            "yara_scan_help": "Scan binary with YARA rules",
            "yara_scan_desc": "Scan binary using YARA rules for threat detection",
            "rules_dir_help": "Directory containing YARA rules",
            "rule_file_help": "Single YARA rule file to scan with",
            
            "diff_help": "Compare two binary versions",
            "diff_desc": "Identify differences between two binary files at function level",
            "deep_help": "Enable deep analysis for detailed comparison",
            
            "patch_help": "Analyze security patches",
            "patch_desc": "Identify vulnerabilities fixed in a security patch",
            "cve_help": "CVE identifier for the patch (optional)",
            
            "packer_help": "Detect if binary is packed",
            "packer_desc": "Identify packer/obfuscator used on binary",
            
            "unpack_help": "Unpack packed binary",
            "unpack_desc": "Attempt to unpack/decompress packed binary",
            "method_help": "Unpacking method (default: auto)",
            
            "enhance_help": "Improve decompiled code quality with AI",
            "enhance_desc": "Transform raw decompiled code into readable, documented code",
            "func_name_help": "Name of the function being enhanced",
            
            "recompile_help": "Binary \u2192 Source \u2192 Binary reconstruction pipeline",
            "recompile_desc": "Prove vulnerabilities through complete binary reconstruction",
            "ghidra_url_help": "Ghidra server URL (default: http://127.0.0.1:13370)",
            "no_gemini_help": "Disable Gemini AI enhancement",
            "no_exploits_help": "Skip exploit generation",
            
            "decompile_help": "Decompile binary to source code",
            "decompile_desc": "Extract source code from binary using Ghidra + AI enhancement",
            "lang_out_help": "Output language (default: c)",
            "enhance_opt_help": "Apply AI enhancement to improve code quality",
            
            "exploit_help": "Generate proof-of-concept exploit",
            "exploit_desc": "Automatically generate working exploits for discovered vulnerabilities",
            "vuln_help": "Specific vulnerability to target",
            
            "enhanced_group": "Enhanced Analysis Options",
            "enhanced_group_desc": "Control AI-enhanced analysis modules",
            "no_enhanced_help": "Disable all enhanced analysis modules",
            "no_corporate_help": "Disable corporate exposure analysis",
            "no_vuln_help": "Disable vulnerability discovery",
            "no_threat_help": "Disable threat intelligence correlation",
            "no_recon_help": "Disable enhanced binary reconstruction",
            "no_demo_help": "Disable demonstration generation",
            
            "config_group": "Configuration Options",
            "config_group_desc": "Control analysis configuration",
            "config_help": "Path to enhanced analysis configuration file",
            "no_ollama_help": "Skip Ollama availability check",
            "out_dir_help": "Directory to save analysis results",
            
            "logging_group": "Logging Options",
            "logging_group_desc": "Control logging and output verbosity",
            "verbose_help": "Enable verbose output",
            "quiet_help": "Suppress non-essential output",
            "log_file_help": "Path to log file",
            
            "success": "[SUCCESS] REVENG analysis completed successfully!",
            "error": "[ERROR] REVENG analysis failed!",
            "bin_not_found": "Error: Binary not found",
            "usage": "Usage",
        },
        "pt-br": {
            "description": "REVENG - Plataforma Universal de Engenharia Reversa",
            "epilog": "Para mais informações, visite: https://github.com/oimiragieo/reveng-main",
            "version_help": "Mostrar informações da versão e sair",
            "commands_help": "Comandos disponíveis",
            "lang_help": "Idioma da interface (en, pt-br)",
            
            "analyze_help": "Analisar um arquivo binário",
            "analyze_desc": "Executar análise binária abrangente no arquivo especificado",
            "binary_path_help": "Caminho para o arquivo binário (auto-detectado se não fornecido)",
            
            "serve_help": "Iniciar servidor da interface web",
            "serve_desc": "Lançar a interface web REVENG para análise interativa",
            "host_help": "Host para vincular o servidor (padrão: localhost)",
            "port_help": "Porta para vincular o servidor (padrão: 3000)",
            "reload_help": "Habilitar recarregamento automático para desenvolvimento",
            
            "ask_help": "Fazer perguntas em linguagem natural sobre um binário",
            "ask_desc": "Usar IA para responder perguntas sobre o comportamento e funcionalidade do binário",
            "question_help": 'Pergunta em linguagem natural (ex: "O que este binário faz?")',
            "binary_path_opt_help": "Caminho para o arquivo binário (opcional se resultados da análise forem fornecidos)",
            "results_help": "Caminho para o arquivo JSON de resultados de análise anterior",
            "conversational_help": "Habilitar modo conversacional para perguntas de acompanhamento",
            
            "ai_help": "Assistente de IA para análise binária interativa",
            "ai_desc": "Iniciar uma sessão interativa de assistente de IA para análise binária abrangente",
            "analysis_type_help": "Tipo de análise a ser executada (padrão: abrangente)",
            "goals_help": "Objetivos da análise (ex: understand_functionality find_vulnerabilities assess_threats)",
            "interactive_help": "Habilitar modo interativo para perguntas de acompanhamento",
            
            "triage_help": "Avaliação rápida de ameaças (<30 segundos)",
            "triage_desc": "Executar análise de triagem instantânea para resposta a incidentes",
            "bulk_help": "Triagem de vários arquivos em lote",
            "format_help": "Formato de saída (padrão: text)",
            
            "vt_lookup_help": "Consultar hash do arquivo no VirusTotal",
            "vt_lookup_desc": "Enriquecer a análise com inteligência de ameaças do VirusTotal",
            "api_key_help": "Chave de API do VirusTotal (ou defina a variável de ambiente VT_API_KEY)",
            
            "vt_submit_help": "Enviar arquivo ao VirusTotal para análise",
            "vt_submit_desc": "Enviar binário para o VirusTotal e aguardar os resultados",
            "wait_help": "Aguardar a conclusão da análise",
            
            "yara_gen_help": "Gerar regra YARA a partir do binário",
            "yara_gen_desc": "Criar regra de detecção YARA baseada nas características do binário",
            "rule_name_help": "Nome personalizado para a regra YARA",
            "output_help": "Caminho para salvar o arquivo de saída",
            
            "yara_scan_help": "Escanear binário com regras YARA",
            "yara_scan_desc": "Escanear binário usando regras YARA para detecção de ameaças",
            "rules_dir_help": "Diretório contendo regras YARA",
            "rule_file_help": "Arquivo de regra YARA único para escanear",
            
            "diff_help": "Comparar duas versões de binários",
            "diff_desc": "Identificar diferenças entre dois arquivos binários em nível de função",
            "deep_help": "Habilitar análise profunda para comparação detalhada",
            
            "patch_help": "Analisar patches de segurança",
            "patch_desc": "Identificar vulnerabilidades corrigidas em um patch de segurança",
            "cve_help": "Identificador CVE para o patch (opcional)",
            
            "packer_help": "Detectar se o binário está compactado (packed)",
            "packer_desc": "Identificar packer/ofuscador usado no binário",
            
            "unpack_help": "Descompactar binário compactado",
            "unpack_desc": "Tentar descompactar/descomprimir binário compactado",
            "method_help": "Método de descompactação (padrão: auto)",
            
            "enhance_help": "Melhorar qualidade do código descompilado com IA",
            "enhance_desc": "Transformar código descompilado bruto em código legível e documentado",
            "func_name_help": "Nome da função sendo aprimorada",
            
            "recompile_help": "Pipeline de reconstrução Binário \u2192 Fonte \u2192 Binário",
            "recompile_desc": "Provar vulnerabilidades através da reconstrução binária completa",
            "ghidra_url_help": "URL do servidor Ghidra (padrão: http://127.0.0.1:13370)",
            "no_gemini_help": "Desabilitar aprimoramento Gemini AI",
            "no_exploits_help": "Pular geração de exploits",
            
            "decompile_help": "Descompilar binário para código-fonte",
            "decompile_desc": "Extrair código-fonte do binário usando Ghidra + aprimoramento de IA",
            "lang_out_help": "Linguagem de saída (padrão: c)",
            "enhance_opt_help": "Aplicar aprimoramento de IA para melhorar a qualidade do código",
            
            "exploit_help": "Gerar exploit de prova de conceito",
            "exploit_desc": "Gerar automaticamente exploits funcionais para vulnerabilidades descobertas",
            "vuln_help": "Vulnerabilidade específica para atingir",
            
            "enhanced_group": "Opções de Análise Aprimorada",
            "enhanced_group_desc": "Controlar módulos de análise aprimorados por IA",
            "no_enhanced_help": "Desabilitar todos os módulos de análise aprimorados",
            "no_corporate_help": "Desabilitar análise de exposição corporativa",
            "no_vuln_help": "Desabilitar descoberta de vulnerabilidades",
            "no_threat_help": "Desabilitar correlação de inteligência de ameaças",
            "no_recon_help": "Desabilitar reconstrução binária aprimorada",
            "no_demo_help": "Desabilitar geração de demonstração",
            
            "config_group": "Opções de Configuração",
            "config_group_desc": "Controlar configuração da análise",
            "config_help": "Caminho para o arquivo de configuração de análise aprimorada",
            "no_ollama_help": "Pular verificação de disponibilidade do Ollama",
            "out_dir_help": "Diretório para salvar resultados da análise",
            
            "logging_group": "Opções de Log",
            "logging_group_desc": "Controlar log e verbosidade da saída",
            "verbose_help": "Habilitar saída detalhada",
            "quiet_help": "Suprimir saída não essencial",
            "log_file_help": "Caminho para o arquivo de log",
            
            "success": "[SUCESSO] Análise REVENG concluída com sucesso!",
            "error": "[ERRO] Análise REVENG falhou!",
            "bin_not_found": "Erro: Binário não encontrado",
            "usage": "Uso",
        }
    }
    return translations.get(lang.lower(), translations["en"])
