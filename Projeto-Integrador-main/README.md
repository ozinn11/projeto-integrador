# Projeto-Integrador
Organizando e começando o flask
 
Ideia para os modos do Scannner - em processo, as portas ainda não foram filtradas.

Nova ideia para outro dia: Mandar para o GPT qualquer XML e pedir um código para extrair os dados. Tratar de correção de erros: Não deixar letras na caixas de ip, separar IP por ",".

Concluido Leitura de Ip Range e Máscara.

Modo Porta Padrão ( Scaneia da porta 0-1024 )

Modo Completo (Full Scan) Escaneia todas as portas e mostra todos os CVES (0-65535)

Modo Web (HTTP/HTTPS) Portas: 80, 443, 8080, 8443, 8000, 8888 e CVES Relacionados a WEB Objetivo: detectar servidores web e serviços relacionados.

Modo Serviços Remotos Portas: 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC) E CVES relacionados a conexão remota

Objetivo: localizar serviços de acesso remoto potencialmente expostos.

Modo Bancos de Dados Portas: 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB) e CVES relacionados a Banco de Dados Ideal para identificar servidores de banco de dados em rede.

Modo Infraestrutura Portas: 21 (FTP), 25 (SMTP), 53 (DNS), 161 (SNMP) CVES de problemas típicos de Infra. Para identificar componentes típicos de infraestruturas de rede.

Modo IoT / Dispositivos Embutidos Portas: 80, 554 (RTSP), 1900 (UPnP), 49152+ (IoT) e Cves de IOTS Detecção de câmeras IP, impressoras, TVs, etc.

Modo Vulnerabilidade Crítica Portas com histórico de CVEs graves: 445 (SMB), 135 (RPC), 389 (LDAP)

Útil para priorizar brechas com impacto conhecido.

Modo Personalizado (avançado) Usuário define uma lista de portas diretamente
OPCIONAIS:

Modo Shadow IT: tenta identificar serviços fora do padrão ou não documentados na rede (ex: servidores HTTP em portas incomuns, etc.).

Modo Discovery Rápido: escaneia só as top 100 portas mais comuns (com base no Nmap ou Shodan).

Modo Pós-Exploração: foca em serviços vulneráveis que são típicos alvos após invasão (ex: SMB, RPC, WinRM).

Modo Compliance (PCI/DSS, LGPD, etc.): verifica exposição de serviços proibidos por regulamentações específicas.