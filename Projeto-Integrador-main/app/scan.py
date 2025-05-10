import subprocess
import datetime
import os
import xml.etree.ElementTree as ET

# Definindo as categorias de CVEs com base nos modos de escaneamento
CVE_CATEGORIES = {
    "web": ["80", "443", "8080", "8000", "8443", "8888", "10000", "10443", "2082", "2083", "2095", "2096", "3000", "4200", "5601", "8081", "9000", "9090"],
    "ssh": ["22"],
    "ftp": ["21"],
    "smtp": ["25"],
    "mysql": ["3306"],
    "postgresql": ["5432"],
    "mssql": ["1433"],
    "oracle": ["1521"],
    "dns": ["53"],
    "snmp": ["161"],
    "vnc": ["5900"],
    # Você pode adicionar mais categorias conforme necessário...
}

def run_nmap(target_ip, port_select=None, ranges=None, scan_mode=None):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_dir = "relatorios"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"nmap_report_{target_ip}_{timestamp}.xml")

    modos = {
        "0": ["0-1024"],  # Porta Padrão
        "1": ["0-65535"],  # Completo
        "2": ["80", "443", "8080", "8000", "8443", "8888", "10000", "10443", "2082", "2083", "2095", "2096", "3000", "4200", "5601", "8081", "9000", "9090"],  # Web
        "3": ["22", "23", "3389"],  # Serviços Remotos (SSH, Telnet, RDP)
        "4": ["3306", "5432", "1433", "1521"],  # Bancos de Dados (MySQL, PostgreSQL, MSSQL, MongoDB)
        "5": ["21", "25", "53", "161"],  # Infraestrutura (FTP, SMTP, DNS, SNMP)
        "6": ["81", "82", "554", "5000", "1900"],  # IoT (Gerais)
        "7": ["135", "139", "445", "5985", "5900", "8009"],  # Vulnerabilidades críticas (NetBios, RPC, SMB, WinRM, VNC)
    }

    ports = []

    # Se um scan_mode foi passado, filtra as portas conforme o modo
    if scan_mode and scan_mode in modos:
        ports += modos[scan_mode]

    if port_select:
        ports.append(str(port_select))

    if ranges:
        ports += ranges

    port_arg = ','.join(ports) if ports else None

    command = ['nmap', '-sS', '-sV', '--script=vuln']
    if port_arg:
        command += ['-p', port_arg]
    command += ['-oX', output_file, target_ip]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            return None, f"Erro no Nmap: {result.stderr}"
        return output_file, None
    except Exception as e:
        return None, str(e)

def parse_ports_by_state(output_file, scan_mode=None):
    try:
        tree = ET.parse(output_file)
        root = tree.getroot()

        open_ports = []
        closed_ports = []
        cve_list = []  # Para armazenar CVEs encontrados

        # Iterando sobre os hosts e suas portas
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None:
                    port_id = port.get('portid')
                    
                    # Verificando o estado da porta (aberta ou fechada)
                    if state.get('state') == 'open':
                        open_ports.append(port_id)
                    elif state.get('state') == 'closed':
                        closed_ports.append(port_id)

                    # Filtrar CVEs com base no scan_mode
                    if scan_mode:
                        # Verificar se a porta está dentro da categoria relevante para o modo selecionado
                        if port_id in CVE_CATEGORIES.get(scan_mode, []):
                            # Buscar CVEs específicos da porta (script vuln do Nmap)
                            for cve in port.findall('.//script[@id="vuln"]/text()'):
                                cve_list.append(cve.text)

        return open_ports, closed_ports, cve_list
    except Exception:
        return [], [], []

