from flask import Flask, render_template, request
from app.scan import run_nmap, parse_ports_by_state
import os

def create_app():
    app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'APP', 'templates'), static_folder=os.path.join(os.getcwd(), 'APP', 'static'))

    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html")

    @app.route("/scan", methods=["POST"])
    def scan():
        target_ip = request.form.get("target_ip")
        port_select = request.form.get("port_select")
        ranges = request.form.getlist("range")
        scan_mode = request.form.get("scan_mode")

        # Executa o Nmap e retorna o arquivo de saída e um erro, se houver
        output_file, error = run_nmap(target_ip, port_select, ranges, scan_mode)

        if error:
            return render_template("index.html", result=error)

        # Agora, passamos o scan_mode para filtrar os CVEs
        open_ports, closed_ports, cve_list = parse_ports_by_state(output_file, scan_mode)

        # Preparando os resultados para exibição
        result_text = ""
        result_text += f"Portas abertas: {', '.join(open_ports) if open_ports else ''}\n"
        result_text += f"Portas fechadas: {', '.join(closed_ports) if closed_ports else ''}"

        # Se houver CVEs filtrados, adicione-os ao resultado
        if cve_list:
            result_text += f"\nCVEs encontrados:\n"
            result_text += "\n".join(cve_list)

        # Extrair o nome do relatório para exibir no template
        report_name = output_file.split("/")[-1]

        return render_template("index.html", result=result_text, report_name=report_name)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)