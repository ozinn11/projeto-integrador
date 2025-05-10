from flask import Blueprint, render_template, request
from app.scan import run_nmap, show_open_ports

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/scan', methods=['POST'])
def scan():
    target_ip = request.form.get('target_ip').strip()

    if not target_ip:
        return render_template('index.html', error="Por favor, forneça um IP válido.")
    
    output_file, error = run_nmap(target_ip)

    if error:
        return render_template('index.html', error=error)
    
    open_ports = show_open_ports(output_file)

    return render_template('index.html', output_file=output_file, open_ports=open_ports)
