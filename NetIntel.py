import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import subprocess
import threading
import re
import datetime
import os
import ipaddress
import platform

class NetIntelScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("NetIntel - Scanner Avançado de Rede")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Variáveis para armazenar resultados
        self.report = []
        self.wifi_report = []
        
        # Configuração de estilo
        self.style = ttk.Style()
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', padding=(10, 5), font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=5)
        
        # Criação das abas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Aba 1: Rede Wi-Fi
        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text='Rede Wi-Fi')
        
        # Aba 2: Redes Wi-Fi próximas
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text='Redes Wi-Fi Próximas')
        
        # Configuração da Aba 1
        self.setup_tab1()
        
        # Configuração da Aba 2
        self.setup_tab2()
        
        # Barra de status
        self.status_var = tk.StringVar()
        self.status_var.set("Pronto")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_tab1(self):
        # Frame de botões
        btn_frame = ttk.Frame(self.tab1)
        btn_frame.pack(pady=10, padx=10, fill=tk.X)
        
        # Botões
        ttk.Button(btn_frame, text="Informações de Rede", 
                  command=self.show_network_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Iniciar Varredura Completa", 
                  command=lambda: threading.Thread(target=self.scan_network).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exportar Relatório", 
                  command=self.export_report).pack(side=tk.LEFT, padx=5)
        
        # Área de saída
        self.output_text = scrolledtext.ScrolledText(
            self.tab1, 
            wrap=tk.WORD,
            width=120,
            height=30,
            font=('Consolas', 9),
            bg="#2c2c2c",
            fg="#ffffff"
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.output_text.insert(tk.END, "Clique em 'Iniciar Varredura Completa' para começar.\n")
    
    def setup_tab2(self):
        # Frame de botões
        btn_frame = ttk.Frame(self.tab2)
        btn_frame.pack(pady=10, padx=10, fill=tk.X)
        
        # Botões
        ttk.Button(btn_frame, text="Buscar Redes Wi-Fi", 
                  command=lambda: threading.Thread(target=self.scan_wifi_networks).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exportar Relatório Wi-Fi", 
                  command=self.export_wifi_report).pack(side=tk.LEFT, padx=5)
        
        # Área de saída
        self.wifi_output = scrolledtext.ScrolledText(
            self.tab2, 
            wrap=tk.WORD,
            width=120,
            height=30,
            font=('Consolas', 9),
            bg="#2c2c2c",
            fg="#ffffff"
        )
        self.wifi_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.wifi_output.insert(tk.END, "Clique em 'Buscar Redes Wi-Fi' para listar redes próximas.\n")
    
    def get_local_ip(self):
        """Obtém o IP local de forma confiável usando uma conexão UDP"""
        try:
            # Cria um socket UDP e conecta a um servidor externo (não envia dados)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback para localhost
    
    def get_wifi_gateway(self):
        """Obtém o gateway do Wi-Fi usando comandos do sistema"""
        try:
            if platform.system() == "Windows":
                # Comando para Windows
                result = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.PIPE)
                
                # Encontra a seção do adaptador Wi-Fi
                wifi_section = None
                sections = result.split("\n\n")
                for section in sections:
                    if "Adaptador de Rede sem Fio Wi-Fi" in section:
                        wifi_section = section
                        break
                
                if wifi_section:
                    # Procura pelo gateway na seção do Wi-Fi
                    match = re.search(r"Gateway Padr.o[ .]*: (\d+\.\d+\.\d+\.\d+)", wifi_section, re.IGNORECASE)
                    if match:
                        return match.group(1)
                
                # Se não encontrou no Wi-Fi, tenta encontrar qualquer gateway
                match = re.search(r"Gateway Padr.o[ .]*: (\d+\.\d+\.\d+\.\d+)", result, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            elif platform.system() == "Linux":
                # Comando para Linux
                result = subprocess.check_output("ip route show default", shell=True, text=True, stderr=subprocess.PIPE)
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result)
                if match:
                    return match.group(1)
            
            return "Não encontrado"
        except Exception as e:
            return f"Erro: {str(e)}"
    
    def get_mac_address(self, ip):
        """Obtém o endereço MAC para um IP específico"""
        try:
            if platform.system() == "Windows":
                arp_result = subprocess.check_output(f"arp -a {ip}", shell=True, text=True, stderr=subprocess.PIPE)
                match = re.search(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", arp_result)
                if match:
                    return match.group(0)
            else:
                arp_result = subprocess.check_output(f"arp -n {ip}", shell=True, text=True, stderr=subprocess.PIPE)
                match = re.search(r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", arp_result)
                if match:
                    return match.group(0)
            return "Não disponível"
        except:
            return "Erro ao obter MAC"
    
    def scan_port(self, ip, port):
        """Verifica se uma porta está aberta em um IP específico"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def scan_host(self, ip, results, lock):
        """Escaneia um host individual para verificar portas abertas e informações"""
        try:
            # Verifica se o host está ativo
            param = '-n' if platform.system() == 'Windows' else '-c'
            command = ['ping', param, '1', '-w', '1', ip]
            ping_result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if ping_result.returncode != 0:
                with lock:
                    results[ip] = {'status': 'inactive'}
                return
            
            # Obtém informações do host
            hostname = "Desconhecido"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            mac = self.get_mac_address(ip)
            
            # Lista de portas para verificar
            ports_to_scan = [
                21,    # FTP
                22,    # SSH
                23,    # Telnet
                25,    # SMTP
                53,    # DNS
                80,    # HTTP
                110,   # POP3
                139,   # NetBIOS
                143,   # IMAP
                443,   # HTTPS
                445,   # SMB
                3389,  # RDP
                8080   # HTTP Proxy
            ]
            
            # Verifica as portas
            open_ports = []
            for port in ports_to_scan:
                if self.scan_port(ip, port):
                    open_ports.append(port)
            
            with lock:
                results[ip] = {
                    'hostname': hostname,
                    'mac': mac,
                    'open_ports': open_ports,
                    'status': 'active'
                }
        except Exception as e:
            with lock:
                results[ip] = {'error': str(e)}
    
    def show_network_info(self):
        """Exibe informações básicas de rede - IP local e gateway do Wi-Fi"""
        self.output_text.delete(1.0, tk.END)
        local_ip = self.get_local_ip()
        wifi_gateway = self.get_wifi_gateway()
        
        self.output_text.insert(tk.END, f"{'='*30} INFORMAÇÕES DE REDE {'='*30}\n", "header")
        self.output_text.insert(tk.END, f"IP Local: {local_ip}\n")
        self.output_text.insert(tk.END, f"Gateway do Wi-Fi: {wifi_gateway}\n")
        self.output_text.insert(tk.END, f"{'-'*80}\n")
        
        # Adiciona formatação
        self.output_text.tag_configure("header", foreground="#4fc3f7", font=('Consolas', 10, 'bold'))
    
    def scan_network(self):
        """Executa uma varredura completa na rede local"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Iniciando varredura de rede...\n", "info")
        self.output_text.update()
        
        self.report = []
        local_ip = self.get_local_ip()
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
        wifi_gateway = self.get_wifi_gateway()
        
        self.output_text.insert(tk.END, f"Escaneando rede: {subnet}\n")
        self.output_text.insert(tk.END, f"Gateway: {wifi_gateway}\n\n")
        self.output_text.update()
        
        # Cria lista de IPs
        network = ipaddress.ip_network(subnet, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        
        # Dicionário para resultados
        results = {}
        lock = threading.Lock()
        
        # Cria e inicia threads
        threads = []
        for ip in ips:
            t = threading.Thread(target=self.scan_host, args=(ip, results, lock))
            t.start()
            threads.append(t)
            
            # Limita o número de threads simultâneas
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Espera threads restantes
        for t in threads:
            t.join()
        
        # Processa resultados
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"{'='*30} RESULTADOS DA VARREDURA {'='*30}\n", "header")
        self.output_text.insert(tk.END, f"{'IP':16} {'Hostname':25} {'MAC Address':20} {'Portas Abertas'}\n", "subheader")
        self.output_text.insert(tk.END, f"{'-'*80}\n")
        
        # Formatação
        self.output_text.tag_configure("header", foreground="#4fc3f7", font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("subheader", foreground="#81c784", font=('Consolas', 9, 'bold'))
        
        # Ordena os IPs para exibição
        sorted_ips = sorted(results.keys(), key=lambda ip: [int(part) for part in ip.split('.')])
        
        for ip in sorted_ips:
            data = results[ip]
            
            if 'error' in data:
                self.output_text.insert(tk.END, f"{ip}: Erro - {data['error']}\n", "error")
                self.report.append(f"{ip}: Erro - {data['error']}")
            elif data['status'] == 'inactive':
                self.output_text.insert(tk.END, f"{ip:16} {'-':25} {'-':20} Inativo\n")
                self.report.append(f"{ip:16} | - | - | Inativo")
            else:
                ports = ', '.join(map(str, data['open_ports'])) if data['open_ports'] else "Nenhuma"
                self.output_text.insert(tk.END, 
                                      f"{ip:16} {data['hostname'][:24]:25} {data['mac'][:18]:20} {ports}\n")
                self.report.append(f"{ip:16} | {data['hostname']} | {data['mac']} | Portas: {ports}")
        
        active_hosts = len([ip for ip in results if 'status' in results[ip] and results[ip]['status'] == 'active'])
        self.output_text.insert(tk.END, f"\nVarredura concluída! Hosts encontrados: {active_hosts}\n", "info")
        self.output_text.tag_configure("info", foreground="#ffb74d")
        self.output_text.tag_configure("error", foreground="#e57373")
    
    def scan_wifi_networks(self):
        """Busca redes Wi-Fi próximas (funciona apenas no Windows)"""
        self.wifi_output.delete(1.0, tk.END)
        
        if platform.system() != "Windows":
            self.wifi_output.insert(tk.END, "Esta funcionalidade está disponível apenas no Windows.\n", "error")
            self.wifi_output.tag_configure("error", foreground="#e57373")
            return
        
        self.wifi_output.insert(tk.END, "Buscando redes Wi-Fi...\n", "info")
        self.wifi_output.update()
        
        try:
            # Executa o comando para listar redes Wi-Fi
            result = subprocess.check_output(
                "netsh wlan show networks mode=Bssid", 
                shell=True, 
                encoding='cp850',  # Codificação para português do Windows
                errors='ignore'
            )
            
            self.wifi_report = []
            current_ssid = None
            
            # Processa a saída do comando
            for line in result.splitlines():
                if "SSID" in line and ":" in line and "BSSID" not in line:
                    # Encontrou um novo SSID
                    current_ssid = line.split(":")[1].strip()
                    self.wifi_report.append({
                        "SSID": current_ssid,
                        "Signal": "",
                        "Authentication": "",
                        "Encryption": ""
                    })
                elif current_ssid:
                    if "Sinal" in line or "Signal" in line:
                        signal = line.split(":")[1].strip()
                        self.wifi_report[-1]["Signal"] = signal
                    elif "Autenticação" in line or "Authentication" in line:
                        auth = line.split(":")[1].strip()
                        self.wifi_report[-1]["Authentication"] = auth
                    elif "Criptografia" in line or "Encryption" in line:
                        enc = line.split(":")[1].strip()
                        self.wifi_report[-1]["Encryption"] = enc
            
            # Exibe os resultados
            self.wifi_output.delete(1.0, tk.END)
            self.wifi_output.insert(tk.END, f"{'='*30} REDES WI-FI DETECTADAS {'='*30}\n", "header")
            self.wifi_output.insert(tk.END, f"{'SSID':30} {'Sinal':15} {'Autenticação':20} {'Criptografia'}\n", "subheader")
            self.wifi_output.insert(tk.END, f"{'-'*90}\n")
            
            # Formatação
            self.wifi_output.tag_configure("header", foreground="#4fc3f7", font=('Consolas', 10, 'bold'))
            self.wifi_output.tag_configure("subheader", foreground="#81c784", font=('Consolas', 9, 'bold'))
            self.wifi_output.tag_configure("info", foreground="#ffb74d")
            
            for network in self.wifi_report:
                self.wifi_output.insert(tk.END, 
                                      f"{network['SSID'][:29]:30} {network['Signal']:15} "
                                      f"{network['Authentication'][:19]:20} {network['Encryption']}\n")
            
            self.wifi_output.insert(tk.END, f"\nTotal de redes encontradas: {len(self.wifi_report)}\n", "info")
            
        except Exception as e:
            self.wifi_output.insert(tk.END, f"Erro ao buscar redes Wi-Fi: {e}\n", "error")
            self.wifi_output.tag_configure("error", foreground="#e57373")
    
    def export_report(self):
        """Exporta o relatório de varredura de rede para arquivo"""
        if not self.report:
            messagebox.showwarning("Sem dados", "Execute uma varredura primeiro para gerar o relatório.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivo de Texto", "*.txt"), ("Todos os arquivos", "*.*")],
            title="Salvar Relatório de Varredura"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write("="*80 + "\n")
                file.write("NetIntel - Relatório de Varredura de Rede\n")
                file.write("="*80 + "\n\n")
                file.write(f"Data/Hora: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write(f"IP Local: {self.get_local_ip()}\n")
                file.write(f"Gateway Wi-Fi: {self.get_wifi_gateway()}\n\n")
                file.write(f"{'IP':16} {'Hostname':25} {'MAC Address':20} {'Portas Abertas'}\n")
                file.write("-"*80 + "\n")
                
                for line in self.report:
                    file.write(line + "\n")
                
                file.write("\n" + "="*80 + "\n")
                file.write("Fim do relatório\n")
            
            messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar o relatório:\n{str(e)}")
    
    def export_wifi_report(self):
        """Exporta o relatório de redes Wi-Fi para arquivo"""
        if not self.wifi_report:
            messagebox.showwarning("Sem dados", "Busque redes Wi-Fi primeiro para gerar o relatório.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivo de Texto", "*.txt"), ("Todos os arquivos", "*.*")],
            title="Salvar Relatório Wi-Fi"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write("="*80 + "\n")
                file.write("NetIntel - Relatório de Redes Wi-Fi\n")
                file.write("="*80 + "\n\n")
                file.write(f"Data/Hora: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write(f"Dispositivo: {platform.node()}\n")
                file.write(f"Gateway Wi-Fi: {self.get_wifi_gateway()}\n\n")
                file.write(f"{'SSID':30} {'Sinal':15} {'Autenticação':20} {'Criptografia'}\n")
                file.write("-"*90 + "\n")
                
                for network in self.wifi_report:
                    file.write(f"{network['SSID']:30} {network['Signal']:15} "
                              f"{network['Authentication']:20} {network['Encryption']}\n")
                
                file.write("\n" + "="*80 + "\n")
                file.write(f"Total de redes: {len(self.wifi_report)}\n")
            
            messagebox.showinfo("Sucesso", f"Relatório Wi-Fi salvo em:\n{filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar o relatório Wi-Fi:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetIntelScanner(root)
    root.mainloop()