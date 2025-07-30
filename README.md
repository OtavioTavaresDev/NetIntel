# NetIntel - Scanner de Rede Local e Wi-Fi

## 🛠️ Funcionalidades

### 1. Escaneamento de Rede LAN/Wi-Fi Local (IP Local)
- Descobre todos os IPs conectados à sua rede local (LAN ou Wi-Fi).
- Para cada IP detectado, realiza:
  - Verificação de hostname (nome do dispositivo).
  - Detecção do endereço MAC (se possível).
  - Escaneamento das portas mais comuns:
    - 21 (FTP)
    - 22 (SSH)
    - 23 (Telnet)
    - 25 (SMTP)
    - 53 (DNS)
    - 80 (HTTP)
    - 110 (POP3)
    - 139 (NetBIOS)
    - 143 (IMAP)
    - 443 (HTTPS)
    - 445 (SMB)
    - 3306 (MySQL)
    - 3389 (RDP)
    - 8080 (HTTP Alternativo)
  - Indica se a porta está **aberta** ou **fechada**.

### 2. Escaneamento de Redes Wi-Fi Próximas (sem fio)
- Lista todas as redes Wi-Fi ao alcance.
- Para cada rede detectada, exibe:
  - SSID (nome da rede)
  - Tipo de autenticação e criptografia
  - Intensidade do sinal (%)
  - Canal utilizado

## 💻 Requisitos
- Python 3.x
- Bibliotecas:
  - `tkinter` (interface gráfica)
  - `socket`, `subprocess`, `platform`, `threading`, `re`, `datetime`, `psutil`

## 🚀 Como Usar
1. Execute o script Python.
2. Utilize a interface para:
   - Escanear dispositivos conectados à sua rede local.
   - Listar redes Wi-Fi próximas.
3. Os resultados serão exibidos no painel inferior com detalhes de IPs e portas.

## 📌 Observações
- O escaneamento de Wi-Fi depende do comando `netsh`, portanto só funciona no **Windows**.
- O escaneamento de portas pode demorar dependendo da quantidade de IPs e do tempo limite.

## 👨‍💻 Desenvolvido por
Otávio Augusto De Souza Tavares. 
