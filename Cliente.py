import socket
import time

MANUAL_KEY = b'COMP'

def checksum(s):
    return sum(ord(c) for c in s) % 256

def manual_encrypt(payload_str):
    padded_payload = payload_str.encode('utf-8')
    key_bytes = MANUAL_KEY
    
    encrypted_bytes = bytearray(4)
    
    for i in range(4):
        encrypted_bytes[i] = padded_payload[i] ^ key_bytes[i]
        
    final_encrypted = bytearray(4)
    final_encrypted[0] = encrypted_bytes[2]
    final_encrypted[1] = encrypted_bytes[3]
    final_encrypted[2] = encrypted_bytes[0]
    final_encrypted[3] = encrypted_bytes[1]
    
    return final_encrypted.hex()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = ("127.0.0.1", 10000)
timeout = 3.0
sock.settimeout(timeout)

while True:
    try:
        maxlen = int(input("Defina o limite máximo de caracteres por mensagem (≥30): ").strip())
        if maxlen < 30:
            print("O limite deve ser no mínimo 30.")
            continue
        break
    except:
        print("Digite um número válido.")

while True:
    modo = input("Escolha o modo de confirmação (gobackn / selecionado): ").strip().lower()
    if modo in ["gobackn", "selecionado"]:
        break
    else:
        print("Entrada inválida. Digite 'gobackn' ou 'selecionado'.")

while True:
    erro_seq_input = input("Digite os números dos pacotes que devem falhar, separados por vírgula (ex: 2,5). Deixe vazio para nenhum: ").strip()
    if erro_seq_input:
        try:
            erro_seq = [int(x) for x in erro_seq_input.split(',')]
            erro_seq_to_apply = set(erro_seq) 
            print(f"Pacotes que terão erro: {erro_seq}")
            break
        except:
            print("Entrada inválida. Digite apenas números separados por vírgula.")
    else:
        erro_seq = []
        erro_seq_to_apply = set()
        print("Nenhum pacote terá erro.")
        break


sock.sendto(f"HELLO|{maxlen}|{modo}".encode('utf-8'), server_addr)
try:
    data, _ = sock.recvfrom(4096)
    parts = data.decode().split('|')
    if parts[0] == "HELLO_ACK":
        window_size = int(parts[1])
        print(f"[CLIENTE] HELLO_ACK recebido. Janela = {window_size}")
    else:
        print("[CLIENTE] Resposta inesperada do servidor. Abortando.")
        exit(1)
except socket.timeout:
    print("[CLIENTE] Sem resposta do servidor. Abortando.")
    exit(1)

while True:
    mensagem = input(f"Digite a mensagem (mín 30, máx {maxlen} chars): ")
    if len(mensagem) > maxlen:
        print(f"Mensagem maior que {maxlen} caracteres. Tente novamente.")
    elif len(mensagem) < 30:
        print("Mensagem menor que 30 caracteres. Tente novamente.")
    else:
        break

frag_size = 4
fragments = [mensagem[i:i+frag_size] for i in range(0, len(mensagem), frag_size)]
total = len(fragments)
print(f"[CLIENTE] Fragmentando em {total} pedaços.")

base = 0
next_seq = 0
acks_received = {}
pending_naks = set()
last_ack_time = {}

while base < total:
    while next_seq < total and next_seq < base + window_size:
        
        payload = fragments[next_seq]
        
        payload_with_padding = payload.ljust(4)
        
        cs = checksum(payload_with_padding)
        
        if next_seq in erro_seq_to_apply:
            cs += 1
            print(f"[{time.strftime('%H:%M:%S')}] Enviado seq={next_seq} payload='{payload}' (erro proposital) checksum={cs}")
            erro_seq_to_apply.remove(next_seq)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Enviado seq={next_seq} payload='{payload}' checksum={cs}")
        
        encrypted_payload = manual_encrypt(payload_with_padding) 
            
        print(f"[{time.strftime('%H:%M:%S')}] Enviado seq={next_seq} (Payload Criptografado) checksum={cs}")
            
        packet = f"DATA|{next_seq}|{total}|{encrypted_payload}|{cs}".encode('utf-8')
        sock.sendto(packet, server_addr)
        acks_received[next_seq] = False
        last_ack_time[next_seq] = time.time()
        next_seq += 1

    try:
        data, _ = sock.recvfrom(4096)
        parts = data.decode().split('|')
        if parts[0] == "ACK":
            ack_num = int(parts[1])
            print(f"[{time.strftime('%H:%M:%S')}] ACK recebido seq={ack_num}")
            
            if ack_num in pending_naks:
                pending_naks.remove(ack_num)
            
            acks_received[ack_num] = True
            
            while base in acks_received and acks_received[base]:
                base += 1

        elif parts[0] == "NAK":
            nak_num = int(parts[1])
            print(f"[{time.strftime('%H:%M:%S')}] NAK recebido seq={nak_num}, retransmitindo")
            
            if modo == "selecionado":
                pending_naks.add(nak_num)
            elif modo == "gobackn":
                if nak_num >= base:
                    base = nak_num
                    next_seq = nak_num
                    for i in range(nak_num, total):
                        acks_received[i] = False
                    
    except socket.timeout:
        if modo == "gobackn":
            if next_seq > base:
                print(f"[{time.strftime('%H:%M:%S')}] Timeout. Retransmitindo a partir da base={base}")
                next_seq = base
        elif modo == "selecionado":
            current_time = time.time()
            for seq in range(base, min(base + window_size, total)):
                if not acks_received.get(seq, False) and (current_time - last_ack_time.get(seq, 0) > timeout):
                    print(f"[{time.strftime('%H:%M:%S')}] Timeout no pacote {seq}. Adicionando para retransmissão.")
                    pending_naks.add(seq)

    if modo == "selecionado":
        temp_naks = sorted(list(pending_naks))
        for nak_num in temp_naks:
            if nak_num >= total: continue
            
            payload = fragments[nak_num]
            payload_with_padding = payload.ljust(4)
            cs = checksum(payload_with_padding)
            
            encrypted_payload = manual_encrypt(payload_with_padding)
            
            print(f"[{time.strftime('%H:%M:%S')}] Retransmitindo seq={nak_num} (Payload Criptografado)")
                
            packet = f"DATA|{nak_num}|{total}|{encrypted_payload}|{cs}".encode('utf-8')
            sock.sendto(packet, server_addr)
            last_ack_time[nak_num] = time.time()

print("[CLIENTE] Todas as partes enviadas e confirmadas.")
sock.close()
