import socket, time

MANUAL_KEY = b'COMP' 

def checksum(s):
    return sum(ord(c) for c in s) % 256

def manual_decrypt(encrypted_hex):
    encrypted_bytes = bytearray.fromhex(encrypted_hex)
    key_bytes = MANUAL_KEY
    
    decrypted_substitution = bytearray(4)
    decrypted_substitution[0] = encrypted_bytes[2]
    decrypted_substitution[1] = encrypted_bytes[3]
    decrypted_substitution[2] = encrypted_bytes[0]
    decrypted_substitution[3] = encrypted_bytes[1]
    
    original_bytes = bytearray(4)
    for i in range(4):
        original_bytes[i] = decrypted_substitution[i] ^ key_bytes[i]
        
    return original_bytes.decode('utf-8') 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10000))
print("[SERVIDOR] ouvindo em 0.0.0.0:10000")

clients_state = {}
window_size = 5

while True:
    data, addr = sock.recvfrom(4096)
    arrival = time.strftime('%H:%M:%S')
    try:
        parts = data.decode().split('|')
    except:
        print(f"[{arrival}] Pacote inválido recebido de {addr}")
        sock.sendto(b"NAK", addr)
        continue

    if parts[0] == "HELLO":
        try:
            maxlen = int(parts[1])
            modo = parts[2] 
        except Exception as e:
            maxlen = None
            modo = "gobackn"
        
        print(f"[{arrival}] HELLO de {addr} - MAXLEN={maxlen} - MODO={modo}")
        sock.sendto(f"HELLO_ACK|{window_size}".encode(), addr)
        clients_state[addr] = {'total': None, 'received': {}, 'expected_seq': 0, 'modo': modo}
        continue

    if parts[0] == "DATA":
        if len(parts) < 5:
            print(f"[{arrival}] Pacote DATA mal formatado de {addr}: {parts}")
            sock.sendto(b"NAK", addr)
            continue

        if addr not in clients_state:
            clients_state[addr] = {'total': None, 'received': {}, 'expected_seq': 0, 'modo': 'gobackn'}

        try:
            seq_num = int(parts[1])
            total = int(parts[2])
            encrypted_payload = parts[3]
            recv_cs = int(parts[4])
        except:
            print(f"[{arrival}] Erro ao parsear pacote DATA de {addr}: {parts}")
            sock.sendto(f"NAK|{parts[1] if len(parts)>1 else '?'}".encode(), addr)
            continue
            
        try:
            payload_with_padding = manual_decrypt(encrypted_payload)
        except Exception as e:
            print(f"[{arrival}] Erro de Descriptografia/Formato no seq={seq_num}. Enviando NAK.")
            sock.sendto(f"NAK|{seq_num}".encode(), addr)
            continue

        calc_cs = checksum(payload_with_padding)
        
        if calc_cs != recv_cs:
            print(f"[{arrival}] Erro de checksum no seq={seq_num}: esperado {calc_cs}, recebido {recv_cs}")
            sock.sendto(f"NAK|{seq_num}".encode(), addr)
            continue

        payload = payload_with_padding.rstrip(' ') 
        state = clients_state[addr]
        
        if state['modo'] == 'gobackn':
            if seq_num == state['expected_seq']:
                print(f"[{arrival}] Recebido seq={seq_num} payload='{payload}' checksum OK (GBN - Ordem Correta)")
                if state['total'] is None: state['total'] = total
                state['received'][seq_num] = payload
                state['expected_seq'] += 1
                
                while state['expected_seq'] in state['received']:
                    state['expected_seq'] += 1
                
                ack = f"ACK|{seq_num}".encode('utf-8')
                sock.sendto(ack, addr)
                print(f"[{arrival}] Reconhecimento positivo enviado seq={seq_num} (ACK)")
                
            elif seq_num < state['expected_seq']:
                print(f"[{arrival}] Recebido seq={seq_num} (Duplicado GBN). Reenviando ACK.")
                ack = f"ACK|{seq_num}".encode('utf-8')
                sock.sendto(ack, addr)
            else:
                print(f"[{arrival}] Recebido seq={seq_num} (Fora de Ordem GBN). Descartando e enviando NAK para {state['expected_seq']}.")
                nak = f"NAK|{state['expected_seq']}".encode('utf-8')
                sock.sendto(nak, addr)

        elif state['modo'] == 'selecionado':
            print(f"[{arrival}] Recebido seq={seq_num} payload='{payload}' checksum OK (Selective Repeat)")
            
            if state['total'] is None: state['total'] = total

            if seq_num not in state['received']:
                state['received'][seq_num] = payload

            ack = f"ACK|{seq_num}".encode('utf-8')
            sock.sendto(ack, addr)
            print(f"[{arrival}] Reconhecimento positivo enviado seq={seq_num} (ACK)")
        
        if state['total'] is not None and len(state['received']) == state['total']:
            full_message = "".join(state['received'][i] for i in range(state['total']))
            print("="*40)
            print(f"[{time.strftime('%H:%M:%S')}] MENSAGEM COMPLETA de {addr}:")
            print(full_message)
            print("="*40)
            clients_state[addr] = {'total': None, 'received': {}, 'expected_seq': 0, 'modo': state['modo']}
        continue

    print(f"[{arrival}] Pacote desconhecido de {addr}: {parts[0]}")
    sock.sendto(b"NAK", addr)
