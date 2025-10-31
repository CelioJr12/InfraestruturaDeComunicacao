"""
Servidor.py

- Handshake: aceita escolha do cliente:
    Cliente -> "REQ:<modo>:<min>-<max>", onde <modo> ∈ {"GBN", "SR"}
    Servidor -> "OK:<modo>:<min>-<max>:W<window>:M<ack_mode>"
      * window ∈ [1..5]; ack_mode=1 (GBN) | 0 (SR)

- Implementa recepção confiável na camada de aplicação:
    * CRC32 (NACK em caso de corrupção)
    * GBN (ACK cumulativo, descarta fora-de-ordem; FIX: NACK(expected_seq) se ainda não há in-order)
    * SR  (ACK individual, buffer fora-de-ordem, entrega em ordem)

- Injeção de falhas no servidor (opcional, para testes) permanece disponível:
    DROP_SEQS, CORRUPT_SEQS, DELAY_ACK_SEQS

- Logs verbosos para demonstrar batches, timers e ACKs.

Execução:
    python Servidor.py [HOST] [PORT]
"""

import socket
import struct
import zlib
import time
import sys

HOST = sys.argv[1] if len(sys.argv) >= 2 else '127.0.0.1'
try:
    PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 65432
except ValueError:
    PORT = 65432

HDR_DATA_FMT = '!cH H B B I'  
HDR_DATA_SIZE = struct.calcsize(HDR_DATA_FMT)

HDR_ACK_FMT = '!cH B B'      
HDR_ACK_SIZE = struct.calcsize(HDR_ACK_FMT)

ACK_OK   = b'K'
ACK_NACK = b'N'
DATA_TYPE = b'D'
FLAG_LAST = 0x01

# --------------------- Config do servidor ---------------------
WINDOW_SIZE = 5        # 1..5 (pode alterar em tempo de execução se quiser demonstrar janela dinâmica)
ACK_MODE    = 1        # default; será substituído pelo pedido do cliente (1=GBN, 0=SR)

# --------------------- Injeção de falhas (opcional) ---------------------
# Exemplos:
#   DROP_SEQS = {2}             # dropar seq=2 (não processa, sem ACK/NACK)
#   CORRUPT_SEQS = {3}          # tratar seq=3 como corrompido (força NACK)
#   DELAY_ACK_SEQS = {4: 1.0}   # atrasar o ACK/NACK do seq=4 em 1s
DROP_SEQS = set()
CORRUPT_SEQS = set()
DELAY_ACK_SEQS = {}
VERBOSE_CRC_OK = True

def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada ao tentar ler bytes")
        buf += chunk
    return buf

def compute_crc_for_packet_fields(seq, total_len, flags, pay_len, payload):
    header_no_ck = struct.pack('!cH H B B I', DATA_TYPE, seq, total_len, flags, pay_len, 0)
    return zlib.crc32(header_no_ck + payload) & 0xFFFFFFFF

def send_ack(conn, ack_seq, window, ack_mode):
    hdr = struct.pack(HDR_ACK_FMT, ACK_OK, ack_seq, window, ack_mode)
    conn.sendall(hdr)

def send_nack(conn, bad_seq, window, ack_mode):
    hdr = struct.pack(HDR_ACK_FMT, ACK_NACK, bad_seq, window, ack_mode)
    conn.sendall(hdr)

def parse_handshake(hs: str):
    """
    Espera: "REQ:<modo>:<min>-<max>"
    Retorna: (ack_mode, modo_str, tam_str)
    """
    modo_str, tam = "GBN", "0-0"
    ack_mode = 1
    try:
        parts = hs.strip().split(':')
        if len(parts) >= 3 and parts[0].upper() == 'REQ':
            req = parts[1].strip().upper()
            if req == 'SR':
                ack_mode = 0
                modo_str = 'SR'
            else:
                ack_mode = 1
                modo_str = 'GBN'
            tam = parts[2].strip()
    except Exception:
        pass
    return ack_mode, modo_str, tam

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Servidor aguardando conexão... ({HOST}:{PORT})")
    conn, addr = server_socket.accept()

    with conn:
        print(f"Conectado por {addr}")

        handshake = conn.recv(128).decode('utf-8', errors='replace')
        print(f"Handshake recebido: {handshake.strip()}")

        ACK_MODE, modo_str, tam_str = parse_handshake(handshake)
        resposta = f"OK:{modo_str}:{tam_str}:W{WINDOW_SIZE}:M{ACK_MODE}"
        conn.sendall(resposta.encode('utf-8'))
        print(f"Resposta enviada ao cliente: {resposta}")

        print(f"[CONF] WINDOW_SIZE={WINDOW_SIZE}, ACK_MODE={'GBN' if ACK_MODE==1 else 'SR'}")
        print(f"[FAIL-INJECT] DROP={DROP_SEQS} CORRUPT={CORRUPT_SEQS} DELAY_ACK={DELAY_ACK_SEQS}")

        while True:
            tam_prefix = conn.recv(2)
            if not tam_prefix:
                print("Conexão fechada pelo cliente.")
                break

            try:
                total_len = int(tam_prefix.decode('utf-8'))
            except Exception:
                total_len = 0

            print(f"\n[INFO] Iniciando recepção de mensagem: total_len={total_len}")

            if ACK_MODE == 1:
                expected_seq = 0
                last_in_order = -1
                acumulado = bytearray()

                while True:
                    try:
                        hdr = recv_exact(conn, HDR_DATA_SIZE)
                    except ConnectionError:
                        print("[ERRO] conexão interrompida")
                        break

                    p_type, seq, total_len_hdr, flags, pay_len, recv_crc = struct.unpack(HDR_DATA_FMT, hdr)
                    payload = recv_exact(conn, pay_len)

                    if p_type != DATA_TYPE:
                        print(f"[WARN] tipo inválido (esperado 'D'), descartando seq={seq}")
                        continue

                    if seq in DROP_SEQS:
                        print(f"[SIM-DROP] seq={seq} (servidor). Ignorando pacote.")
                        continue

                    if seq in CORRUPT_SEQS:
                        calc_crc = compute_crc_for_packet_fields(seq, total_len_hdr, flags, pay_len, payload) ^ 0xFFFFFFFF
                    else:
                        calc_crc = compute_crc_for_packet_fields(seq, total_len_hdr, flags, pay_len, payload)

                    if VERBOSE_CRC_OK:
                        print(f"[CRC] seq={seq} calc=0x{calc_crc:08X} recv=0x{recv_crc:08X}")

                    if calc_crc != recv_crc:
                        print(f"[CRC-ERR] seq={seq} -> NACK({seq})")
                        if seq in DELAY_ACK_SEQS:
                            d = float(DELAY_ACK_SEQS[seq])
                            print(f"[DELAY] NACK({seq}) em {d}s")
                            time.sleep(d)
                        send_nack(conn, seq, WINDOW_SIZE, ACK_MODE)
                        continue

                    if seq == expected_seq:
                        acumulado += payload
                        expected_seq += 1
                        last_in_order = expected_seq - 1
                        print(f"[OK] seq={seq} len={pay_len} flags={'LAST' if (flags & FLAG_LAST) else '-'} | expected_seq={expected_seq}")

                        if seq in DELAY_ACK_SEQS:
                            d = float(DELAY_ACK_SEQS[seq])
                            print(f"[DELAY] ACK({last_in_order}) em {d}s")
                            time.sleep(d)
                        send_ack(conn, last_in_order, WINDOW_SIZE, ACK_MODE)

                        if (flags & FLAG_LAST) != 0:
                            print("[INFO] LAST recebido em ordem. Mensagem completa (GBN).")
                            break

                    elif seq > expected_seq:
                        print(f"[OOD] fora-de-ordem seq={seq} (esperado={expected_seq}) -> ", end="")
                        if last_in_order >= 0:
                            print(f"ACK({last_in_order})")
                            if seq in DELAY_ACK_SEQS:
                                time.sleep(float(DELAY_ACK_SEQS[seq]))
                            send_ack(conn, last_in_order, WINDOW_SIZE, ACK_MODE)
                        else:
                            print(f"NACK({expected_seq})")
                            if seq in DELAY_ACK_SEQS:
                                time.sleep(float(DELAY_ACK_SEQS[seq]))
                            send_nack(conn, expected_seq, WINDOW_SIZE, ACK_MODE)

                    else:
                        print(f"[DUP] duplicata seq={seq} -> ", end="")
                        if last_in_order >= 0:
                            print(f"re-ACK({last_in_order})")
                            send_ack(conn, last_in_order, WINDOW_SIZE, ACK_MODE)
                        else:
                            print(f"NACK({expected_seq})")
                            send_nack(conn, expected_seq, WINDOW_SIZE, ACK_MODE)

                try:
                    msg = acumulado.decode('utf-8')
                except UnicodeDecodeError:
                    msg = "<MENSAGEM CORROMPIDA>"
                print(f"\n🟢 Mensagem completa recebida (GBN) ({len(acumulado)} bytes): {msg}\n")

            else:
                recv_buffer = {}    
                received = set()
                expected_base = 0
                acumulado = bytearray()
                delivered_last_flag = False

                while True:
                    try:
                        hdr = recv_exact(conn, HDR_DATA_SIZE)
                    except ConnectionError:
                        print("[ERRO] conexão interrompida")
                        break

                    p_type, seq, total_len_hdr, flags, pay_len, recv_crc = struct.unpack(HDR_DATA_FMT, hdr)
                    payload = recv_exact(conn, pay_len)

                    if p_type != DATA_TYPE:
                        print(f"[WARN] tipo inválido (esperado 'D'), descartando seq={seq}")
                        continue

                    if seq in DROP_SEQS:
                        print(f"[SIM-DROP] seq={seq} (servidor). Ignorando pacote.")
                        continue

                    if seq in CORRUPT_SEQS:
                        calc_crc = compute_crc_for_packet_fields(seq, total_len_hdr, flags, pay_len, payload) ^ 0xFFFFFFFF
                    else:
                        calc_crc = compute_crc_for_packet_fields(seq, total_len_hdr, flags, pay_len, payload)

                    if VERBOSE_CRC_OK:
                        print(f"[CRC] seq={seq} calc=0x{calc_crc:08X} recv=0x{recv_crc:08X}")

                    if calc_crc != recv_crc:
                        print(f"[CRC-ERR] seq={seq} -> NACK({seq})")
                        if seq in DELAY_ACK_SEQS:
                            time.sleep(float(DELAY_ACK_SEQS[seq]))
                        send_nack(conn, seq, WINDOW_SIZE, ACK_MODE)
                        continue

                    if seq in received:
                        print(f"[DUP] duplicata seq={seq} -> re-ACK({seq})")
                        send_ack(conn, seq, WINDOW_SIZE, ACK_MODE)
                        continue

                    recv_buffer[seq] = (flags, payload)
                    received.add(seq)
                    print(f"[SR-RECV] seq={seq} len={pay_len} flags={'LAST' if (flags & FLAG_LAST) else '-'} | buffered")

                    if seq in DELAY_ACK_SEQS:
                        print(f"[DELAY] ACK({seq}) em {DELAY_ACK_SEQS[seq]}s")
                        time.sleep(float(DELAY_ACK_SEQS[seq]))
                    send_ack(conn, seq, WINDOW_SIZE, ACK_MODE)

                    while expected_base in recv_buffer:
                        f, p = recv_buffer.pop(expected_base)
                        acumulado += p
                        print(f"[SR-DELIVER] Delivered seq={expected_base}")
                        if (f & FLAG_LAST) != 0:
                            delivered_last_flag = True
                        expected_base += 1

                    if delivered_last_flag:
                        print("[INFO] LAST entregue em ordem (SR). Mensagem completa.")
                        break

                try:
                    msg = acumulado.decode('utf-8')
                except UnicodeDecodeError:
                    msg = "<MENSAGEM CORROMPIDA>"
                print(f"\n🟢 Mensagem completa recebida (SR) ({len(acumulado)} bytes): {msg}\n")
