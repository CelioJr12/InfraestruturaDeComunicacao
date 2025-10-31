"""
Cliente.py

- O cliente ESCOLHE o modo: GBN (lote/ACK cumulativo) ou SR (ACK individual).
  Handshake:
      Cliente -> "REQ:<modo>:<min>-<max>"
      Servidor -> "OK:<modo>:<min>-<max>:W<window>:M<ack_mode>"

- Fragmenta mensagem em blocos de 4 bytes (UTF-8 safe), computa CRC32.
- Envio com janela deslizante:
    * GBN: timer na base; timeout => retransmitir JANELA.
    * SR : timer por pacote; timeout => retransmitir APENAS expirados.
- Recebe ACK_OK/ACK_NACK; interpreta cumulativo (GBN) ou individual (SR).
- Injeção de falhas no CLIENTE (determinística, no primeiro envio):
    * CLIENT_DROP_ONCE    = {seq,...}  -> não envia a 1ª vez (retransmite depois)
    * CLIENT_CORRUPT_ONCE = {seq,...}  -> envia 1ª vez corrompido; retransmite correto
    * CLIENT_DUP_ONCE     = {seq,...}  -> envia 1ª vez em duplicata

Execução:
    python Cliente.py [HOST] [PORT]
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

MIN_BYTES = 30
MAX_BYTES = 50
BLOCO_BYTES = 4

HDR_DATA_FMT = '!cH H B B I'
HDR_DATA_SIZE = struct.calcsize(HDR_DATA_FMT)

HDR_ACK_FMT = '!cH B B'
HDR_ACK_SIZE = struct.calcsize(HDR_ACK_FMT)

ACK_OK   = b'K'
ACK_NACK = b'N'
DATA_TYPE = b'D'
FLAG_LAST = 0x01

SOCKET_TIMEOUT = 0.15
GBN_RETRANS_TIMEOUT = 1.0
SR_RETRANS_TIMEOUT  = 1.0

VERBOSE = True

# --------------------- Injeção de falhas (CLIENTE) ---------------------
# Edite os sets abaixo para simular falhas no PRIMEIRO envio do seq indicado.
# Ex.: CLIENT_CORRUPT_ONCE = {3}  -> seq=3 será enviado corrompido só na 1ª vez.
CLIENT_DROP_ONCE    = set()     # {2}
CLIENT_CORRUPT_ONCE = set()     # {3}
CLIENT_DUP_ONCE     = set()     # {4}

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada ao tentar ler bytes")
        buf += chunk
    return buf

def build_data_packet(seq, total_len, flags, payload):
    pay_len = len(payload)
    header_no_ck = struct.pack('!cH H B B I', DATA_TYPE, seq, total_len, flags, pay_len, 0)
    crc = zlib.crc32(header_no_ck + payload) & 0xFFFFFFFF
    header = struct.pack(HDR_DATA_FMT, DATA_TYPE, seq, total_len, flags, pay_len, crc)
    return header + payload

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.settimeout(SOCKET_TIMEOUT)

    modo_in = input("Escolha o modo (GBN/SR) [GBN]: ").strip().upper() or "GBN"
    if modo_in not in {"GBN", "SR"}:
        modo_in = "GBN"
    handshake = f'REQ:{modo_in}:{MIN_BYTES}-{MAX_BYTES}'
    sock.sendall(handshake.encode('utf-8'))

    resp = sock.recv(128).decode('utf-8', errors='replace')
    print(f"Resposta do servidor: {resp}")

    server_window = 5
    ack_mode = 1  # 1=GBN, 0=SR
    try:
        parts = resp.split(':')
        for p in parts:
            if p.startswith('W'):
                server_window = int(p[1:])
            if p.startswith('M'):
                ack_mode = int(p[1:])
    except Exception:
        pass
    print(f"[CONF] Server window={server_window}, ack_mode={'GBN' if ack_mode==1 else 'SR'}")

    first_send_done = set()

    while True:
        mensagem = input(f"Digite uma mensagem entre {MIN_BYTES} e {MAX_BYTES} BYTES (vazio para sair): ")
        if mensagem == '':
            break

        data_bytes = mensagem.encode('utf-8')
        total_len = len(data_bytes)
        if total_len < MIN_BYTES or total_len > MAX_BYTES:
            print(f"Mensagem inválida: {total_len} bytes")
            continue

        sock.sendall(str(total_len).zfill(2).encode('utf-8'))

        # Fragmentação segura em UTF-8
        fragments = []
        i = 0
        while i < total_len:
            bloco = data_bytes[i:i+BLOCO_BYTES]
            while True:
                try:
                    bloco.decode('utf-8')
                    break
                except UnicodeDecodeError:
                    bloco = bloco[:-1]
                    if not bloco:
                        raise ValueError("Falha ao alinhar UTF-8")
            is_last = (i + len(bloco)) >= total_len
            flags = FLAG_LAST if is_last else 0x00
            fragments.append((flags, bloco))
            i += len(bloco)

        nfrags = len(fragments)
        print(f"[INFO] Mensagem dividida em {nfrags} pacotes.")

        base = 0
        next_seq = 0
        window_max = max(1, min(5, int(server_window)))
        snd_buffer = {}  
        snd_time = {}    

        gbn_timer = {"running": False, "start": 0.0}

        def start_gbn_timer():
            gbn_timer["running"] = True
            gbn_timer["start"] = time.monotonic()
            if VERBOSE:
                print(f"[TIMER] GBN START (base={base})")

        def stop_gbn_timer():
            if gbn_timer["running"]:
                gbn_timer["running"] = False
                if VERBOSE:
                    print(f"[TIMER] GBN STOP (base={base})")

        def gbn_timer_expired():
            return gbn_timer["running"] and (time.monotonic() - gbn_timer["start"] >= GBN_RETRANS_TIMEOUT)

        def send_one(seq_idx):
            flags, payload = fragments[seq_idx]
            correct_pkt = build_data_packet(seq_idx, total_len, flags, payload)

            snd_buffer[seq_idx] = correct_pkt

            pkt_to_send = correct_pkt
            first = (seq_idx not in first_send_done)

            if first and (seq_idx in CLIENT_CORRUPT_ONCE):
                mp = bytearray(correct_pkt)
                if len(mp) > HDR_DATA_SIZE:
                    mp[HDR_DATA_SIZE] ^= 0x01
                pkt_to_send = bytes(mp)

            if first and (seq_idx in CLIENT_DROP_ONCE):
                if VERBOSE:
                    print(f"[SIM-DROP-CLI] seq={seq_idx} (primeiro envio NÃO enviado)")
                first_send_done.add(seq_idx)
                return

            sock.sendall(pkt_to_send)

            if VERBOSE:
                print(f"[SEND] seq={seq_idx} len={len(payload)} flags={'LAST' if (flags & FLAG_LAST) else '-'}")

            if first and (seq_idx in CLIENT_DUP_ONCE):
                sock.sendall(pkt_to_send)
                if VERBOSE:
                    print(f"[SEND-DUP] seq={seq_idx} (duplicata no primeiro envio)")

            first_send_done.add(seq_idx)
            snd_time[seq_idx] = time.monotonic()

        def gbn_retransmit_window():
            if VERBOSE:
                print(f"[TIMEOUT] GBN timeout at base={base}. Retransmit [{base}..{next_seq-1}]")
            for s in range(base, next_seq):
                pkt = snd_buffer.get(s)
                if pkt is not None:
                    sock.sendall(pkt)
                    snd_time[s] = time.monotonic()
                    if VERBOSE:
                        print(f"[RETX] seq={s}")
            if base < next_seq:
                start_gbn_timer()
            else:
                stop_gbn_timer()

        def sr_retransmit_expired():
            expired = []
            now = time.monotonic()
            for s in list(snd_buffer.keys()):
                if base <= s < base + window_max:
                    t = snd_time.get(s, 0.0)
                    if now - t >= SR_RETRANS_TIMEOUT:
                        expired.append(s)
            if expired and VERBOSE:
                print(f"[TIMEOUT-SR] retransmitindo expirados: {expired}")
            for s in expired:
                pkt = snd_buffer.get(s)
                if pkt is not None:
                    sock.sendall(pkt)
                    snd_time[s] = time.monotonic()
                    if VERBOSE:
                        print(f"[RETX-SR] seq={s}")

        while base < nfrags:
            batch_start = None
            while next_seq < nfrags and next_seq < base + window_max:
                if batch_start is None:
                    batch_start = next_seq
                send_one(next_seq)
                next_seq += 1

            if batch_start is not None:
                if VERBOSE:
                    print(f"[SEND-BATCH] enviei pacote(s) {batch_start}..{next_seq-1} (base={base})")
                if ack_mode == 1 and not gbn_timer["running"] and base < next_seq:
                    start_gbn_timer()

            try:
                ack_hdr = recv_exact(sock, HDR_ACK_SIZE)
                ack_type, ack_seq, window, rmode = struct.unpack(HDR_ACK_FMT, ack_hdr)

                if window and int(window) != window_max:
                    old = window_max
                    window_max = max(1, min(5, int(window)))
                    print(f"[INFO] window atualizada pelo servidor: {old} -> {window_max}")

                if ack_type == ACK_OK:
                    if ack_mode == 1:
                        if VERBOSE:
                            print(f"[ACK+] cumulativo={ack_seq} window={window} mode=GBN")
                        if ack_seq >= base:
                            for s in list(snd_buffer.keys()):
                                if s <= ack_seq:
                                    snd_buffer.pop(s, None)
                                    snd_time.pop(s, None)
                            base = ack_seq + 1
                            if base == next_seq:
                                stop_gbn_timer()
                            else:
                                start_gbn_timer()
                    else:
                        if VERBOSE:
                            print(f"[ACK+] individual={ack_seq} window={window} mode=SR")
                        if ack_seq in snd_buffer:
                            snd_buffer.pop(ack_seq, None)
                            snd_time.pop(ack_seq, None)

                        while base < nfrags and base < next_seq and base not in snd_buffer:
                            base += 1

                elif ack_type == ACK_NACK:
                    if VERBOSE:
                        print(f"[ACK-] NACK recebido para seq={ack_seq}")
                    if ack_mode == 1:
                        gbn_retransmit_window()
                    else:
                        pkt = snd_buffer.get(ack_seq)
                        if pkt is not None:
                            sock.sendall(pkt)
                            snd_time[ack_seq] = time.monotonic()
                            if VERBOSE:
                                print(f"[RETX-SR] seq={ack_seq} (via NACK)")
                else:
                    print(f"[WARN] controle desconhecido: {ack_type!r}")

            except socket.timeout:
                if ack_mode == 1:
                    if gbn_timer_expired():
                        gbn_retransmit_window()
                else:
                    sr_retransmit_expired()
                continue
            except ConnectionError:
                print("[ERRO] conexão encerrada")
                break

        print(f"[DONE] Todos os {nfrags} fragmentos confirmados pelo servidor.\n")

    print("Cliente finalizado.")
