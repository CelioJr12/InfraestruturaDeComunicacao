#!/usr/bin/env python3
# cliente_compat_server.py
# Cliente adaptado para o servidor que espera pacotes textuais "seq|length|chk|payload\n"
# e handshake "<MODO>;<TAMANHO>\n", responde "ACK;modo=...;tamanho=...;janela=...;dh=...\n"

import socket
import sys
import time
import base64
import hashlib

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    PYCRYPTODOME = True
except Exception:
    PYCRYPTODOME = False

HOST = sys.argv[1] if len(sys.argv) >= 2 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 5000

MIN_BYTES = 30
MAX_BYTES = 50
BLOCO_BYTES = 4

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

USE_ENCRYPTION = True  # set False to force no encryption even if pycryptodome present
SOCKET_TIMEOUT = 0.2
GBN_RETRANS_TIMEOUT = 1.0
SR_RETRANS_TIMEOUT  = 1.0

VERBOSE = True

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def derive_aes_key(shared_secret_int: int) -> bytes:
    return hashlib.sha256(str(shared_secret_int).encode()).digest()

def aes_encrypt_to_bytes(plaintext_bytes: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    from Crypto.Cipher import AES as _AES
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext_bytes, _AES.block_size))
    return iv + ct

def aes_decrypt_from_bytes(data: bytes, key: bytes) -> bytes:
    iv = data[:16]
    from Crypto.Cipher import AES as _AES
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(data[16:]), _AES.block_size)
    return pt

def recv_lines(sock, timeout=SOCKET_TIMEOUT):
    """Recebe dados e retorna lista de linhas (sem newline). retorna [] em timeout."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(4096)
        if not data:
            raise ConnectionError("Conexão fechada pelo servidor")
        txt = data.decode('utf-8', errors='replace')
        return txt.splitlines()
    except socket.timeout:
        return []
    except BlockingIOError:
        return []
    except Exception:
        raise

def build_text_packet(seq:int, payload_b64_str:str) -> str:
    length = len(payload_b64_str)
    chk = checksum_of(payload_b64_str.encode('utf-8'))
    return f"{seq}|{length}|{chk}|{payload_b64_str}\n"

def parse_server_ack_line(line: str):
    # formatos: "ACK|<num>", "NAK|<num>", "ACK_IND|<num>", "ACK_END"
    if line.startswith("ACK_END"):
        return ("END", None)
    if '|' in line:
        typ, val = line.split('|',1)
        try:
            num = int(val)
        except:
            num = None
        return (typ, num)
    return (line, None)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.settimeout(None)
        modo_in = input("Escolha o modo (GBN/SR) [GBN]: ").strip().upper() or "GBN"
        if modo_in not in {"GBN","SR"}:
            modo_in = "GBN"

        use_encryption_now = USE_ENCRYPTION and PYCRYPTODOME
        if USE_ENCRYPTION and not PYCRYPTODOME:
            print("[WARN] PyCryptodome não encontrado: criptografia desabilitada.")
            use_encryption_now = False

        # handshake esperado pelo server: "<MODO>;<TAMANHO>\n"
        handshake = f"{modo_in};{MAX_BYTES}\n"
        sock.sendall(handshake.encode('utf-8'))

        # recebe resposta do servidor (linha)
        full_resp = ""
        sock.settimeout(5.0)
        try:
            # ler até newline
            while '\n' not in full_resp:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Conexão fechada pelo servidor durante handshake")
                full_resp += chunk.decode('utf-8', errors='replace')
        except socket.timeout:
            print("[ERRO] timeout aguardando resposta do servidor.")
            return
        finally:
            sock.settimeout(SOCKET_TIMEOUT)

        # assume uma linha
        resp_line = full_resp.strip().splitlines()[0]
        if VERBOSE:
            print(f"[SERVER] {resp_line}")

        # resp esperada: "ACK;modo=...;tamanho=...;janela=...;dh=..."
        server_window = 5
        server_mode = modo_in
        server_dh = None
        try:
            parts = resp_line.split(';')
            for p in parts:
                if p.startswith("janela=") or p.startswith("janela"):
                    try:
                        server_window = int(p.split('=',1)[1])
                    except:
                        pass
                if p.lower().startswith("dh=") or p.startswith("dh="):
                    try:
                        server_dh = int(p.split('=',1)[1])
                    except:
                        pass
                if p.startswith("modo="):
                    server_mode = p.split('=',1)[1]
        except Exception:
            pass

        aes_key = None
        if use_encryption_now and server_dh is not None:
            # gera DH do cliente, envia "DH|<client_pub>\n"
            client_priv = int.from_bytes(get_random_bytes(64), 'big') % (DH_PRIME - 2) + 2
            client_pub = pow(DH_G, client_priv, DH_PRIME)
            sock.sendall(f"DH|{client_pub}\n".encode())
            shared = pow(server_dh, client_priv, DH_PRIME)
            aes_key = derive_aes_key(shared)
            if VERBOSE: print("[SEC] DH concluído. AES-256 derivada.")
        elif use_encryption_now:
            print("[WARN] Servidor não ofereceu DH; criptografia desativada para esta sessão.")
            use_encryption_now = False

        # loop de mensagens do usuário
        while True:
            mensagem = input(f"Digite uma mensagem entre {MIN_BYTES} e {MAX_BYTES} BYTES (vazio para sair): ")
            if mensagem == '':
                break

            data_bytes = mensagem.encode('utf-8')
            total_len = len(data_bytes)
            if total_len < MIN_BYTES or total_len > MAX_BYTES:
                print(f"Mensagem inválida: {total_len} bytes (esperado entre {MIN_BYTES} e {MAX_BYTES})")
                continue

            # se criptografado -> criptografa toda a mensagem e codifica em base64
            if use_encryption_now and aes_key is not None:
                ciphertext = aes_encrypt_to_bytes(data_bytes, aes_key)
                stream_bytes = base64.b64encode(ciphertext)  # bytes
            else:
                # envia base64 também (o servidor trata sempre como base64-strings concatenadas)
                stream_bytes = base64.b64encode(data_bytes)

            stream_str = stream_bytes.decode('ascii')  # string base64 completa
            # fragmenta por BLOCO_BYTES (contando caracteres base64)
            fragments = []
            i = 0
            while i < len(stream_str):
                bloco = stream_str[i:i+BLOCO_BYTES]
                fragments.append(bloco)
                i += len(bloco)

            nfrags = len(fragments)
            if VERBOSE:
                print(f"[INFO] Mensagem codificada em base64 ({len(stream_str)} chars) -> {nfrags} fragmentos.")

            # janela negociada
            window_max = max(1, min(5, int(server_window)))

            base = 0
            next_seq = 0
            snd_buffer = {}       # seq -> packet_str
            snd_time = {}         # seq -> last send time
            gbn_timer_running = False
            gbn_timer_start = 0.0

            def start_gbn_timer():
                nonlocal gbn_timer_running, gbn_timer_start
                gbn_timer_running = True
                gbn_timer_start = time.monotonic()
                if VERBOSE:
                    print(f"[TIMER] GBN START base={base}")

            def stop_gbn_timer():
                nonlocal gbn_timer_running
                if gbn_timer_running and VERBOSE:
                    print(f"[TIMER] GBN STOP base={base}")
                gbn_timer_running = False

            def gbn_timer_expired():
                return gbn_timer_running and (time.monotonic() - gbn_timer_start >= GBN_RETRANS_TIMEOUT)

            def send_one(seq_idx):
                payload_b64 = fragments[seq_idx]
                pkt = build_text_packet(seq_idx, payload_b64)
                snd_buffer[seq_idx] = pkt
                sock.sendall(pkt.encode('utf-8'))
                snd_time[seq_idx] = time.monotonic()
                if VERBOSE:
                    lastflag = "LAST" if (seq_idx == nfrags-1) else ""
                    print(f"[SEND] seq={seq_idx} len={len(payload_b64)} {lastflag}")

            def gbn_retransmit_window():
                if VERBOSE:
                    print(f"[TIMEOUT] GBN timeout base={base}. Retransmit [{base}..{next_seq-1}]")
                for s in range(base, next_seq):
                    pkt = snd_buffer.get(s)
                    if pkt:
                        sock.sendall(pkt.encode('utf-8'))
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
                for s, t in list(snd_time.items()):
                    if base <= s < base + window_max:
                        if now - t >= SR_RETRANS_TIMEOUT:
                            expired.append(s)
                if expired and VERBOSE:
                    print(f"[TIMEOUT-SR] retransmitindo expirados: {expired}")
                for s in expired:
                    pkt = snd_buffer.get(s)
                    if pkt:
                        sock.sendall(pkt.encode('utf-8'))
                        snd_time[s] = time.monotonic()
                        if VERBOSE:
                            print(f"[RETX-SR] seq={s}")

            # envia e gerencia ACKs (GBN ou SR dependendo do modo negociado)
            # ack_mode: servidor respondeu modo; server_mode pode ser 'GBN' ou 'SR'
            ack_mode = 1 if server_mode.upper() == 'GBN' else 0

            while base < nfrags:
                # enviar novos na janela
                while next_seq < nfrags and next_seq < base + window_max:
                    send_one(next_seq)
                    next_seq += 1

                if ack_mode == 1 and not gbn_timer_running and base < next_seq:
                    start_gbn_timer()

                # aguarda linha(s) de ack do servidor com timeout curto
                try:
                    lines = recv_lines(sock, timeout=SOCKET_TIMEOUT)
                except ConnectionError:
                    print("[ERRO] conexão encerrada pelo servidor.")
                    return

                if not lines:
                    # timeout
                    if ack_mode == 1:
                        if gbn_timer_expired():
                            gbn_retransmit_window()
                    else:
                        sr_retransmit_expired()
                    continue

                for line in lines:
                    if not line:
                        continue
                    if VERBOSE:
                        print(f"[RCV] {line}")
                    typ, num = parse_server_ack_line(line.strip())
                    if typ == "END":
                        # servidor finalizou
                        if VERBOSE:
                            print("[INFO] Servidor sinalizou END.")
                        break
                    if typ == "ACK":
                        # servidor envia ACK|<expected_seq> in GBN (expected next)
                        if num is None:
                            continue
                        if ack_mode == 1:
                            # cumulative ack: server sends expected next seq
                            # server expected_seq == next expected; in server logic it sent ACK|expected_seq
                            # So all seq < expected_seq are acknowledged.
                            expected_next = num
                            # remove acknowledged packets
                            to_remove = [s for s in list(snd_buffer.keys()) if s < expected_next]
                            for s in to_remove:
                                snd_buffer.pop(s, None)
                                snd_time.pop(s, None)
                            base = expected_next
                            if base == next_seq:
                                stop_gbn_timer()
                            else:
                                start_gbn_timer()
                        else:
                            # in SR mode server shouldn't send plain ACK but maybe does; treat as individual ack
                            if num in snd_buffer:
                                snd_buffer.pop(num, None)
                                snd_time.pop(num, None)
                            # advance base while base acknowledged
                            while base < nfrags and base not in snd_buffer and base < next_seq:
                                base += 1

                    elif typ == "ACK_IND":
                        # individual ack for SR (server used "ACK_IND|seq")
                        if num is None:
                            continue
                        if num in snd_buffer:
                            snd_buffer.pop(num, None)
                            snd_time.pop(num, None)
                        # advance base
                        while base < nfrags and base not in snd_buffer and base < next_seq:
                            base += 1

                    elif typ == "NAK":
                        # server asks retransmit specific seq
                        if num is None:
                            continue
                        if VERBOSE:
                            print(f"[NAK] servidor pediu retransmit seq={num}")
                        pkt = snd_buffer.get(num)
                        if pkt:
                            sock.sendall(pkt.encode('utf-8'))
                            snd_time[num] = time.monotonic()
                            if VERBOSE:
                                print(f"[RETX-NAK] seq={num}")

                    else:
                        # desconhecido
                        if VERBOSE:
                            print(f"[WARN] ACK desconhecido: {typ}")

            # ao terminar todos os fragmentos confirmados localmente, enviar "END\n" para sinalizar conclusão
            sock.sendall(b"END\n")
            # aguardar ACK_END
            # leia por até 2s
            end_deadline = time.time() + 2.0
            got_end_ack = False
            buf = ""
            while time.time() < end_deadline:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk.decode('utf-8', errors='replace')
                    if '\n' in buf:
                        for l in buf.splitlines():
                            if l.strip() == "ACK_END":
                                got_end_ack = True
                                break
                        if got_end_ack:
                            break
                except socket.timeout:
                    continue
                except Exception:
                    break

            if VERBOSE:
                if got_end_ack:
                    print("[DONE] Servidor confirmou END (ACK_END).")
                else:
                    print("[DONE] Não recebeu ACK_END explícito (continuando).")

        print("Cliente finalizado.")

if __name__ == "__main__":
    main()
