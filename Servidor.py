import socket

HOST = '127.0.0.1'
PORT = 65432
modo_operacao = 'texto'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

server_socket.listen()
print('Servidor aguardando conexão...')

conn, addr = server_socket.accept()
print(f'Conectado por {addr}')

data = conn.recv(30).decode()
print(f'Handshake recebido: {data}')

modo, tamanho = data.split(':')
LIMITE_MAX = int(tamanho)
print(f'Modo de operação: {modo}')
print(f'Usando limite máximo definido pelo cliente: {LIMITE_MAX}')

resposta = f'OK:{modo}:{LIMITE_MAX}'
conn.sendall(resposta.encode())

while True:
    data = conn.recv(LIMITE_MAX)
    if not data:
        break
    mensagem = data.decode()
    print(f'Dados recebidos: {mensagem}')
    conn.sendall(mensagem.encode())

conn.close()
server_socket.close()
