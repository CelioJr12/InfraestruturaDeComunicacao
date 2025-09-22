import socket

HOST = '127.0.0.1'  # localhost
PORT = 65432        # porta arbitrária

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

modo_operacao = 'texto'
tamanho_max = '50'
handshake = f'{modo_operacao}:{tamanho_max}'
client_socket.sendall(handshake.encode())

data = client_socket.recv(30).decode()
print(f'Resposta do servidor: {data}')

while True:
    mensagem = input(f'Digite uma mensagem (máx {tamanho_max} caracteres, vazio para sair): ')
    if mensagem == '':
        break

    carga_util = mensagem[:int(tamanho_max)]

    client_socket.sendall(carga_util.encode())
    resposta = client_socket.recv(int(tamanho_max)).decode()
    print(f'Resposta do servidor: {resposta}')

client_socket.close()
