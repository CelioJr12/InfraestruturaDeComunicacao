import socket

HOST = '127.0.0.1'  # localhost
PORT = 65432        # porta arbitrária

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

modo_operacao = 'texto'
tamanho_min = 30
tamanho_pacote = 4
tamanho_max= 50
handshake = f'{modo_operacao}:{tamanho_max}'
client_socket.sendall(handshake.encode())

data = client_socket.recv(30).decode()
print(f'Resposta do servidor: {data}')

while True:
    mensagem = input(f'Digite uma mensagem (min {tamanho_min} e max {tamanho_max} de caracteres, vazio para sair): ')
    if mensagem == '':
        break
    elif len(mensagem) >= 30 and len(mensagem) <=50:
        for i in range(0, len(mensagem), tamanho_pacote):
            pacote = mensagem[i:i+tamanho_pacote]
            client_socket.sendall(pacote.encode())
            resposta = client_socket.recv(tamanho_pacote).decode()
            print(f'Resposta do servidor: {resposta}')
    elif len(mensagem) > 50:
        print("Valor maior que o possível")
    else:
        print("Valor menor que o possível")

client_socket.close()
