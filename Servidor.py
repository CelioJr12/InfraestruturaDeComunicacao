import socket

HOST = '127.0.0.1'#localhost
PORT = 65432 #porta arbitrária não privilegiada
LIMITE_MAX = 30 # Limite máximo fixo
modo_operacao = 'texto'

#Criando o socket do servidor /AF_INET --> IPv4 /SOCK_STREAM --> TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST,PORT))

#Escutando as conexões
server_socket.listen()
print('Servidor aguardando conexão...')

#Aceita a conexão do cliente
conn, addr = server_socket.accept() 
print(f'Conectado por {addr}')

#Receber o handshake
data = conn.recv(30).decode() #Recebe até 1024 bytes e decodifica para string
print(f'Handshake recebido: {data}')

#Processar o handshake do cliente
modo,tamanho = data.split(':')
print(f'Modo de operação: {modo}')
print(f'Tamanho máximo recebido no handshake (ignorado): {tamanho}')
print(f'Usando limite máximo fixo: {LIMITE_MAX}')

#Enviar resposta ao cliente confirmando o handshake
resposta = f'OK:{modo}:{LIMITE_MAX}'
conn.sendall(resposta.encode())

while True:
    data = conn.recv(30)
    if not data:
        break
    mensagem = data.decode()
    if len(mensagem) > LIMITE_MAX:
        print(f'Mensagem recebida maior que limite ({len(mensagem)} > {LIMITE_MAX}), truncando.')
        mensagem = mensagem[:LIMITE_MAX]
    print(f'Dados recebidos: {mensagem}')
    conn.sendall(mensagem.encode())
        

#Fechat a conexão
conn.close()
server_socket.close()