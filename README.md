README
Como executar

Servidor

python Servidor.py


Cliente

python Cliente.py


O cliente pedirá o modo de operação (GBN ou SR).

## Como enviar mensagens

O cliente aceita mensagens entre 30 e 50 bytes.
A mensagem será fragmentada e enviada automaticamente.
O servidor monta tudo e exibe o resultado no final.

## Como testar erros

Você pode simular erros editando temporariamente o código, por exemplo:

alterar o checksum antes de enviar um fragmento

comentar um envio para gerar timeout

enviar o mesmo fragmento duas vezes

O servidor responderá com NAK ou ACK dependendo do caso.

Recursos implementados

modos GBN e SR

checksum para integridade

retransmissão com timeout

janela de 1 a 5, definida pelo servidor

criptografia opcional com Diffie Hellman e AES
