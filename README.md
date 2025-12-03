# 📄 README: Trabalho I da Disciplina de Infraestrutura de Comunicação (RSD)

---

## 🚀 1. Introdução ao Projeto

Este projeto implementa um sistema básico de **Transferência Confiável de Dados (RDT)** sobre o protocolo UDP, utilizando Python. O objetivo é simular as camadas de transporte e aplicação, garantindo a entrega correta e na ordem de uma mensagem fragmentada, mesmo na presença de erros (perda de pacotes e erros de checksum).

### 🔑 Recursos de Aplicação

* **Fragmentação:** Mensagens são quebradas em fragmentos de 4 bytes (caracteres).
* **Criptografia Simples:** Um esquema de criptografia XOR/Permutação é aplicado a cada payload de 4 bytes.
* **Verificação de Integridade:** Um algoritmo de **Checksum Modulo-256** é usado para detectar erros de bits.

---

## 🔬 2. Relatório Técnico e Protocolo de Aplicação

### 2.1 Protocolo de Transporte (RDT)

O sistema suporta dois modos de transferência, selecionados pelo Cliente no início da comunicação:

* **Go-Back-N (GBN):** Utiliza uma **janela deslizante ($W=5$)**. O Servidor envia **NAK** para o pacote fora de ordem (`expected_seq`). Um NAK recebido ou um **Timeout** no Cliente faz com que **toda a janela** seja retransmitida a partir da base (`base`). 
* **Selective Repeat (SR):** Utiliza uma **janela deslizante ($W=5$)** e permite o armazenamento de pacotes fora de ordem no Servidor. O Servidor envia **ACK** para pacotes corretos e **NAK** apenas para pacotes específicos faltantes. O Cliente retransmite **apenas** os pacotes solicitados (via NAK) ou aqueles que atingiram o timeout. 

| Característica | Go-Back-N (GBN) | Selective Repeat (SR) |
| :---: | :---: | :---: |
| **Janela de Envio** | $W=5$ | $W=5$ |
| **Avanço da Janela** | Cumulativo (base avança apenas com ACK da base) | Individual (base avança com ACK da base) |
| **Retransmissão** | Pacotes perdidos **e** subsequentes. | Somente pacotes perdidos/solicitados por NAK. |

### 2.2 Estrutura do Pacote de Dados (DATA)

O pacote de dados é transmitido em formato string (separado por `|`):

$$\text{DATA}| \text{SeqNum}| \text{TotalPacotes}| \text{PayloadCriptografado}| \text{Checksum}$$

* **SeqNum:** Número de sequência do pacote.
* **TotalPacotes:** Número total de fragmentos da mensagem.
* **PayloadCriptografado:** Carga útil de 4 bytes, após criptografia.
* **Checksum:** Valor Módulo-256 calculado sobre o **Payload de 4 bytes com padding**.

### 2.3 Detalhes da Criptografia e Integridade

#### 🛡️ Criptografia Manual

Cada fragmento de 4 caracteres é criptografado usando a chave fixa `MANUAL_KEY = b'COMP'`. O processo envolve:

1.  **Padding (`.ljust(4)`):** Fragmentos incompletos são preenchidos com espaços.
2.  **Checksum:** O valor de integridade é calculado sobre o payload de 4 bytes **já com o padding**.
3.  **Criptografia:** Os 4 bytes são submetidos a uma operação **XOR** com a chave seguida por uma **Permutação** de bytes.

#### ✅ Checksum

O algoritmo de Checksum é uma soma simples dos valores ASCII (ord) de todos os caracteres do payload, módulo 256. É fundamental que o cálculo inclua o padding.

$$C = \left(\sum_{c \in \text{payload}} \text{ord}(c)\right) \pmod{256}$$

---

## 📖 3. Manual de Utilização

### 3.1 Pré-requisitos

* Python 3.x instalado.
* Os arquivos `Cliente.py` e `Server.py` devem estar no mesmo diretório.

### 3.2 Execução

É obrigatório iniciar o **Servidor** primeiro e, em seguida, o **Cliente**.

#### Passo 1: Iniciar o Servidor

`python Server.py`

#### Passo 2: Iniciar o Cliente

`python Cliente.py`

O Cliente solicitará as seguintes informações:

| Configuração           | Descrição                                                                 | Exemplo                               |
|------------------------|--------------------------------------------------------------------------|--------------------------------------|
| Tamanho Máximo da Mensagem | Limite superior para a mensagem (mínimo 30 chars).                     | 60                                   |
| Modo de Confirmação    | Escolha o protocolo de RDT.                                               | gobackn ou selecionado                |
| Pacotes com Falha      | Digite os números de sequência (SeqNum) que terão o checksum alterado para forçar a falha (separe por vírgula). | 2,5,7 (ou deixe vazio)               |
| Mensagem               | Digite a mensagem a ser transmitida.                                      | Qualquer mensagem com comprimento válido. |



