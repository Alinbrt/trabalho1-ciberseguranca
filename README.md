# trabalho1-ciberseguranca
Sistema de Inventário de Ativos de TI e Gestão de Vulnerabilidades - UFU

# Sistema de Inventário de Ativos de TI e Gestão de Vulnerabilidades

## Descrição do Projeto

Este projeto foi desenvolvido como parte da Atividade Avaliativa 1 da disciplina de Cibersegurança da UFU.

O sistema tem como objetivo realizar o inventário de ativos de Tecnologia da Informação (TI) e permitir o gerenciamento de vulnerabilidades associadas a esses ativos.

A aplicação foi desenvolvida em Python, utilizando estruturas de dados em memória e persistência dos dados em arquivo no formato JSON.

---

## Objetivos

O sistema foi desenvolvido com os seguintes objetivos:

* Cadastrar ativos de TI;
* Consultar ativos por ID;
* Consultar ativos por hostname;
* Atualizar informações dos ativos;
* Remover ativos;
* Cadastrar vulnerabilidades associadas aos ativos;
* Listar vulnerabilidades de um determinado ativo;
* Validar informações inseridas pelo usuário;
* Persistir os dados em arquivo;
* Aplicar conceitos de organização e segurança no desenvolvimento do sistema.

---

## Tecnologias Utilizadas

* Python 3
* JSON para serialização e persistência dos dados
* Git e GitHub para versionamento e armazenamento do projeto

O projeto utiliza apenas bibliotecas disponíveis na instalação padrão do Python:

```python
import json
import os
from enum import Enum
```

---

## Estrutura do Projeto

```text
trabalho1-ciberseguranca/
│
├── inventario.py
├── banco_ativos.txt
└── README.md
```

### `inventario.py`

Arquivo principal do sistema, contendo toda a implementação do inventário de ativos e do gerenciamento de vulnerabilidades.

### `banco_ativos.txt`

Arquivo utilizado para armazenar os dados persistidos do sistema.

Apesar da extensão `.txt`, seu conteúdo é estruturado no formato JSON.

### `README.md`

Documento de apresentação, instalação e utilização do projeto.

---

# Funcionalidades

O sistema possui um menu interativo com as seguintes opções:

```text
1 - Cadastrar Ativo
2 - Buscar Ativo por ID
3 - Buscar Ativo por Hostname
4 - Atualizar Ativo
5 - Deletar Ativo
6 - Cadastrar Vulnerabilidade em Ativo
7 - Listar Vulnerabilidades de um Ativo
8 - Listar Todos os Ativos
0 - Sair e Salvar Dados
```

---

## Gerenciamento de Ativos

### Cadastro de Ativos

É possível cadastrar um ativo informando:

* ID;
* Hostname;
* Responsável;
* Localização;
* Tipo do ativo.

O sistema verifica se o ID já está cadastrado e também realiza validações sobre os dados informados.

---

### Busca por ID

Permite localizar diretamente um ativo utilizando seu identificador.

Como os ativos são armazenados em um dicionário Python, a busca por ID possui complexidade média de **O(1)**.

---

### Busca por Hostname

Permite localizar ativos utilizando o hostname cadastrado.

Nesse caso, o sistema percorre os ativos armazenados para encontrar aqueles que possuem o hostname informado.

A complexidade dessa operação é O(n).

---

### Atualização de Ativos

É possível atualizar informações de um ativo já cadastrado, como:

* Hostname;
* Responsável;
* Localização;
* Tipo do ativo.

As vulnerabilidades associadas ao ativo são preservadas durante a atualização.

---

### Exclusão de Ativos

O sistema permite remover um ativo pelo seu ID.

Ao remover o ativo, também são removidas as vulnerabilidades associadas a ele, pois elas são armazenadas junto ao registro do ativo.

---

# Gerenciamento de Vulnerabilidades

Cada ativo pode possuir uma lista de vulnerabilidades associadas.

Para cadastrar uma vulnerabilidade, são utilizadas informações como:

* Descrição;
* Categoria;
* Severidade;
* Status de tratamento.

---

## Níveis de Severidade

O sistema possui quatro níveis de severidade:

* Baixa
* Média
* Alta
* Crítica

---

## Status de Tratamento

As vulnerabilidades podem possuir os seguintes status:

* Aberta
* Em Tratamento
* Corrigida
* Aceita como Risco

---

## Tipos de Ativos

O sistema possui os seguintes tipos de ativos:

| Código | Tipo                |
| ------ | ------------------- |
| 1      | Notebook            |
| 2      | Servidor            |
| 3      | Roteador            |
| 4      | Estação de Trabalho |
| 5      | Aplicação Web       |
| 6      | Banco de Dados      |

---

# Validações

O sistema possui mecanismos de validação para evitar o cadastro de informações inválidas.

Entre as validações implementadas estão:

* Verificação de ID duplicado;
* Verificação da existência do ativo antes de realizar operações;
* Validação do nome do responsável;
* Verificação de campos obrigatórios;
* Validação do tipo de ativo;
* Validação da severidade da vulnerabilidade;
* Validação do status da vulnerabilidade;
* Tratamento de entradas inválidas;
* Tratamento de erros durante leitura e gravação do arquivo.

---

# Persistência dos Dados

Os dados são mantidos em memória durante a execução utilizando um dicionário Python.

Além disso, o sistema possui persistência em arquivo utilizando o módulo `json`.

Os dados são serializados utilizando:

```python
json.dump()
```

E carregados novamente utilizando:

```python
json.loads()
```

Dessa forma, os dados cadastrados permanecem disponíveis mesmo após o encerramento do programa.

O arquivo utilizado atualmente é:

```text
banco_ativos.txt
```

Embora possua extensão `.txt`, o conteúdo armazenado segue a estrutura JSON.

---

# Como Executar o Projeto

## 1. Pré-requisitos

É necessário possuir o **Python 3** instalado no computador.

Para verificar a instalação:

```bash
python --version
```

ou:

```bash
python3 --version
```

---

## 2. Clonar o Repositório

Para baixar o projeto diretamente do GitHub, abra o terminal e execute:

```bash
git clone https://github.com/Alinbrt/trabalho1-ciberseguranca.git
```

Depois, entre na pasta do projeto:

```bash
cd trabalho1-ciberseguranca
```

---

## 3. Executar o Programa

Execute o arquivo principal:

```bash
python inventario.py
```

Caso seu sistema utilize `python3`:

```bash
python3 inventario.py
```

Após executar, o menu principal será apresentado no terminal.

---

# Exemplo de Execução

Ao iniciar o programa, será apresentado um menu semelhante a:

```text
==================================================
 SISTEMA DE INVENTÁRIO DE ATIVOS DE TI
==================================================
1 - Cadastrar Ativo
2 - Buscar Ativo por ID
3 - Buscar Ativo por Hostname
4 - Atualizar Ativo
5 - Deletar Ativo
6 - Cadastrar Vulnerabilidade em Ativo
7 - Listar Vulnerabilidades de um Ativo
8 - Listar Todos os Ativos
0 - Sair e Salvar Dados
==================================================
```

O usuário pode selecionar uma das opções e interagir com o sistema pelo terminal.

---

# Fluxo do Sistema

O funcionamento geral do sistema pode ser representado da seguinte forma:

```text
                 ┌─────────────────────┐
                 │     Iniciar         │
                 │      Sistema        │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Carregar dados do   │
                 │ arquivo JSON        │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Menu Principal    │
                 └──────────┬──────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
    ┌───────────┐     ┌─────────────┐   ┌─────────────┐
    │  Ativos   │     │Vulnerabili- │   │   Consultas │
    │ CRUD      │     │   dades     │   │             │
    └───────────┘     └─────────────┘   └─────────────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Persistir alterações│
                 │      em arquivo     │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │       Encerrar      │
                 └─────────────────────┘
```

---

# Estruturas de Dados

O sistema utiliza principalmente um dicionário Python para armazenar os ativos.

A estrutura geral de um ativo segue o formato:

```python
{
    "id": 1,
    "hostname": "PC-001",
    "responsavel": "Nome do Responsável",
    "localizacao": "Laboratório",
    "tipo": "NOTEBOOK",
    "tipo_codigo": 1,
    "vulnerabilidades": []
}
```

As vulnerabilidades são armazenadas dentro da lista associada a cada ativo.

---

# Organização do Código

O programa está organizado em funções responsáveis por diferentes partes do sistema:

* Persistência dos dados;
* Validação de informações;
* Cadastro de ativos;
* Busca de ativos;
* Atualização de ativos;
* Exclusão de ativos;
* Cadastro de vulnerabilidades;
* Listagem de vulnerabilidades;
* Interface do menu principal.

Essa organização facilita a manutenção e a compreensão do código.

---

# Dependências

O projeto não necessita da instalação de bibliotecas externas.

São utilizadas apenas bibliotecas da biblioteca padrão do Python:

```python
json
os
enum
```

Portanto, não é necessário executar `pip install` para utilizar o sistema.

---

# Autoria

Projeto desenvolvido para a disciplina de Cibersegurança - UFU.

Repositório:
https://github.com/Alinbrt/trabalho1-ciberseguranca

---

# Licença

Este projeto foi desenvolvido para fins acadêmicos e educacionais.
