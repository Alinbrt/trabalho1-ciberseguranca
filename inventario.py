"""
Módulo de Inventário de Ativos de TI e Gestão de Vulnerabilidades
Atividade Avaliativa 1 - Cibersegurança UFU
"""

import json
import os
from enum import Enum


# ==============================================================================
# 1. ESTRUTURAS DE DADOS E ENUMS (Requisitos 2 e 7)
# ==============================================================================

class TipoAtivo(Enum):
    """
    Enumeração para os tipos de ativos de TI (Requisito 2).
    Mapeia cada categoria a um código numérico inteiro imutável.
    """
    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    ESTACAO_TRABALHO = 4
    APLICACAO_WEB = 5
    BANCO_DE_DADOS = 6


class Severidade(Enum):
    """
    Escala de severidade de vulnerabilidades (Requisito 7).
    """
    BAIXA = "Baixa"
    MEDIA = "Média"
    ALTA = "Alta"
    CRITICA = "Crítica"


class StatusTratamento(Enum):
    """
    Status do ciclo de vida da vulnerabilidade (Requisito 7).
    """
    ABERTA = "Aberta"
    EM_TRATAMENTO = "Em Tratamento"
    CORRIGIDA = "Corrigida"
    ACEITA = "Aceita como Risco"


# Dicionário principal em memória (Hash Map)
# Chave: identificador único (int) -> Valor: dados do ativo (dict)
# Atende ao Requisito 9 (busca e acesso em tempo O(1))
banco_ativos = {}

# Nome padrão do arquivo para persistência dos dados (Requisito 3)
NOME_ARQUIVO_BANCO = "banco_ativos.txt"


# ==============================================================================
# 2. PERSISTÊNCIA EM ARQUIVO DE TEXTO (Requisito 3)
# ==============================================================================

def salvar_dados_em_arquivo(dados: dict, caminho_arquivo: str = NOME_ARQUIVO_BANCO) -> bool:
    """
    Grava o dicionário principal de ativos em um arquivo de texto estruturado (Requisito 3).
    Utiliza serialização JSON formatada com recuo de 4 espaços para facilitar a auditoria.
    """
    try:
        with open(caminho_arquivo, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=4, ensure_ascii=False)
        return True
    except IOError as erro:
        print(f"Erro ao salvar base de dados no disco: {erro}")
        return False


def carregar_dados_de_arquivo(caminho_arquivo: str = NOME_ARQUIVO_BANCO) -> dict:
    """
    Carrega os registros do arquivo de texto para a memória ao iniciar o sistema (Requisito 3).
    Trata erro de arquivo inexistente ou corrompido, inicializando uma base vazia de forma segura.
    """
    if not os.path.exists(caminho_arquivo):
        return {}

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
            conteudo = arquivo.read().strip()
            if not conteudo:
                return {}
            return json.loads(conteudo)
    except (json.JSONDecodeError, IOError) as erro:
        print(f"Aviso: Erro ao ler base de dados ({erro}). Iniciando base vazia.")
        return {}


# ==============================================================================
# 3. VALIDAÇÕES E SANITIZAÇÃO DE ENTRADA (Requisito 1)
# ==============================================================================

def validar_nome_responsavel(nome: str) -> bool:
    """
    Sanitiza e valida o nome do responsável (Requisito 1).
    Rejeita campos vazios, strings contendo dígitos numéricos ou nomes com menos de 2 letras.
    """
    nome_limpo = nome.strip()

    # Não pode ser vazio nem conter menos de 2 caracteres
    if len(nome_limpo) < 2:
        return False

    # Percorre caractere por caractere: se encontrar qualquer dígito numérico, rejeita
    for caractere in nome_limpo:
        if caractere.isdigit():
            return False

    return True


# ==============================================================================
# 4. OPERAÇÕES DE CRUD DE ATIVOS (Requisitos 3, 4, 5, 6, 9)
# ==============================================================================

def cadastrar_ativo(
    banco: dict,
    id_ativo: int,
    hostname: str,
    responsavel: str,
    localizacao: str,
    tipo_codigo: int
) -> bool:
    """
    [C - CREATE] Cadastra um novo ativo de TI no dicionário em memória (Requisito 3).
    Garante a unicidade do identificador, validação contra números no responsável e tipo via Enum.
    """
    # Validação 1: Verificação de chave primária duplicada no dicionário (Requisito 3)
    if id_ativo in banco:
        print(f"Erro: O identificador {id_ativo} já está em uso.")
        return False

    # Validação 2: Validação de segurança do nome do responsável (Requisito 1)
    if not validar_nome_responsavel(responsavel):
        print(f"Erro: Nome de responsável '{responsavel}' inválido. Não são permitidos números ou campos vazios.")
        return False

    # Validação 3: Hostname e localização não podem ficar em branco (Requisito 1)
    if not hostname.strip() or not localizacao.strip():
        print("Erro: Hostname e localização não podem ficar em branco.")
        return False

    # Validação 4: Validação do tipo de ativo contra a enumeração (Requisito 2)
    try:
        tipo_validado = TipoAtivo(tipo_codigo)
    except ValueError:
        print(f"Erro: Código {tipo_codigo} inválido para tipo de ativo.")
        return False

    # Estrutura do registro inserida na tabela hash em tempo O(1) (Requisitos 3 e 9)
    banco[id_ativo] = {
        "id": id_ativo,
        "hostname": hostname.strip(),
        "responsavel": responsavel.strip(),
        "localizacao": localizacao.strip(),
        "tipo": tipo_validado.name,
        "tipo_codigo": tipo_validado.value,
        "vulnerabilidades": []
    }
    return True


def buscar_ativo_por_id(banco: dict, id_ativo: int) -> dict | None:
    """
    [R - READ] Recupera um ativo pela chave primária inteira (Requisitos 4 e 9).
    Acesso direto via hash map com complexidade média O(1).
    """
    return banco.get(id_ativo)


def buscar_ativos_por_hostname(banco: dict, termo_busca: str) -> list[dict]:
    """
    [R - READ] Busca ativos cujo hostname contenha o termo pesquisado (Requisito 4).
    Varredura linear sobre os valores do dicionário com complexidade O(n).
    """
    termo = termo_busca.strip().lower()
    resultados = []
    for ativo in banco.values():
        if termo in ativo["hostname"].lower():
            resultados.append(ativo)
    return resultados


def atualizar_ativo(
    banco: dict,
    id_ativo: int,
    novo_hostname: str = None,
    novo_responsavel: str = None,
    nova_localizacao: str = None,
    novo_tipo_codigo: int = None
) -> bool:
    """
    [U - UPDATE] Atualiza dados cadastrais de um ativo existente (Requisito 5).
    Aplica validações de segurança aos novos dados e mantém a lista de vulnerabilidades intacta.
    """
    if id_ativo not in banco:
        print(f"Erro: Ativo com ID {id_ativo} não encontrado.")
        return False

    ativo = banco[id_ativo]

    # Atualiza o hostname se fornecido e não vazio
    if novo_hostname is not None:
        if not novo_hostname.strip():
            print("Erro: O novo hostname não pode ser vazio.")
            return False
        ativo["hostname"] = novo_hostname.strip()

    # Atualiza o responsável aplicando a validação anti-números
    if novo_responsavel is not None:
        if not validar_nome_responsavel(novo_responsavel):
            print(f"Erro: Novo nome de responsável '{novo_responsavel}' inválido.")
            return False
        ativo["responsavel"] = novo_responsavel.strip()

    # Atualiza a localização se fornecida e não vazia
    if nova_localizacao is not None:
        if not nova_localizacao.strip():
            print("Erro: A nova localização não pode ser vazia.")
            return False
        ativo["localizacao"] = nova_localizacao.strip()

    # Atualiza o tipo validando contra o Enum
    if novo_tipo_codigo is not None:
        try:
            tipo_validado = TipoAtivo(novo_tipo_codigo)
            ativo["tipo"] = tipo_validado.name
            ativo["tipo_codigo"] = tipo_validado.value
        except ValueError:
            print(f"Erro: Código {novo_tipo_codigo} inválido. Tipo anterior mantido.")
            return False

    return True


def deletar_ativo(banco: dict, id_ativo: int) -> bool:
    """
    [D - DELETE] Remove o ativo da tabela hash da memória (Requisito 6).
    Como a lista de vulnerabilidades fica contida no registro do ativo,
    todas as vulnerabilidades associadas são eliminadas em cascata automaticamente.
    """
    if id_ativo not in banco:
        print(f"Erro: Ativo com ID {id_ativo} não existe na base.")
        return False

    del banco[id_ativo]
    return True


# ==============================================================================
# 5. GESTÃO DE VULNERABILIDADES ASSOCIADAS (Requisitos 7 e 8)
# ==============================================================================

def cadastrar_vulnerabilidade(
    banco: dict,
    id_ativo: int,
    descricao: str,
    categoria: str,
    severidade_nome: str,
    status_nome: str
) -> bool:
    """
    Cadastra uma vulnerabilidade associada a um ativo existente (Requisito 7).
    Valida campos obrigatórios e checa valores contra as enumerações Severidade e StatusTratamento.
    """
    # 1. Verifica se o ativo pai existe na base
    if id_ativo not in banco:
        print(f"Erro: Ativo com ID {id_ativo} não encontrado. Impossível associar vulnerabilidade.")
        return False

    # 2. Validação de campos de texto não vazios (Requisito 1)
    desc_limpa = descricao.strip()
    cat_limpa = categoria.strip()
    if not desc_limpa or not cat_limpa:
        print("Erro: Descrição e categoria da vulnerabilidade não podem ficar em branco.")
        return False

    # 3. Validação da Severidade contra o Enum (Requisito 7)
    try:
        severidade_validada = Severidade(severidade_nome.strip())
    except ValueError:
        opcoes_sev = [s.value for s in Severidade]
        print(f"Erro: Severidade '{severidade_nome}' inválida. Opções válidas: {opcoes_sev}")
        return False

    # 4. Validação do Status contra o Enum (Requisito 7)
    try:
        status_validado = StatusTratamento(status_nome.strip())
    except ValueError:
        opcoes_st = [st.value for st in StatusTratamento]
        print(f"Erro: Status '{status_nome}' inválido. Opções válidas: {opcoes_st}")
        return False

    # 5. Estruturação do registro da vulnerabilidade
    registro_vulnerabilidade = {
        "descricao": desc_limpa,
        "categoria": cat_limpa,
        "severidade": severidade_validada.value,
        "status": status_validado.value
    }

    # 6. Inserção na lista interna do ativo pai em tempo amortizado O(1)
    banco[id_ativo]["vulnerabilidades"].append(registro_vulnerabilidade)
    return True


def listar_vulnerabilidades_ativo(banco: dict, id_ativo: int) -> bool:
    """
    Exibe as vulnerabilidades associadas a um ativo de forma estruturada (Requisito 8).
    Informa explicitamente se o ativo estiver sem vulnerabilidades registradas.
    """
    if id_ativo not in banco:
        print(f"Erro: Ativo com ID {id_ativo} não encontrado.")
        return False

    ativo = banco[id_ativo]
    vulnerabilidades = ativo.get("vulnerabilidades", [])

    print(f"\n=== VULNERABILIDADES DO ATIVO {id_ativo} ({ativo['hostname']}) ===")

    # Atendimento estrito ao Requisito 8 quando a lista estiver vazia
    if not vulnerabilidades:
        print("Ativo sem vulnerabilidades registradas.")
        return True

    for indice, vuln in enumerate(vulnerabilidades, start=1):
        print(f"\n[{indice}] Categoria:  {vuln['categoria']}")
        print(f"    Descrição:  {vuln['descricao']}")
        print(f"    Severidade: {vuln['severidade']}")
        print(f"    Status:     {vuln['status']}")

    return True

# ==============================================================================
# 6. INTERFACE DE USUÁRIO E MENU PRINCIPAL (Requisito 1)
# ==============================================================================

def menu_principal():
    """
    Controlador central da interface em linha de comando (CLI).
    Garante o ciclo de vida da aplicação com persistência e tolerância a falhas.
    """
    global banco_ativos

    # Carregamento seguro dos dados persistidos ao inicializar o sistema (Requisito 3)
    banco_ativos = carregar_dados_de_arquivo()
    print("Base de dados carregada com sucesso.")

    while True:
        print("\n" + "=" * 48)
        print("  SISTEMA DE GESTÃO DE ATIVOS E VULNERABILIDADES")
        print("=" * 48)
        print("1. Cadastrar Ativo")
        print("2. Buscar Ativo por ID")
        print("3. Buscar Ativo por Hostname")
        print("4. Atualizar Ativo")
        print("5. Deletar Ativo")
        print("6. Cadastrar Vulnerabilidade")
        print("7. Listar Vulnerabilidades de um Ativo")
        print("8. Salvar Base de Dados em Disco")
        print("0. Sair do Sistema")
        print("-" * 48)

        opcao = input("Selecione uma opção: ").strip()

        if opcao == "1":
            print("\n--- CADASTRO DE NOVO ATIVO ---")
            try:
                id_ativo = int(input("Informe o ID numérico do ativo: ").strip())
            except ValueError:
                print("Erro: O identificador deve ser um número inteiro válido.")
                continue

            hostname = input("Informe o Hostname (ex: srv-db-01): ")
            responsavel = input("Informe o Responsável (sem números): ")
            localizacao = input("Informe a Localização física/lógica: ")

            print("\nCategorias disponíveis:")
            for tipo in TipoAtivo:
                print(f"  [{tipo.value}] {tipo.name}")

            try:
                tipo_codigo = int(input("Código da categoria: ").strip())
            except ValueError:
                print("Erro: Código de categoria deve ser numérico.")
                continue

            if cadastrar_ativo(banco_ativos, id_ativo, hostname, responsavel, localizacao, tipo_codigo):
                print(f"Ativo ID {id_ativo} cadastrado com sucesso!")

        elif opcao == "2":
            print("\n--- BUSCA DE ATIVO POR ID ---")
            try:
                id_ativo = int(input("Informe o ID a pesquisar: ").strip())
            except ValueError:
                print("Erro: O ID informado deve ser um número inteiro.")
                continue

            ativo = buscar_ativo_por_id(banco_ativos, id_ativo)
            if ativo:
                print(f"\n[ID {ativo['id']}] Hostname: {ativo['hostname']}")
                print(f"  Responsável: {ativo['responsavel']}")
                print(f"  Localização: {ativo['localizacao']}")
                print(f"  Categoria:   {ativo['tipo']} (Código {ativo['tipo_codigo']})")
                print(f"  Qtd. Vulnerabilidades: {len(ativo['vulnerabilidades'])}")
            else:
                print(f"Nenhum ativo localizado com o ID {id_ativo}.")

        elif opcao == "3":
            print("\n--- BUSCA DE ATIVOS POR HOSTNAME ---")
            termo = input("Informe o termo de busca: ")
            resultados = buscar_ativos_por_hostname(banco_ativos, termo)
            if resultados:
                print(f"\n{len(resultados)} registro(s) encontrado(s):")
                for at in resultados:
                    print(f"  - [ID {at['id']}] {at['hostname']} | {at['tipo']} | Resp: {at['responsavel']}")
            else:
                print(f"Nenhum ativo encontrado contendo o termo '{termo}'.")

        elif opcao == "4":
            print("\n--- ATUALIZAÇÃO DE ATIVO ---")
            try:
                id_ativo = int(input("Informe o ID do ativo a ser atualizado: ").strip())
            except ValueError:
                print("Erro: O ID deve ser numérico.")
                continue

            if id_ativo not in banco_ativos:
                print(f"Erro: Ativo com ID {id_ativo} não encontrado.")
                continue

            print("Pressione Enter sem digitar nada caso queira manter o valor atual.")
            novo_host = input(f"Novo Hostname [{banco_ativos[id_ativo]['hostname']}]: ").strip()
            novo_resp = input(f"Novo Responsável [{banco_ativos[id_ativo]['responsavel']}]: ").strip()
            nova_loc = input(f"Nova Localização [{banco_ativos[id_ativo]['localizacao']}]: ").strip()

            print("\nCategorias disponíveis:")
            for tipo in TipoAtivo:
                print(f"  [{tipo.value}] {tipo.name}")
            tipo_input = input(f"Novo Código de Categoria [{banco_ativos[id_ativo]['tipo_codigo']}]: ").strip()

            novo_tipo = None
            if tipo_input:
                try:
                    novo_tipo = int(tipo_input)
                except ValueError:
                    print("Erro: Código de categoria deve ser um número.")
                    continue

            atualizar_ativo(
                banco=banco_ativos,
                id_ativo=id_ativo,
                novo_hostname=novo_host if novo_host else None,
                novo_responsavel=novo_resp if novo_resp else None,
                nova_localizacao=nova_loc if nova_loc else None,
                novo_tipo_codigo=novo_tipo
            )
            print(f"Dados do ativo ID {id_ativo} atualizados.")

        elif opcao == "5":
            print("\n--- REMOÇÃO DE ATIVO ---")
            try:
                id_ativo = int(input("Informe o ID do ativo a remover: ").strip())
            except ValueError:
                print("Erro: O ID deve ser numérico.")
                continue

            if deletar_ativo(banco_ativos, id_ativo):
                print(f"Ativo ID {id_ativo} e suas vulnerabilidades foram removidos com sucesso.")

        elif opcao == "6":
            print("\n--- CADASTRO DE VULNERABILIDADE ---")
            try:
                id_ativo = int(input("Informe o ID do ativo afetado: ").strip())
            except ValueError:
                print("Erro: O ID deve ser numérico.")
                continue

            if id_ativo not in banco_ativos:
                print(f"Erro: Ativo ID {id_ativo} não existe.")
                continue

            descricao = input("Descrição da vulnerabilidade: ")
            categoria = input("Categoria (ex: Software desatualizado, Configuração insegura): ")

            print("\nSeveridades válidas: " + ", ".join([s.value for s in Severidade]))
            severidade = input("Severidade: ")

            print("Status válidos: " + ", ".join([st.value for st in StatusTratamento]))
            status = input("Status do tratamento: ")

            if cadastrar_vulnerabilidade(banco_ativos, id_ativo, descricao, categoria, severidade, status):
                print("Vulnerabilidade associada com sucesso ao ativo!")

        elif opcao == "7":
            print("\n--- LISTAGEM DE VULNERABILIDADES ---")
            try:
                id_ativo = int(input("Informe o ID do ativo para auditoria: ").strip())
            except ValueError:
                print("Erro: O ID deve ser numérico.")
                continue

            listar_vulnerabilidades_ativo(banco_ativos, id_ativo)

        elif opcao == "8":
            print("\n--- PERSISTÊNCIA MANUAL ---")
            if salvar_dados_em_arquivo(banco_ativos):
                print(f"Base salva com sucesso no arquivo '{NOME_ARQUIVO_BANCO}'.")

        elif opcao == "0":
            print("\nSalva base antes de finalizar...")
            salvar_dados_em_arquivo(banco_ativos)
            print("Sistema encerrado com sucesso.")
            break

        else:
            print("Erro: Opção inválida. Por favor, escolha um item entre 0 e 8.")


if __name__ == "__main__":
    menu_principal()