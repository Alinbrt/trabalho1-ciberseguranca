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
    Converte as chaves do dicionário de volta para números inteiros (int),
    resolvendo a incompatibilidade de tipos gerada pelo JSON.
    """
    if not os.path.exists(caminho_arquivo):
        return {}

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
            conteudo = arquivo.read().strip()
            if not conteudo:
                return {}
            dados_brutos = json.loads(conteudo)
            
            # Converte chaves de string ("1") de volta para inteiro (1)
            banco_convertido = {}
            for chave, valor in dados_brutos.items():
                try:
                    chave_int = int(chave)
                    banco_convertido[chave_int] = valor
                except ValueError:
                    banco_convertido[chave] = valor
            return banco_convertido
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

    if len(nome_limpo) < 2:
        return False

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
    if id_ativo in banco:
        print(f"Erro: O identificador {id_ativo} já está em uso.")
        return False

    if not validar_nome_responsavel(responsavel):
        print(f"Erro: Nome de responsável '{responsavel}' inválido. Não são permitidos números ou campos vazios.")
        return False

    if not hostname.strip() or not localizacao.strip():
        print("Erro: Hostname e localização não podem ficar em branco.")
        return False

    try:
        tipo_validado = TipoAtivo(tipo_codigo)
    except ValueError:
        print(f"Erro: Código {tipo_codigo} inválido para tipo de ativo.")
        return False

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

    if novo_hostname is not None:
        if not novo_hostname.strip():
            print("Erro: O novo hostname não pode ser vazio.")
            return False
        ativo["hostname"] = novo_hostname.strip()

    if novo_responsavel is not None:
        if not validar_nome_responsavel(novo_responsavel):
            print(f"Erro: Novo nome de responsável '{novo_responsavel}' inválido.")
            return False
        ativo["responsavel"] = novo_responsavel.strip()

    if nova_localizacao is not None:
        if not nova_localizacao.strip():
            print("Erro: A nova localização não pode ser vazia.")
            return False
        ativo["localizacao"] = nova_localizacao.strip()

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
    Elimina em cascata todas as vulnerabilidades contidas nele.
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
    if id_ativo not in banco:
        print(f"Erro: Ativo com ID {id_ativo} não encontrado. Impossível associar vulnerabilidade.")
        return False

    desc_limpa = descricao.strip()
    cat_limpa = categoria.strip()
    if not desc_limpa or not cat_limpa:
        print("Erro: Descrição e categoria da vulnerabilidade não podem ficar em branco.")
        return False

    try:
        severidade_validada = Severidade(severidade_nome.strip())
    except ValueError:
        opcoes_sev = [s.value for s in Severidade]
        print(f"Erro: Severidade '{severidade_nome}' inválida. Opções válidas: {opcoes_sev}")
        return False

    try:
        status_validado = StatusTratamento(status_nome.strip())
    except ValueError:
        opcoes_st = [st.value for st in StatusTratamento]
        print(f"Erro: Status '{status_nome}' inválido. Opções válidas: {opcoes_st}")
        return False

    registro_vulnerabilidade = {
        "descricao": desc_limpa,
        "categoria": cat_limpa,
        "severidade": severidade_validada.value,
        "status": status_validado.value
    }

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
# 6. MENU INTERATIVO COM REPETIÇÃO E TRATAMENTO DE ERROS
# ==============================================================================

def menu_principal():
    global banco_ativos
    banco_ativos = carregar_dados_de_arquivo()

    while True:
        print("\n" + "=" * 50)
        print("   SISTEMA DE INVENTÁRIO E GESTÃO DE VULNERABILIDADES")
        print("=" * 50)
        print("1 - Cadastrar Ativo")
        print("2 - Buscar Ativo por ID")
        print("3 - Buscar Ativo por Hostname")
        print("4 - Atualizar Ativo")
        print("5 - Deletar Ativo")
        print("6 - Cadastrar Vulnerabilidade em Ativo")
        print("7 - Listar Vulnerabilidades de um Ativo")
        print("8 - Listar Todos os Ativos")
        print("0 - Sair e Salvar Dados")
        print("=" * 50)

        opcao = input("Selecione uma opção: ").strip()

        if opcao == "1":
            try:
                id_ativo = int(input("ID do Ativo (número inteiro): ").strip())
                if id_ativo in banco_ativos:
                    print(f"Erro: O identificador {id_ativo} já está em uso.")
                    continue

                hostname = input("Hostname: ").strip()
                if not hostname:
                    print("Erro: O hostname não pode ficar vazio.")
                    continue

                responsavel = input("Responsável (sem números): ").strip()
                if not validar_nome_responsavel(responsavel):
                    print("Erro: Nome de responsável inválido. Não use números nem deixe em branco.")
                    continue

                localizacao = input("Localização física/lógica: ").strip()
                if not localizacao:
                    print("Erro: Localização não pode ficar vazia.")
                    continue

                print("\nTipos disponíveis:")
                for t in TipoAtivo:
                    print(f"  {t.value} - {t.name}")

                # Laço de repetição para garantir tipo válido
                while True:
                    try:
                        tipo_cod = int(input("Código do Tipo: ").strip())
                        if tipo_cod in [t.value for t in TipoAtivo]:
                            break
                        print("Código inválido. Digite um dos números listados acima.")
                    except ValueError:
                        print("Por favor, digite um número inteiro.")

                if cadastrar_ativo(banco_ativos, id_ativo, hostname, responsavel, localizacao, tipo_cod):
                    salvar_dados_em_arquivo(banco_ativos)
                    print("[+] Ativo cadastrado com sucesso!")
            except ValueError:
                print("Erro: ID deve ser um número inteiro.")

        elif opcao == "2":
            try:
                id_ativo = int(input("ID do Ativo a buscar: ").strip())
                ativo = buscar_ativo_por_id(banco_ativos, id_ativo)
                if ativo:
                    print(f"\n[ID {ativo['id']}] Hostname: {ativo['hostname']} | Tipo: {ativo['tipo']} | Resp: {ativo['responsavel']} | Local: {ativo['localizacao']}")
                else:
                    print(f"Ativo com ID {id_ativo} não encontrado.")
            except ValueError:
                print("Erro: O ID deve ser um número inteiro.")

        elif opcao == "3":
            termo = input("Termo de busca no Hostname: ").strip()
            encontrados = buscar_ativos_por_hostname(banco_ativos, termo)
            if encontrados:
                print(f"\nResultados encontrados ({len(encontrados)}):")
                for at in encontrados:
                    print(f"  [ID {at['id']}] {at['hostname']} ({at['tipo']}) - Resp: {at['responsavel']} - Local: {at['localizacao']}")
            else:
                print("Nenhum ativo correspondente localizado.")

        elif opcao == "4":
            try:
                id_ativo = int(input("ID do Ativo a atualizar: ").strip())
                if id_ativo not in banco_ativos:
                    print(f"Ativo com ID {id_ativo} não encontrado.")
                    continue

                novo_host = input("Novo Hostname (Enter para manter): ").strip() or None
                novo_resp = input("Novo Responsável (Enter para manter): ").strip() or None
                nova_loc = input("Nova Localização (Enter para manter): ").strip() or None
                
                print("Tipos: 1-NOTEBOOK | 2-SERVIDOR | 3-ROTEADOR | 4-ESTACAO_TRABALHO | 5-APLICACAO_WEB | 6-BANCO_DE_DADOS")
                novo_cod = None
                cod_input = input("Novo Código de Tipo (Enter para manter): ").strip()
                if cod_input:
                    try:
                        novo_cod = int(cod_input)
                    except ValueError:
                        print("Código inválido. Atualização cancelada.")
                        continue

                if atualizar_ativo(banco_ativos, id_ativo, novo_host, novo_resp, nova_loc, novo_cod):
                    salvar_dados_em_arquivo(banco_ativos)
                    print("[+] Ativo atualizado com sucesso!")
            except ValueError:
                print("Erro: O ID deve ser numérico.")

        elif opcao == "5":
            try:
                id_ativo = int(input("ID do Ativo a deletar: ").strip())
                if deletar_ativo(banco_ativos, id_ativo):
                    salvar_dados_em_arquivo(banco_ativos)
                    print("[+] Ativo e vulnerabilidades removidos com sucesso.")
            except ValueError:
                print("Erro: O ID deve ser um número inteiro.")

        elif opcao == "6":
            try:
                id_ativo = int(input("ID do Ativo: ").strip())
                if id_ativo not in banco_ativos:
                    print(f"Erro: Ativo com ID {id_ativo} não encontrado.")
                    continue

                while True:
                    descricao = input("Descrição da vulnerabilidade: ").strip()
                    if descricao:
                        break
                    print("A descrição não pode ficar em branco. Tente novamente.")

                while True:
                    categoria = input("Categoria (ex: Configuração, Software): ").strip()
                    if categoria:
                        break
                    print("A categoria não pode ficar em branco. Tente novamente.")

                # Seleção com repetição para Severidade
                print("\nSeveridades disponíveis:")
                opcoes_sev = list(Severidade)
                for idx, s in enumerate(opcoes_sev, start=1):
                    print(f"  {idx} - {s.value}")

                while True:
                    entrada_sev = input("Escolha a severidade (número ou nome completo): ").strip()
                    severidade_escolhida = None

                    # Aceita número de menu (1, 2, 3, 4)
                    if entrada_sev.isdigit() and 1 <= int(entrada_sev) <= len(opcoes_sev):
                        severidade_escolhida = opcoes_sev[int(entrada_sev) - 1].value
                    else:
                        # Aceita digitação por texto ignorando maiúsculas
                        for s in opcoes_sev:
                            if entrada_sev.lower() == s.value.lower():
                                severidade_escolhida = s.value
                                break

                    if severidade_escolhida:
                        break
                    print("Opção de severidade inválida. Digite o número ou nome correspondente.")

                # Seleção com repetição para Status
                print("\nStatus disponíveis:")
                opcoes_stat = list(StatusTratamento)
                for idx, st in enumerate(opcoes_stat, start=1):
                    print(f"  {idx} - {st.value}")

                while True:
                    entrada_stat = input("Escolha o status (número ou nome completo): ").strip()
                    status_escolhido = None

                    if entrada_stat.isdigit() and 1 <= int(entrada_stat) <= len(opcoes_stat):
                        status_escolhido = opcoes_stat[int(entrada_stat) - 1].value
                    else:
                        for st in opcoes_stat:
                            if entrada_stat.lower() == st.value.lower():
                                status_escolhido = st.value
                                break

                    if status_escolhido:
                        break
                    print("Opção de status inválida. Digite o número ou nome correspondente.")

                if cadastrar_vulnerabilidade(banco_ativos, id_ativo, descricao, categoria, severidade_escolhida, status_escolhido):
                    salvar_dados_em_arquivo(banco_ativos)
                    print("[+] Vulnerabilidade registrada com sucesso!")
            except ValueError:
                print("Erro: O ID do Ativo deve ser um número inteiro.")

        elif opcao == "7":
            try:
                id_ativo = int(input("ID do Ativo para consulta: ").strip())
                listar_vulnerabilidades_ativo(banco_ativos, id_ativo)
            except ValueError:
                print("Erro: O ID deve ser um número inteiro.")

        elif opcao == "8":
            if not banco_ativos:
                print("\nInventário vazio. Nenhum ativo registrado.")
            else:
                print(f"\n--- Inventário Atual ({len(banco_ativos)} ativos) ---")
                for at in banco_ativos.values():
                    print(f"  [ID {at['id']}] {at['hostname']} | Tipo: {at['tipo']} | Resp: {at['responsavel']} | Local: {at['localizacao']} | Vulns: {len(at.get('vulnerabilidades', []))}")

        elif opcao == "0":
            salvar_dados_em_arquivo(banco_ativos)
            print("[+] Base persistida com sucesso em disco. Encerrando o sistema...")
            break
        else:
            print("Opção inválida. Selecione uma opção válida do menu.")


if __name__ == "__main__":
    menu_principal()