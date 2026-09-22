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