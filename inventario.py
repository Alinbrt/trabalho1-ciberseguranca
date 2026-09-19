"""
Módulo de Inventário de Ativos e Gestão de Vulnerabilidades
Atividade Avaliativa 1 - Cibersegurança UFU
"""

import json
import os
from enum import Enum


class TipoAtivo(Enum):
    """
    Enumeração para os tipos de ativos de TI (Requisito 2).
    Mapeia cada categoria a um código numérico inteiro fixo.
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

banco_ativos = {}

NOME_ARQUIVO_BANCO = "banco_ativos.txt"


def salvar_dados_em_arquivo(dados: dict, caminho_arquivo: str = NOME_ARQUIVO_BANCO) -> bool:
    """
    Grava o dicionário principal de ativos em um arquivo de texto estruturado (Requisito 3).
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
    Carrega os registros do arquivo de texto para a memória ao iniciar o sistema.
    Trata erro de arquivo inexistente ou corrompido criando uma base limpa.
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
