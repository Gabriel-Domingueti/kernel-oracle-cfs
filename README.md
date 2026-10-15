# KernelOracle Sentinel

**Sistema de Deteção de Intrusões (IDS) ao nível do Kernel Linux baseado em Deep Learning.**

O KernelOracle Sentinel é um projeto de pesquisa em cibersegurança que utiliza redes neurais LSTM para prever as fatias de tempo alocadas pelo escalonador do Linux (*Completely Fair Scheduler* - CFS). Ao antecipar o comportamento normal do processador, o sistema transforma-se num oráculo de segurança: qualquer discrepância drástica entre a previsão matemática e a execução real atua como um alarme imediato contra ameaças agressivas, como *cryptominers* e ataques de negação de serviço ao nível de CPU.

## Arquitetura do Repositório

O projeto documenta a evolução da pesquisa em duas fases distintas:

*   **[`v1/`](v1/): Prova de Conceito (Offline)** - Fase inicial utilizando a ferramenta `perf` para extração estática de dados, treino em *batch* e visualização de padrões de escalonamento através de um *dashboard* interativo em Streamlit.
*   **[`v2/`](v2/): Motor IDS em Tempo Real (eBPF)** - Evolução para um sistema de defesa ativo. Utiliza a tecnologia **eBPF (Extended Berkeley Packet Filter)** para monitorização com zero latência no kernel e *Online Learning* (aprendizagem contínua), eliminando a necessidade de bases de dados estáticas.

## Requisitos Globais
*   Sistema Operativo: Linux (Kernel 5.15+ recomendado para suporte total a eBPF)
*   Python 3.8+
*   Criar e ativar o ambiente virtual: `python3 -m venv venv & source venv/bin/activate`
*   Dependências Python: `pip install -r requirements.txt`

---
*Projeto desenvolvido para exploração de segurança em baixo nível e aplicação de Machine Learning na defesa de infraestruturas.*