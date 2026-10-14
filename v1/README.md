# KernelOracle: Previsão do Escalonador CFS com Deep Learning

Este projeto implementa uma arquitetura baseada em inteligência artificial para prever a sequência de tarefas selecionadas pelo *Completely Fair Scheduler* (CFS) do Linux. Utilizando uma rede neural *Long Short-Term Memory* (LSTM), o objetivo é modelar o comportamento de alocação de tempo de CPU, abrindo caminho para decisões de escalonamento mais adaptativas perante diferentes cargas de trabalho.

## Estrutura da Arquitetura
O pipeline do projeto está dividido em três fases fundamentais:
* **Geração de Carga e Captura (C e Linux Perf):** Um script nativo gera contenção assimétrica de CPU e I/O, enquanto o utilitário `perf` regista as decisões exatas de preempção do kernel.
* **Engenharia de Dados e Modelação (Python e PyTorch):** Extração da diferença de tempo entre os escalonamentos consecutivos e treino de uma rede LSTM capaz de reconhecer os padrões sequenciais e a magnitude das fatias de tempo.
* **Visualização Dinâmica (Streamlit):** Um *dashboard* interativo que contrasta as previsões do modelo treinado com o comportamento real do CFS, evidenciando a capacidade da rede em antecipar a alocação de tarefas.

## Requisitos do Sistema
* Sistema Operacional baseado em Linux (testado no Arch Linux).
* GCC (para compilação do gerador de carga nativo).
* Ferramentas nativas do kernel: `linux-tools-common`, `linux-tools-generic`.
* Python 3.8+.

## Instalação e Configuração

Clone o repositório e crie um ambiente virtual Python para isolar as dependências:
```bash
git clone https://github.com/Gabriel-Domingueti/kernel-oracle-cfs.git
cd kernel-oracle-cfs

# Criar e ativar o ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instalar as dependências do projeto
pip install -r requirements.txt
```
## Como Executar

Certifica-se de que o ambiente virtual está ativado (`source venv/bin/activate`) antes de executar os scripts em Python.

**1. Geração de Dados**
Compila o gerador de estresse em C e inicia a execução. Em outro terminal, utiliza o utilitário `perf` para registar as métricas de escalonamento do kernel:
```bash
gcc -o scripts/stress_cfs scripts/stress_cfs.c -lpthread
./scripts/stress_cfs

# Em outro terminal:
sudo perf sched record -- sleep 50
sudo perf sched script > data/escalonamento_raw.txt
```

**2. Pré-processamento e Treino**
Converte os dados brutos em um dataset limpo e inicia o treino da rede LSTM:
```bash
python3 scripts/pre_processamento.py
python3 scripts/treinar_lstm.py
```

**3. Lançamento do Dashboard**
Visualiza graficamente o comportamento real do CFS em contraste com as previsões da rede neural:
```bash
streamlit run dashboard/app.py
```