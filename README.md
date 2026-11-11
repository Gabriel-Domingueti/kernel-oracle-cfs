# KernelOracle Sentinel: Prevenção de Intrusões (IPS) no Escalonador Linux CFS via eBPF, Deep Learning (LSTM) e Cadeias de Markov

O **KernelOracle Sentinel** é um Sistema de Detecção e Prevenção de Intrusões (IDS/IPS) autônomo que opera diretamente na fronteira entre o espaço do kernel (Anel 0) e o espaço de usuário no Linux. Em vez de depender de assinaturas estáticas de arquivos ou regras heurísticas fixas, o Sentinel intercepta eventos de troca de contexto do escalonador **CFS (*Completely Fair Scheduler*)** em tempo real via **eBPF** (`sched:sched_switch`) para identificar e neutralizar ameaças *zero-day* de exaustão de CPU — como *cryptojackers* (RandomX/XMRig) e *ransomwares* — através de uma arquitetura híbrida que funde **Redes Neurais Recorrentes (LSTM)** e **Cadeias de Markov de Tempo Discreto (DTMC)**.

---

## Arquitetura do Sistema e Fluxo de Operação

1. **Telemetria no Anel 0 (eBPF / BCC):** Um programa eBPF acoplado ao tracepoint nativo `sched:sched_switch` calcula, em nanossegundos, o tempo exato de retenção de CPU ($\Delta t$) de cada thread antes de ceder o núcleo, extraindo o `pid`, o grupo de threads real (`tgid`) e o nome do processo (`comm`) com *overhead* residual.
2. **Modelagem Temporal (Rede LSTM):** Uma rede *Long Short-Term Memory* analisa janelas deslizantes de 30 eventos consecutivos para prever a duração esperada da próxima fatia de tempo ($\hat{y}_t$), quantificando o erro de regressão temporal $E_{\text{LSTM}} = \vert{}\hat{y}_t - y_t\vert{}$.
3. **Modelagem Estocástica (Cadeia de Markov — DTMC):** As fatias de tempo são discretizadas em três regimes operacionais do CFS ($S_0$: Cooperativo/I/O-bound, $S_1$: Moderado, $S_2$: Exaustão/CPU-bound). Uma matriz estocástica $P_{3 \times 3}$ com suavização de Laplace avalia a surpresa informacional (Log-Likelihood negativo) de cada transição $S_i \to S_j$.
4. **Fusão Híbrida e Mitigação Ativa (IPS via `systemd`):** Os scores da LSTM ($60\%$) e da Cadeia de Markov ($40\%$) são fundidos e comparados contra o limiar ótimo estatístico calculado pelo **Índice $J$ de Youden**. Um **Acumulador de Risco Estocástico** aplica decaimento exponencial ($\times 0.85$) a processos benignos que retornam ao estado cooperativo $S_0$ e abate instantaneamente com `SIGKILL` (`os.kill(tgid, signal.SIGKILL)`) processos maliciosos que atingem o limiar crítico de retenção em $S_2 \to S_2$.

---

## Evolução do Projeto (`v1` $\to$ `v2` $\to$ `v3`)

O repositório está organizado de forma modular para documentar toda a evolução experimental e arquitetural da pesquisa:

| Versão | Diretório | Foco Arquitetural | Principais Características |
| :--- | :---: | :--- | :--- |
| **v1** | [`./v1`](./v1) | **Prova de Conceito (PoC)** | Captura inicial de eventos do escalonador via eBPF e validação do acoplamento com tensores PyTorch em tempo real. |
| **v2** | [`./v2`](./v2) | **Detector Online (IDS)** | Aprendizado online contínuo com rede LSTM, normalização de janelas temporais e calibração de carga com simulador multi-thread (`malware_sim.c`). |
| **v3 (Atual)** | [`./v3`](./v3) | **Motor IPS Híbrido & Produção** | Fusão **LSTM + Cadeia de Markov**, treino único serializado (`pickle`), calibração via Curva ROC (Índice de Youden), acumulador estocástico de risco, abate ativo (`SIGKILL`) e daemon nativo do `systemd` sem caminhos fixos. |

---

## Síntese dos Resultados Experimentais (v3)

A validação científica na **v3** foi conduzida sobre um dataset balanceado de $N = 1000$ trocas de contexto reais do kernel Linux ($500$ amostras de processos legítimos na Classe $0$ e $500$ amostras de ataque multi-thread na Classe $1$), demonstrando que a arquitetura híbrida supera significativamente os modelos isolados[cite: 9, 10]:

| Arquitetura Avaliada | ROC-AUC | Acurácia (%) | Precisão (%) | Recall / TPR (%) | Especificidade / TNR (%) | F1-Score (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Cadeia de Markov Isolada (DTMC) | 0.9717 | — | — | — | — | — |
| Rede LSTM Isolada | 0.9801 | — | — | — | — | — |
| **Híbrido (LSTM + Markov)** | **0.9905** | **97.70** | **96.86** | **98.60** | **96.80** | **97.72** |

*Nota: Métricas de classificação binária avaliadas no limiar ótimo de Youden ($\tau = 0.0194$), resultando em $TP = 493$, $TN = 484$, $FP = 16$, $FN = 7$ e Índice de Youden $J = 0.9540$[cite: 9, 10].*

### Artefatos Gráficos Gerados Automaticamente (`v3/metrics/`)
* **`curva_roc.png`**: Comparativo triplo das Curvas ROC (LSTM Isolada vs. Cadeia de Markov vs. Modelo Híbrido)[cite: 9].
* **`matriz_confusao.png`**: Matriz de confusão do detector híbrido no limiar ótimo[cite: 10].
* **`matriz_transicao_markov.png`**: Mapa de calor das probabilidades empíricas de transição de estados ($S_0, S_1, S_2$) do escalonador CFS[cite: 11].

---

## Estrutura Geral do Repositório

```text
kernel-oracle-cfs/
├── v1/                             # Prova de Conceito inicial (Telemetria eBPF + PyTorch)
├── v2/                             # Detector IDS com aprendizado online contínuo
├── v3/                             # Versão de Produção: IPS Híbrido (LSTM + Markov) + Systemd Daemon
│   ├── artifacts/                  # Modelo e matrizes serializados (sentinel_bundle.pkl)
│   ├── metrics/                    # Gráficos científicos em 300 DPI (ROC, Confusão e Markov)
│   ├── scripts/                    # Pipeline de treino/avaliação, daemon IPS e simulador em C
│   ├── systemd/                    # Template agnóstico do serviço sentinel.service
│   ├── install_service.sh          # Instalador automatizado do daemon no systemd
│   ├── requirements.txt            # Dependências Python (CPU-only)
│   └── README.md                   # Documentação matemática e guia completo da v3
└── README.md                       # Visão geral do projeto (este arquivo)
```

---

## Guia Rápido de Execução (Versão de Produção — `v3`)

Para instruções detalhadas e protocolos de teste com payloads reais de *cryptojacking* (**XMRig / RandomX**), consulte a [documentação dedicada da v3](./v3/README.md). Abaixo está o resumo rápido para colocar o IPS em operação:

### 1. Instalar Dependências do Kernel e Compiladores

**Debian / Ubuntu / Linux Mint:**

```bash
sudo apt update
sudo apt install -y build-essential bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-venv
```

**Fedora / RHEL:**

```bash
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r) kernel-headers gcc
```

### 2. Criar Ambiente Virtual e Instalar Pacotes Python

```bash
git clone [https://github.com/Gabriel-Domingueti/kernel-oracle-cfs.git](https://github.com/Gabriel-Domingueti/kernel-oracle-cfs.git)
cd kernel-oracle-cfs/v3
python3 -m venv ../venv --system-site-packages
source ../venv/bin/activate
pip install -r requirements.txt
```

### 3. Compilar Simulador, Treinar Modelo Híbrido e Gerar Gráficos

```bash
gcc -O0 -o scripts/malware_sim scripts/malware_sim.c -lpthread
sudo ../venv/bin/python scripts/train_and_eval.py
```

### 4. Instalar e Ativar o Daemon IPS no `systemd`

```bash
chmod +x install_service.sh
./install_service.sh
```

### 5. Monitorar o Abate de Ameaças em Tempo Real

Em um terminal, acompanhe os logs do serviço:

```bash
sudo journalctl -u sentinel.service -f
```

Em outro terminal, execute o simulador de estresse:

```bash
./scripts/malware_sim
```

O daemon identificará a retenção anômala no estado $S_2 \to S_2$ e encerrará o grupo de processos automaticamente com `SIGKILL`.

---

## Requisitos de Ambiente e Reprodutibilidade

* **Sistema Operacional:** Linux com kernel $\ge 5.15$ (testado nos kernels $6.8+$ e $6.11+$ em Fedora Workstation e Linux Mint / Ubuntu).
* **Execução em CPU:** Projetado especificamente para operar sem necessidade de GPU dedicada (`torch+cpu`), viabilizando a implantação direta em servidores de produção, máquinas virtuais e ambientes de borda (*edge*).
* **Privilégios:** Requer acesso `root` (`CAP_BPF` / `CAP_SYS_ADMIN`) para injeção do bytecode eBPF no verificador do kernel e emissão de sinais `SIGKILL` entre processos.