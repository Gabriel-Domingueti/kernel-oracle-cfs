# KernelOracle Sentinel: Motor IPS Híbrido (LSTM + Cadeia de Markov) via eBPF (v3)

A **v3** consolida o KernelOracle Sentinel como um **Sistema de Prevenção de Intrusões (IPS)** autônomo de nível de produção para ambientes Linux. Projetada para reprodutibilidade científica e submissão acadêmica internacional, esta versão substitui heurísticas empíricas por uma **Arquitetura Híbrida de Duplo Estágio** que funde **Deep Learning (Rede LSTM)** e **Modelagem Estocástica (Cadeia de Markov de Tempo Discreto — DTMC)** diretamente sobre a telemetria do escalonador CFS (*Completely Fair Scheduler*) no anel 0 do kernel (`sched:sched_switch`).

Ao desacoplar o pipeline em **Treino Único Offline (`train_and_eval.py`)** e **Daemon de Inferência Contínua (`sentinel_daemon.py`)** gerenciado nativamente pelo `systemd`, o sistema opera em modo `torch.no_grad()` com complexidade de consulta estocástica $O(1)$, neutralizando ameaças de exaustão de CPU (como *cryptojackers* RandomX/XMRig) em milissegundos via sinal `SIGKILL`.

---

## Fundamentação Matemática da Arquitetura Híbrida (v3)

### 1. Espaço de Estados Discretos da Cadeia de Markov ($S$)
Cada fatia de tempo de execução ($\Delta t$) capturada pelo tracepoint eBPF é normalizada em relação à janela máxima de escalonamento ($\Delta t_{\text{norm}} \in [0, 1]$, com $\text{max\_norm\_ms} = 10.0\text{ ms}$) e discretizada em três estados operacionais do CFS:
* **$S_0$ (Cooperativo / I/O-Bound):** $\Delta t_{\text{norm}} < 0.08$ ($< 0.8\text{ ms}$) — processos interativos ou que cedem voluntariamente a CPU.
* **$S_1$ (Carga Intermediária):** $0.08 \le \Delta t_{\text{norm}} < 0.35$ ($0.8\text{ ms a } 3.5\text{ ms}$) — processamento moderado dentro da granularidade padrão.
* **$S_2$ (Exaustão / CPU-Bound):** $\Delta t_{\text{norm}} \ge 0.35$ ($\ge 3.5\text{ ms}$) — retenção intensiva do núcleo de processamento.

Durante a fase de treinamento com o comportamento orgânico do sistema, a Matriz de Probabilidades de Transição $P_{3 \times 3}$ é construída com **Suavização de Laplace** ($\alpha_{\text{smooth}} = 1$) para garantir ergodicidade e evitar probabilidades nulas:

$$P_{ij} = P(X_{t+1} = S_j \mid X_t = S_i) = \frac{N_{ij} + 1}{\sum_{k=0}^{2} (N_{ik} + 1)}$$

### 2. Fusão de Decisão (Erro de Regressão LSTM + Log-Likelihood de Markov)
Para cada troca de contexto, o erro temporal da rede LSTM ($E_{\text{LSTM}} = \vert{}\hat{y}_t - y_t\vert{}$) é combinado com a surpresa informacional (Log-Likelihood negativo normalizado) da transição de estado observada $i \to j$:

$$A_{\text{Markov}}(i, j) = \min\left(\frac{-\ln(\max(P_{ij}, \epsilon))}{-\ln(\epsilon)}, 1.0\right), \quad \epsilon = 10^{-4}$$

O **Score Híbrido de Anomalia ($A_{\text{Hybrid}}$)** é dado pela combinação convexa ponderada ($\alpha = 0.60$):

$$A_{\text{Hybrid}} = \alpha \cdot E_{\text{LSTM}} + (1 - \alpha) \cdot A_{\text{Markov}}(i, j)$$

### 3. Acumulador de Risco Estocástico Assíncrono (Prevenção IPS)
Em substituição a contadores estáticos de infrações, o daemon mantém um acumulador de risco dinâmico $R_p$ por grupo de processos (`tgid`):
* Se $A_{\text{Hybrid}} > \tau_{\text{Youden}}$ (limiar ótimo da Curva ROC), o risco cresce proporcionalmente à improbabilidade estocástica da transição: $R_p \leftarrow R_p + (1.0 + A_{\text{Markov}})$.
* Se $A_{\text{Hybrid}} \le \tau_{\text{Youden}}$, processos legítimos que retornam ao estado cooperativo $S_0$ sofrem decaimento exponencial ($R_p \leftarrow R_p \times 0.85$), eliminando falsos positivos.
* Ao atingir $R_p \ge 8.0$, o daemon executa `os.kill(tgid, signal.SIGKILL)`, abatendo toda a árvore de *threads* do processo malicioso.

---

## Resultados Experimentais e Validação Científica

A validação supervisionada foi conduzida sobre um conjunto balanceado de $N = 1000$ amostras de trocas de contexto ($500$ amostras de processos legítimos na Classe $0$ e $500$ amostras de ataque multi-thread na Classe $1$), calibrando o limiar ótimo de decisão através do **Índice $J$ de Youden** ($\tau = 0.0194$)[cite: 9, 10].

### 1. Comparativo de Desempenho das Arquiteturas

| Arquitetura Avaliada | ROC-AUC | Acurácia (%) | Precisão (%) | Recall / TPR (%) | Especificidade / TNR (%) | F1-Score (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Cadeia de Markov Isolada (DTMC) | 0.9717 | — | — | — | — | — |
| Rede LSTM Isolada | 0.9801 | — | — | — | — | — |
| **Híbrido (LSTM + Markov)** | **0.9905** | **97.70** | **96.86** | **98.60** | **96.80** | **97.72** |

*Nota: No limiar ótimo $\tau = 0.0194$, a Matriz de Confusão do Modelo Híbrido registrou $TP = 493$, $TN = 484$, $FP = 16$ e $FN = 7$, alcançando Índice de Youden $J = 0.9540$[cite: 9, 10].*

### 2. Matriz Empírica de Probabilidades de Transição de Markov ($P_{ij}$ — Baseline)

| Estado Atual ($t$) | $S_0$ (Leve: $< 0.8\text{ ms}$) | $S_1$ (Médio: $0.8\text{–}3.5\text{ ms}$) | $S_2$ (Exaustão: $> 3.5\text{ ms}$) |
| :--- | :---: | :---: | :---: |
| **$S_0$ (Leve)** | **0.9858** | 0.0121 | 0.0020 |
| **$S_1$ (Médio)** | **0.9000** | 0.0500 | 0.0500 |
| **$S_2$ (Exaustão)** | **0.6000** | 0.2000 | 0.2000 |

*Interpretação Física:* Em regime normal de operação, $98.58\%$ das transições permanecem no regime cooperativo ($S_0 \to S_0$), e processos legítimos que eventualmente atingem exaustão ($S_2$) cedem a CPU e retornam imediatamente ao estado leve na fatia seguinte em $60.00\%$ das vezes ($S_2 \to S_0$)[cite: 11]. Ameaças *CPU-bound* violam essa propriedade ao permanecerem retidas na transição $S_2 \to S_2$.

---

## Estrutura do Diretório

```text
v3/
├── artifacts/                  # Modelo serializado (sentinel_bundle.pkl: pesos LSTM + Matriz Markov)
├── metrics/                    # Gráficos (curva_roc.png, matriz_confusao.png, matriz_transicao_markov.png)
├── scripts/
│   ├── malware_sim.c           # Simulador multi-thread CPU-bound para calibração supervisionada
│   ├── train_and_eval.py       # Treinamento híbrido, cálculo ROC/Matriz/Markov e exportação .pkl
│   └── sentinel_daemon.py      # Daemon IPS de inferência híbrida contínua e bloqueio (SIGKILL)
├── systemd/
│   └── sentinel.service        # Template universal do serviço systemd (sem caminhos fixos)
├── install_service.sh          # Instalador automático do daemon (resolve caminhos dinamicamente)
├── requirements.txt            # Dependências Python para CPU (PyTorch, NumPy, Scikit-Learn, Matplotlib)
└── README.md                   # Documentação científica e operacional da v3
```

---

## Passo a Passo de Instalação e Execução

### 1. Instalar Dependências do Sistema Operacional

**Em distribuições baseadas em Debian / Ubuntu / Linux Mint:**

```bash
sudo apt update
sudo apt install -y build-essential bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-venv wget tar
```

**Em distribuições baseadas em Fedora / RHEL:**

```bash
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r) kernel-headers gcc wget tar
```

### 2. Configurar o Ambiente Virtual (Isolado + Acesso ao `bcc`)

A partir da pasta `v3`, crie o ambiente virtual com a flag `--system-site-packages` (necessária para herdar o binding `bcc` do sistema) e instale as dependências do `requirements.txt`:

```bash
cd v3
python3 -m venv ../venv --system-site-packages
source ../venv/bin/activate
pip install -r requirements.txt
```

### 3. Compilar o Simulador de Calibração Supervisionada

Compile o gerador de estresse multi-thread em C com a flag `-O0` (desativando otimizações de loop do compilador para garantir carga real de CPU durante a avaliação):

```bash
gcc -O0 -o scripts/malware_sim scripts/malware_sim.c -lpthread
```

### 4. Executar o Treino Híbrido e Gerar as Métricas (`pickle`, ROC, Matriz e Markov)

Execute o pipeline de treinamento e validação com privilégios de superusuário (exigidos pela máquina virtual eBPF no kernel):

```bash
sudo ../venv/bin/python scripts/train_and_eval.py
```

**Etapas executadas automaticamente pelo pipeline:**
* **Fase 1 (Treino Híbrido):** Captura 1.500 eventos orgânicos do escalonador CFS, ajustando os pesos da rede LSTM e preenchendo a Matriz de Transição de Markov ($3 \times 3$).
* **Fase 2 (Avaliação Balanceada):** Coleta 500 amostras normais (Classe `0`) e, em seguida, dispara o `malware_sim` em segundo plano para coletar 500 amostras de ataque (Classe `1`).
* **Fase 3 (Exportação Científica):** Gera os gráficos de alta resolução (300 DPI) `metrics/curva_roc.png` (comparando LSTM vs. Markov vs. Híbrido)[cite: 9], `metrics/matriz_confusao.png`[cite: 10] e `metrics/matriz_transicao_markov.png`[cite: 11], além de salvar o pacote completo em `artifacts/sentinel_bundle.pkl`.

### 5. Instalar e Ativar o Daemon IPS no `systemd`

Com o arquivo `artifacts/sentinel_bundle.pkl` gerado, execute o script instalador para configurar dinamicamente os caminhos da máquina atual e iniciar o serviço em segundo plano:

```bash
chmod +x install_service.sh
./install_service.sh
```

Verifique o status do serviço ativo:

```bash
sudo systemctl status sentinel.service
```

---

## Avaliação Experimental de Abate (Red Team vs. Blue Team)

### Cenário A: Teste de Baseline com Simulador Sintético (`malware_sim`)

Abra **dois terminais** na pasta `v3`:

**Terminal 1 (Monitoramento da Telemetria IPS via `journalctl`):**

```bash
sudo journalctl -u sentinel.service -f
```

**Terminal 2 (Disparo do Simulador):**

```bash
./scripts/malware_sim
```

---

### Cenário B: Validação em Sandbox com Payload Real de Cryptojacking (XMRig / RandomX)

Campanhas reais de *cryptojacking* em servidores Linux (como *Kinsing* e *Outlaw*) utilizam o motor **XMRig** para explorar o algoritmo de prova de trabalho **RandomX**. Como o modelo híbrido do Sentinel monitora o padrão estocástico e temporal das fatias de CPU no CFS (sem depender de assinaturas estáticas de arquivos), ele é capaz de interceptar e abater binários reais em execução.

#### 1. Protocolo de Isolamento em Máquina Virtual (Sandboxing)
Antes de executar o binário real em uma Máquina Virtual (QEMU/KVM, GNOME Boxes ou VirtualBox):
1. Certifique-se de que as **Pastas Compartilhadas** e o redirecionamento USB com o sistema hospedeiro estão desativados[cite: 1, 4].
2. Crie um **Snapshot** do estado limpo da Máquina Virtual com o `sentinel.service` ativo.

#### 2. Download e Extração do Binário Real (XMRig Static Linux x64)
Em um diretório temporário dentro da Máquina Virtual, baixe a versão estática oficial do XMRig:

```bash
mkdir -p /tmp/malware_test && cd /tmp/malware_test
wget [https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-static-x64.tar.gz](https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-static-x64.tar.gz)
tar -xvf xmrig-6.21.0-linux-static-x64.tar.gz
cd xmrig-6.21.0
```

#### 3. Execução do Ataque e Neutralização Autónoma
Com o **Terminal 1** exibindo os logs em tempo real (`sudo journalctl -u sentinel.service -f`), inicie o estresse de mineração no **Terminal 2**:

```bash
./xmrig --stress
```

#### 4. Resultado Esperado
1. As *threads* de mineração do `xmrig` forçarão transições repetitivas de exaustão ($S_2 \to S_2$), elevando simultaneamente o erro da rede LSTM e a penalidade logarítmica da Cadeia de Markov.
2. No **Terminal 1**, o daemon registrará a escalada do risco estocástico até atingir o limiar de contenção (`8.0`):

```text
[!] ALERTA HÍBRIDO (Risco: 1.9/8.0) | PID: 4120 | Proc: xmrig | Transição: S2->S2 | Score: 0.5842
...
[!] ALERTA HÍBRIDO (Risco: 8.4/8.0) | PID: 4120 | Proc: xmrig | Transição: S2->S2 | Score: 0.6120
[#] AÇÃO IPS: Ameaça 'xmrig' (PID 4120) ABATIDA com SIGKILL!
```

3. No **Terminal 2**, o processo é imediatamente encerrado pelo kernel do Linux (`Killed` / `Morto`), restaurando a disponibilidade da CPU sem intervenção humana.

---

## Comandos Úteis de Gerenciamento do Daemon

* **Parar o IPS temporariamente:**

```bash
sudo systemctl stop sentinel.service
```

* **Reiniciar o IPS (após um novo treinamento):**

```bash
sudo systemctl restart sentinel.service
```

* **Desativar a inicialização automática no boot:**

```bash
sudo systemctl disable sentinel.service
```