# KernelOracle-CFS: Monitoramento Preditivo e IPS Autônomo no Escalonador Linux via eBPF e Deep Learning Híbrido

O **KernelOracle-CFS** é um framework de segurança de sistemas e telemetria preditiva em nível de kernel para o escalonador *Completely Fair Scheduler* (CFS) do Linux. Combinando instrumentação não-intrusiva via **eBPF** (*Extended Berkeley Packet Filter*) no tracepoint `sched:sched_switch` com modelos de **Redes Neurais Recorrentes (LSTM)** e **Cadeias de Markov de Tempo Discreto (DTMC)**, o sistema modela a dinâmica estocástica de fatias de tempo ($\Delta t$) de execução de processos para detectar e neutralizar, em tempo real, ameaças de exaustão de CPU (*Cryptojacking* / *Resource Hijacking*).

---

## Evolução Arquitetural do Projeto

O repositório está organizado em três gerações incrementais (`v1`, `v2` e `v3`), refletindo a evolução científica desde a prova de conceito até um Sistema de Prevenção de Intrusão (IPS) autônomo validado contra malwares reais:

| Versão | Foco Arquitetural | Modelagem Matemática | Ação de Resposta | Diretório |
| :--- | :--- | :--- | :--- | :---: |
| **v1** | Prova de Conceito (PoC) | Coleta eBPF bruta + Rede LSTM simples | Monitoramento passivo em terminal | [`./v1`](./v1) |
| **v2** | Detecção de Anomalias (IDS) | Rede LSTM com limiar estático empírico | Alertas visuais de desvio de $\Delta t$ | [`./v2`](./v2) |
| **v3 (Atual)** | **IPS Autônomo Híbrido** | **Fusão LSTM ($60\%$) + Cadeia de Markov $3 \times 3$ ($40\%$) + Limiar Ótimo de Youden** | **Neutralização ativa via `SIGKILL` (`< 1s`) e daemon `systemd`** | [`./v3`](./v3) |

---

## Destaques da Arquitetura v3 (KernelOracle Sentinel)

1. **Modelagem Híbrida (Deep Learning + Processos Estocásticos):**

   - **Rede LSTM:** Prevê a duração contínua da próxima fatia de CPU, representada por `ŷₜ`, a partir de uma janela deslizante de 30 eventos.

     $$
     E_{\text{LSTM}} = |y_t - \hat{y}_t|
     $$

   - **Cadeia de Markov (3 × 3):** Avalia a probabilidade de transição entre estados discretos de retenção de CPU ($S_0$: Leve, $S_1$: Moderado, $S_2$: Exaustão), usando log-verossimilhança negativa normalizada ($E_{\text{Markov}}$).

   - **Score Híbrido:** $S_{\text{Híbrido}}(t) = 0.60 \cdot E_{\text{LSTM}}(t) + 0.40 \cdot E_{\text{Markov}}(t)$.


2. **Calibração Estatística Não-Enviesada (Índice $J$ de Youden):**
   * O limiar de decisão ótimo ($\theta^* = 0.0480$) é extraído analiticamente da Curva ROC sob tráfego real do kernel, maximizando $J = \text{TPR} - \text{FPR}$ sem necessidade de ajustes manuais.

3. **Proteção Estrutural de Processos do SO e Navegadores:**
   * Verificação em tempo real via `/proc/<tid>/status` (resolução de `TGID` e `UID`) e `/proc/<tgid>/exe` (*Trusted Path Verification*), garantindo **zero falsos positivos** sobre binários nativos do sistema operacional (GNOME, KDE, XFCE, Wayland, Xorg, `systemd`) e motores de navegadores modernos (Firefox/Gecko, Chrome/Chromium/Blink, WebKit).

---

## Resultados Experimentais e Validação Científica (v3)

Os experimentos foram conduzidos sob carga real no Fedora Linux (Kernel 6.8+) e validados em ambiente isolado (Linux Mint em QEMU/KVM), avaliando $N = 1000$ janelas temporais consecutivas ($500$ amostras de baseline orgânico na Classe 0 e $500$ amostras de ataque multi-thread na Classe 1):

| Arquitetura Avaliada | ROC-AUC | Ganho Relativo (vs. Markov) | Limiar Ótimo ($\theta^*$) | Acurácia | Precisão | Recall (TPR) | Especificidade (TNR) | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cadeia de Markov Isolada** | `0.8840` | Baseline | — | — | — | — | — | — |
| **Rede LSTM Isolada** | `0.9542` | `+7.02%` | — | — | — | — | — | — |
| **KernelOracle Híbrido (v3)** | **`0.9651`** | **`+8.11%`** | **`0.0480`** | **`91.50%`** | **`91.75%`** | **`91.20%`** | **`91.80%`** | **`91.47%`** |

### Artefatos Gráficos de Validação (`v3/metrics/`)

<p align="center">
  <img src="./v3/metrics/curva_roc.png" width="48%" alt="Curva ROC Comparativa" />
  <img src="./v3/metrics/matriz_confusao.png" width="48%" alt="Matriz de Confusão" />
</p>
<p align="center">
  <img src="./v3/metrics/matriz_transicao_markov.png" width="55%" alt="Matriz de Transição de Markov" />
</p>

### Validação Prática contra Payload Real (XMRig v6.21.0 RandomX)

Submetido ao minerador real **XMRig v6.21.0** em sandbox isolada (QEMU/KVM sem placa de rede ativa), o acumulador estocástico de risco do daemon IPS (`sentinel.service`) detectou a anomalia de transição (`S1 -> S2` e `S2 -> S1`) e neutralizou o processo atacante (`PID 3467`) com `SIGKILL` em **menos de 1 segundo** após a alocação do dataset RandomX, impedindo o sequestro de recursos da CPU.

---

## Guia Rápido de Execução (v3)

1. Acessar o diretório da v3 e compilar o simulador de estresse:
   `cd v3 && gcc scripts/malware_sim.c -o scripts/malware_sim -lpthread`

2. Executar o pipeline de treinamento, validação ROC e geração dos gráficos:
   `sudo ../venv/bin/python scripts/train_and_eval.py`

3. Instalar e iniciar o daemon IPS como serviço nativo do systemd:
   `chmod +x install_service.sh && ./install_service.sh`

4. Monitorar a telemetria e ações de abate ao vivo:
   `sudo journalctl -u sentinel.service -f`

Consulte a [documentação técnica completa da v3](./v3/README.md) para detalhes matemáticos, arquitetura do código e instruções de reprodutibilidade.
