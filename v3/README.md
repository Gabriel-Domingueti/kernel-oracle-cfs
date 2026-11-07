# KernelOracle Sentinel: Motor IPS Autónomo & Daemon Systemd (v3)

A **v3** consolida o KernelOracle Sentinel como um **Sistema de Prevenção de Intrusões (IPS)** de nível de produção para ambientes Linux. Em vez de exigir recalibração manual a cada execução, esta arquitetura separa o fluxo em duas etapas: um pipeline de **Treino Único e Validação Científica** e um **Daemon de Inferência Pura** gerido nativamente pelo `systemd`.

Ao operar em modo de inferência contínua (`torch.no_grad()`) e carregar os pesos pré-treinados via `pickle`, o serviço monitoriza o escalonador CFS (*Completely Fair Scheduler*) no anel 0 do kernel via **eBPF** com impacto residual de CPU, abatendo processos maliciosos (como *cryptominers* e *ransomwares*) automaticamente através do sinal `SIGKILL`.

---

## Principais Evoluções da Arquitetura (v3)

1. **Treino Único e Serialização (`pickle`):** O modelo LSTM aprende o padrão orgânico da máquina apenas uma vez. Os pesos da rede (`state_dict`), o histórico de base, a janela temporal e o limiar ótimo de anomalia são empacotados no ficheiro binário `artifacts/sentinel_bundle.pkl`.
2. **Calibração Estatística via Curva ROC e Matriz de Confusão:** O limiar de deteção deixa de ser empírico e passa a ser calculado matematicamente pelo **Índice J de Youden** sobre a Curva ROC (maximizando a Taxa de Verdadeiros Positivos contra a Taxa de Falsos Positivos), exportando os gráficos em alta resolução (300 DPI) na pasta `metrics/`.
3. **Prevenção Ativa com Sistema de Strikes (IPS):** Para evitar que oscilações isoladas de processos legítimos encerrem aplicações do utilizador, o motor utiliza um acumulador de infrações (*Strike Counter*). Ao atingir **8 desvios críticos**, o Sentinel identifica o grupo de threads real (`tgid`) e emite um `os.kill(tgid, signal.SIGKILL)`, neutralizando a ameaça instantaneamente.
4. **Daemon Nativo (`systemd`) e Zero Caminhos Fixos:** Os scripts Python detetam dinamicamente a sua localização no disco (`__file__`), e o instalador `install_service.sh` configura o serviço do Linux automaticamente em qualquer computador ou nome de utilizador, sem necessidade de editar o código.

---

## Estrutura do Diretório

```text
v3/
├── artifacts/                  # Modelo treinado e hiperparâmetros (sentinel_bundle.pkl)
├── metrics/                    # Gráficos exportados (curva_roc.png e matriz_confusao.png)
├── scripts/
│   ├── malware_sim.c           # Simulador multi-thread de cryptominer para validação
│   ├── train_and_eval.py       # Treina a LSTM, calcula ROC/Matriz e gera o .pkl
│   └── sentinel_daemon.py      # Daemon IPS de inferência contínua e bloqueio (SIGKILL)
├── systemd/
│   └── sentinel.service        # Template universal do serviço systemd
├── install_service.sh          # Instalador automático do daemon (resolve caminhos dinamicamente)
├── requirements.txt            # Dependências Python com versões fixadas (CPU-only)
└── README.md                   # Documentação da v3
```

---

## Passo a Passo de Instalação e Execução

### 1. Instalar Dependências do Sistema Operativo (Debian / Ubuntu / Linux Mint)

O motor eBPF requer os cabeçalhos do kernel e a coleção de compiladores BCC a nível global:

```bash
sudo apt update
sudo apt install -y build-essential bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-venv
```

### 2. Configurar o Ambiente Virtual (Isolado + Acesso ao `bcc`)

Na raiz do repositório (ou diretamente dentro da pasta `v3`), crie o ambiente virtual com a flag `--system-site-packages` para permitir a leitura do pacote `python3-bpfcc` do sistema e instale as versões exatas do `requirements.txt`:

```bash
cd v3
python3 -m venv ../venv --system-site-packages
source ../venv/bin/activate
pip install -r requirements.txt
```

*(Nota: O `requirements.txt` já inclui a diretiva `--extra-index-url https://download.pytorch.org/whl/cpu`, instalando automaticamente a versão leve do PyTorch).*

### 3. Compilar o Simulador de Ameaça

Compile o código em C que será utilizado pelo script de treino para validar matematicamente a separação entre processos benignos e maliciosos:

```bash
gcc -o scripts/malware_sim scripts/malware_sim.c -lpthread
```

### 4. Executar o Treino Único e Gerar as Métricas (`pickle`, ROC e Matriz)

Execute o pipeline de treino e avaliação com o Python do ambiente virtual:

```bash
sudo ../venv/bin/python scripts/train_and_eval.py
```

**O que acontece nesta etapa:**
* **Fase 1 (Treino):** O script captura 1.500 eventos normais do escalonador e ajusta os pesos da rede LSTM.
* **Fase 2 (Avaliação):** O script inicia automaticamente o `malware_sim` em segundo plano, recolhendo 1.000 amostras rotuladas entre processos legítimos (`0`) e o ataque (`1`).
* **Fase 3 (Exportação):** Gera os ficheiros `metrics/curva_roc.png`, `metrics/matriz_confusao.png` e guarda o cérebro calibrado em `artifacts/sentinel_bundle.pkl`.

### 5. Instalar e Ativar o Daemon IPS no `systemd`

Com o ficheiro `.pkl` gerado, execute o script instalador para registar e iniciar o Sentinel como um serviço de fundo do Linux:

```bash
chmod +x install_service.sh
./install_service.sh
```

Para verificar se o serviço está ativo e em execução:

```bash
sudo systemctl status sentinel.service
```

---

## Como Testar o Abate Automático de Ameaças (Red Team vs Blue Team)

Com o daemon a correr em segundo plano, abra **dois terminais** na pasta `v3`:

**Terminal 1 (Monitorização dos Logs do Sistema em Tempo Real):**
Acompanhe a saída oficial do daemon através do `journalctl`:

```bash
sudo journalctl -u sentinel.service -f
```

**Terminal 2 (Disparo da Ameaça):**
Execute o simulador de *cryptominer* (ou um binário de teste como o `xmrig --stress` dentro de uma VM isolada):

```bash
./scripts/malware_sim
```

**Resultado Esperado:**
1. No **Terminal 1**, o Sentinel registará a contagem de infrações da ameaça (`[!] ALERTA IDS (1/8)... (8/8)`).
2. Ao atingir o 8º *strike*, o IPS disparará: `[#] AÇÃO IPS: Ameaça 'malware_sim' (PID XXXX) ABATIDA com SIGKILL!`.
3. No **Terminal 2**, a execução do vírus será imediatamente abortada pelo kernel do Linux antes de completar os 15 segundos programados, exibindo a mensagem `Morto` (`Killed`).

---

## Comandos Úteis de Gestão do Serviço

* **Parar o IPS temporariamente:**

```bash
sudo systemctl stop sentinel.service
```

* **Reiniciar o IPS (após um novo treino):**

```bash
sudo systemctl restart sentinel.service
```

* **Desativar o arranque automático no boot:**

```bash
sudo systemctl disable sentinel.service
```