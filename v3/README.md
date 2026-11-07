# KernelOracle Sentinel: Motor IPS Autónomo & Daemon Systemd (v3)

A **v3** consolida o KernelOracle Sentinel como um **Sistema de Prevenção de Intrusões (IPS)** de nível de produção para ambientes Linux. Em vez de exigir recalibração manual a cada execução, esta arquitetura separa o fluxo em duas etapas: um pipeline de **Treino Único e Validação Científica** e um **Daemon de Inferência Pura** gerido nativamente pelo `systemd`.

Ao operar em modo de inferência contínua (`torch.no_grad()`) e carregar os pesos pré-treinados via `pickle`, o serviço monitoriza o escalonador CFS (*Completely Fair Scheduler*) no anel 0 do kernel via **eBPF** (`sched:sched_switch`) com impacto residual de CPU, abatendo processos maliciosos (como *cryptojackers* e *ransomwares*) automaticamente através do sinal `SIGKILL`.

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
│   ├── malware_sim.c           # Simulador sintético multi-thread para calibração da ROC
│   ├── train_and_eval.py       # Treina a LSTM, calcula ROC/Matriz e gera o .pkl
│   └── sentinel_daemon.py      # Daemon IPS de inferência contínua e bloqueio (SIGKILL)
├── systemd/
│   └── sentinel.service        # Template universal do serviço systemd
├── install_service.sh          # Instalador automático do daemon (resolve caminhos dinamicamente)
├── requirements.txt            # Dependências Python com versões fixadas (CPU-only)
└── README.md                   # Documentação científica e operacional da v3
```

---

## Passo a Passo de Instalação e Calibração

### 1. Instalar Dependências do Sistema Operativo (Debian / Ubuntu / Linux Mint)

O motor eBPF requer os cabeçalhos do kernel e a coleção de compiladores BCC a nível global:

```bash
sudo apt update
sudo apt install -y build-essential bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-venv wget tar
```

### 2. Configurar o Ambiente Virtual (Isolado + Acesso ao `bcc`)

A partir da pasta `v3`, crie o ambiente virtual com a flag `--system-site-packages` para permitir a leitura do pacote `python3-bpfcc` do sistema e instale as versões exatas do `requirements.txt`:

```bash
cd v3
python3 -m venv ../venv --system-site-packages
source ../venv/bin/activate
pip install -r requirements.txt
```

*(Nota: O `requirements.txt` já inclui a diretiva `--extra-index-url [https://download.pytorch.org/whl/cpu](https://download.pytorch.org/whl/cpu)` e versões fixadas para reprodutibilidade científica).*

### 3. Compilar o Simulador de Calibração

Compile o gerador de carga em C que será utilizado pelo script de treino para validar matematicamente a separação entre processos benignos e anómalos:

```bash
gcc -o scripts/malware_sim scripts/malware_sim.c -lpthread
```

### 4. Executar o Treino Único e Gerar as Métricas (`pickle`, ROC e Matriz)

Execute o pipeline de treino e avaliação com o Python do ambiente virtual:

```bash
sudo ../venv/bin/python scripts/train_and_eval.py
```

**Etapas executadas automaticamente:**
* **Fase 1 (Treino):** Captura 1.500 eventos orgânicos do escalonador CFS e ajusta os pesos da rede LSTM.
* **Fase 2 (Avaliação Supervisionada):** Inicia automaticamente o `malware_sim` em segundo plano, recolhendo 1.000 amostras rotuladas entre processos legítimos (`0`) e anomalia de CPU (`1`).
* **Fase 3 (Exportação de Artefactos):** Gera os ficheiros `metrics/curva_roc.png`, `metrics/matriz_confusao.png` e serializa o modelo calibrado em `artifacts/sentinel_bundle.pkl`.

### 5. Instalar e Ativar o Daemon IPS no `systemd`

Com o ficheiro `.pkl` gerado, execute o script instalador para registar e iniciar o Sentinel como um serviço nativo do Linux:

```bash
chmod +x install_service.sh
./install_service.sh
```

Para verificar se o serviço está ativo e em execução:

```bash
sudo systemctl status sentinel.service
```

---

## Avaliação Experimental: Simulador Sintético vs. Payload Real (Cryptojacking)

Para validar a capacidade de generalização do modelo (treinado apenas com o comportamento normal do sistema e calibrado com o simulador sintético) contra ameaças do mundo real, o protocolo experimental divide-se em dois cenários.

### Cenário A: Teste de Baseline (Simulador Sintético `malware_sim`)

Abra **dois terminais** na pasta `v3`:

**Terminal 1 (Monitorização do Daemon via `journalctl`):**

```bash
sudo journalctl -u sentinel.service -f
```

**Terminal 2 (Execução do Simulador):**

```bash
./scripts/malware_sim
```

---

### Cenário B: Validação com Payload Real de Cryptojacking (XMRig / RandomX)

Mais de 80% das campanhas reais de *cryptojacking* em servidores Linux (como as botnets *Kinsing* e *Outlaw*) injetam o binário **XMRig** para explorar o algoritmo de prova de trabalho **RandomX** (intensivo em cache L3 e instruções de CPU). Como a rede LSTM do Sentinel monitoriza diretamente o comportamento das fatias de tempo no escalonador CFS (e não assinaturas estáticas de ficheiros), ela é capaz de detetar e abater um ataque *zero-day* de mineração em tempo real.

#### 1. Protocolo de Isolamento de Ambiente (Sandboxing)
Antes de executar qualquer binário real numa Máquina Virtual (KVM/QEMU, GNOME Boxes ou VirtualBox):
1. Certifique-se de que as **Pastas Partilhadas** e o redirecionamento de dispositivos USB com a máquina hospedeira estão desativados.
2. Crie um **Snapshot** do estado limpo da Máquina Virtual com o `sentinel.service` ativo.

#### 2. Download do Binário Real (XMRig Static Linux x64)
Num diretório temporário dentro da Máquina Virtual, transfira e extraia o motor oficial do XMRig:

```bash
mkdir -p /tmp/malware_test && cd /tmp/malware_test
wget https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-static-x64.tar.gz
tar -xvf xmrig-6.21.0-linux-static-x64.tar.gz
cd xmrig-6.21.0
```

*(Nota de Segurança: Caso utilize amostras brutas recolhidas de repositórios forenses como o MalwareBazaar/abuse.ch, desconecte a interface de rede virtual da VM imediatamente após o download e antes de conceder permissão de execução com `chmod +x`).*

#### 3. Execução do Ataque e Interceção pelo IPS
Com o **Terminal 1** a exibir os logs em tempo real (`sudo journalctl -u sentinel.service -f`), inicie o ataque de exaustão de CPU com o XMRig no **Terminal 2**:

```bash
./xmrig --stress
```

#### 4. Resultado Esperado (Mitigação Autónoma)
1. O motor RandomX do `xmrig` alocará *threads* de mineração em todos os núcleos disponíveis, distorcendo a latência de troca de contexto no escalonador CFS.
2. No **Terminal 1**, o `sentinel_daemon.py` intercetará os desvios consecutivos acima do limiar da Curva ROC:

```text
[!] ALERTA IDS (1/8) | PID: 4120 | Processo: xmrig | Erro: 0.9642
...
[!] ALERTA IDS (8/8) | PID: 4120 | Processo: xmrig | Erro: 0.9815
[#] AÇÃO IPS: Ameaça 'xmrig' (PID 4120) ABATIDA com SIGKILL!
```

3. No **Terminal 2**, o processo malicioso é imediatamente terminado pelo kernel do Linux (`Killed` / `Morto`) em poucos milissegundos após o início do processamento, restaurando a disponibilidade da CPU sem intervenção humana.

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