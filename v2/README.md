# KernelOracle Sentinel: Motor IDS em Tempo Real (v2)

Esta fase documenta a evolução do projeto para um Sistema de Deteção de Intrusões (IDS) ativo e autónomo. Abandonando a análise estática baseada em ficheiros, esta arquitetura utiliza **eBPF (Extended Berkeley Packet Filter)** para monitorizar o escalonador diretamente no anel 0 do kernel, com latência quase nula. 

O motor de inteligência artificial incorpora um mecanismo de **Online Learning** (Aprendizado Contínuo), onde a rede LSTM calibra-se dinamicamente ao ritmo da máquina e alerta contra anomalias em tempo real, bloqueando a aprendizagem de comportamentos maliciosos (como *cryptominers* ou *ransomwares*).

## Estrutura da Arquitetura (Red Team vs Blue Team)
O ambiente desta versão foi desenhado para simular um cenário real de ataque e defesa:
- **`scripts/sentinel_online.py` (Blue Team):** O *daemon* defensivo. Injeta código C no kernel para capturar os eventos `sched_switch`, processa as fatias de tempo em milissegundos e treina a rede neural *on-the-fly*. Dispara alertas se o erro de predição ultrapassar o limiar de segurança.
- **`scripts/malware_sim.c` (Red Team):** Um simulador de ameaça que cria *threads* agressivas num laço matemático infinito, sequestrando os núcleos de CPU para quebrar intencionalmente o padrão do *Completely Fair Scheduler* (CFS).

## Requisitos de Sistema
Como o eBPF opera em baixo nível, são necessários privilégios de administrador e pacotes específicos do kernel:
- Sistema Operacional Linux (Kernel 5.15 ou superior recomendado).
- Cabeçalhos do kernel correspondentes à versão em execução.
- Ferramentas BCC (BPF Compiler Collection).

### Instalação das Dependências (Debian/Ubuntu/Mint)
```bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install numpy
```

## Como Simular o Ataque e a Defesa

Abra dois terminais para visualizar a interação do sistema em tempo real.

- **1.Preparar o Simulador de Ameaça (Terminal 1 - Ataque)**

Compile o código em C que atuará como o invasor:

```bash 
gcc -o scripts/malware_sim scripts/malware_sim.c -lpthread
```
- **2.Ativar o Escudo Sentinel (Terminal 2 - Defesa)**

Execute o IDS. Este script necessita de privilégios sudo para injetar o eBPF no kernel:

```bash
sudo ../venv/bin/python scripts/sentinel_online.py
```

O sistema iniciará uma fase de "Calibração" (os primeiros 500 eventos) onde a LSTM aprende organicamente o ritmo atual da máquina. Aguarde até receber a mensagem de que o sistema está a vigiar ativamente.

- **3.Disparar a Intrusão (Terminal 1 - Ataque)**

Com o Sentinel calibrado e a monitorizar, execute o simulador:

```bash
./scripts/malware_sim
```