import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
from collections import deque
from bcc import BPF

# ==========================================
# 1. ARQUITETURA DA REDE NEURAL (LSTM)
# ==========================================
class CFSOnlineOracle(nn.Module):
    def __init__(self, input_size=1, hidden_layer_size=32):
        super().__init__()
        # Rede mais leve para treinar em tempo real sem atrasar o kernel
        self.lstm = nn.LSTM(input_size, hidden_layer_size, batch_first=True)
        self.linear = nn.Linear(hidden_layer_size, 1)

    def forward(self, input_seq):
        lstm_out, _ = self.lstm(input_seq)
        return self.linear(lstm_out[:, -1, :])

# ==========================================
# 2. CÓDIGO eBPF (INJETADO NO KERNEL)
# ==========================================
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 delta_t_ns;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(eventos);
BPF_HASH(inicio_tarefa, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    struct data_t data = {};
    u64 tempo_atual = bpf_ktime_get_ns();
    
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    u64 *tempo_inicio = inicio_tarefa.lookup(&prev_pid);
    if (tempo_inicio != 0) {
        data.delta_t_ns = tempo_atual - *tempo_inicio;
        data.pid = prev_pid;
        bpf_probe_read_kernel_str(&data.comm, sizeof(data.comm), args->prev_comm);
        eventos.perf_submit(args, &data, sizeof(data));
    }
    inicio_tarefa.update(&next_pid, &tempo_atual);
    return 0;
}
"""

# ==========================================
# 3. MOTOR DE APRENDIZADO CONTÍNUO E IDS
# ==========================================
def main():
    # Eleva o processo do Sentinel à prioridade máxima do sistema
    try:
        os.nice(-20)
    except PermissionError:
        pass

    print("[*] Iniciando KernelOracle Sentinel (Modo Online Learning)...")
    
    # Instancia o modelo "em branco"
    modelo = CFSOnlineOracle()
    modelo.train() # Modo de treinamento ativado!
    
    # Motor matemático que vai atualizar a rede em tempo real
    funcao_perda = nn.MSELoss()
    otimizador = optim.Adam(modelo.parameters(), lr=0.01)
    
    b = BPF(text=bpf_text)
    print("[+] eBPF Injetado. Fase 1: Calibrando o sistema (Aprendizado inicial)...")
    
    tamanho_janela = 30
    limite_erro_anomalia = 0.5  # Limiar para considerar como ataque
    historico = deque(maxlen=tamanho_janela)
    contador_eventos = 0

    def processar_evento(cpu, data, size):
        nonlocal contador_eventos
        evento = b["eventos"].event(data)
        
        # Converte nanosegundos para milissegundos
        delta_t_ms = evento.delta_t_ns / 1000000.0
        nome_tarefa = evento.comm.decode('utf-8', 'replace')

        # ==========================================
        # IGNORAR O PRÓPRIO SENTINEL E O EBPF
        # ==========================================
        if "python" in nome_tarefa:
            return 
        # ==========================================
        
        # Normalização simples em tempo real (evita precisar do antigo StandardScaler)
        # Assumimos que uma fatia normal não passa muito de 50ms.
        delta_t_scaled = min(delta_t_ms / 50.0, 1.0) 
        
        historico.append([delta_t_scaled])
        
        if len(historico) == tamanho_janela:
            contador_eventos += 1
            
            # Prepara os dados: os primeiros 29 itens tentam prever o 30º
            dados_np = np.array(historico, dtype=np.float32)
            X_tensor = torch.tensor(dados_np[:-1]).unsqueeze(0) # Janela de contexto
            Y_real = torch.tensor([[dados_np[-1][0]]])          # A realidade que aconteceu
            
            # 1. O modelo faz a previsão
            previsao = modelo(X_tensor)
            
            # 2. Calcula o erro (Loss)
            perda = funcao_perda(previsao, Y_real)
            erro_absoluto = abs(previsao.item() - Y_real.item())
            
            # 3. Lógica de Decisão (O coração do Sentinel)
            if contador_eventos < 500:
                # Período de Warm-up (Aquecimento): O modelo é cego nos primeiros eventos, então só treina
                if contador_eventos % 100 == 0:
                    print(f"    [Calibração] Evento {contador_eventos}/500 | Erro atual: {erro_absoluto:.4f}")
            else:
                if contador_eventos == 500:
                    print("\n[+] Calibração concluída! O sistema está vigiando ativamente.")
                
                if erro_absoluto > limite_erro_anomalia:
                    # ALERTA DE INTRUSÃO! O erro foi muito alto. Não treinamos a rede.
                    print(f"[!!!] ANOMALIA IDS | PID: {evento.pid: <6} | Processo: {nome_tarefa: <15} | Erro: {erro_absoluto:.2f}", flush=True)
                    return # Sai da função para evitar que a rede aprenda o malware
            
            # 4. Fase de Treinamento (Backpropagation)
            otimizador.zero_grad() # Limpa a memória matemática
            perda.backward()       # Calcula os ajustes necessários nos pesos
            otimizador.step()      # Aplica os ajustes na rede neural

    # ==========================================
    # GESTÃO DO BUFFER DO KERNEL
    # ==========================================
    def ignorar_perdas(lost_count):
        # Oculta o aviso de "Possibly lost samples" do terminal
        pass 

    # Abre o buffer com um tamanho muito maior (page_cnt=256) e silencia os drops
    b["eventos"].open_perf_buffer(processar_evento, lost_cb=ignorar_perdas, page_cnt=256)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Sentinel desativado com segurança.")

if __name__ == "__main__":
    main()