import os
import sys
import time
import pickle
import subprocess
import numpy as np
import torch
import torch.nn as nn
from collections import deque
from bcc import BPF
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc
import matplotlib.pyplot as plt

# 1. DEFINIÇÃO DO MODELO LSTM
class KernelLSTM(nn.Module):
    def __init__(self):
        super(KernelLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=16, num_layers=1, batch_first=True)
        self.fc = nn.Linear(16, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

# 2. FUNÇÕES DA CADEIA DE MARKOV (3 ESTADOS)
def discretizar_estado(delta_t_scaled):
    if delta_t_scaled < 0.15:
        return 0  # S0: Cooperativo (I/O-bound)
    elif delta_t_scaled < 0.50:
        return 1  # S1: Carga Moderada
    return 2      # S2: Uso Intenso (CPU-bound)

def calcular_erro_markov(matriz_prob, estado_ant, estado_atual):
    prob = float(matriz_prob[estado_ant, estado_atual])
    # Log-likelihood negativo normalizado em [0, 1] (limite de surpresa = -ln(1e-4))
    nll = -np.log(max(prob, 1e-4))
    return min(nll / (-np.log(1e-4)), 1.0)

# 3. CÓDIGO eBPF
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 tgid;
    u64 delta_t_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start_time, u32, u64);
BPF_PERF_OUTPUT(eventos);

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    start_time.update(&next_pid, &ts);

    u64 *tsp = start_time.lookup(&prev_pid);
    if (tsp != 0 && prev_pid != 0) {
        struct data_t data = {};
        data.pid = prev_pid;
        data.tgid = bpf_get_current_pid_tgid() >> 32;
        data.delta_t_ns = ts - *tsp;
        __builtin_memcpy(&data.comm, args->prev_comm, sizeof(data.comm));
        eventos.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

def main():
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(BASE_DIR)

    os.makedirs("artifacts", exist_ok=True)
    os.makedirs("metrics", exist_ok=True)

    caminho_malware = os.path.join(BASE_DIR, "scripts", "malware_sim")
    if not os.path.exists(caminho_malware):
        print(f"[ERRO] Binário '{caminho_malware}' não encontrado!")
        print("Compile-o primeiro com: gcc -o scripts/malware_sim scripts/malware_sim.c -lpthread")
        sys.exit(1)

    print("[*] Injetando eBPF para captura de treinamento (LSTM + Cadeia de Markov)...")
    b = BPF(text=bpf_code)

    modelo = KernelLSTM()
    criterio = nn.MSELoss()
    otimizador = torch.optim.Adam(modelo.parameters(), lr=0.005)

    tamanho_janela = 30
    max_norm_ms = 50.0
    alpha_hibrido = 0.60  # Peso: 60% LSTM + 40% Cadeia de Markov
    historico = deque(maxlen=tamanho_janela)

    # Matriz de Contagem de Transições de Markov com Suavização de Laplace (3x3)
    num_estados = 3
    contagem_markov = np.ones((num_estados, num_estados), dtype=np.float64)
    matriz_markov = np.full((num_estados, num_estados), 1.0 / num_estados)
    estado_anterior = 0

    # Fases: TREINO -> EVAL_NORMAL -> EVAL_MALWARE -> FIM
    fase = "TREINO"
    eventos_treino = 0
    meta_treino = 1500
    meta_por_classe = 500

    y_true = []
    scores_lstm = []
    scores_markov = []
    scores_hibrido = []
    proc_malware = None

    def ignorar_perdas(lost):
        pass

    def processar_evento(cpu, data, size):
        nonlocal fase, eventos_treino, proc_malware, estado_anterior, matriz_markov
        if fase == "FIM":
            return

        evento = b["eventos"].event(data)
        nome_tarefa = evento.comm.decode('utf-8', 'replace').strip()

        if "python" in nome_tarefa:
            return

        delta_t_ms = evento.delta_t_ns / 1000000.0
        delta_t_scaled = min(delta_t_ms / max_norm_ms, 1.0)
        estado_atual = discretizar_estado(delta_t_scaled)

        if len(historico) == tamanho_janela:
            x_tensor = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)
            y_real = torch.tensor([[delta_t_scaled]], dtype=torch.float32)

            if fase == "TREINO":
                # 1. Atualiza Rede LSTM
                modelo.train()
                otimizador.zero_grad()
                predicao = modelo(x_tensor)
                perda = criterio(predicao, y_real)
                perda.backward()
                otimizador.step()

                # 2. Atualiza Matriz de Transição de Markov
                contagem_markov[estado_anterior, estado_atual] += 1.0

                eventos_treino += 1
                if eventos_treino % 300 == 0:
                    print(f"    [Treino Híbrido] {eventos_treino}/{meta_treino} eventos | Loss LSTM: {perda.item():.6f}")

                if eventos_treino >= meta_treino:
                    # Normaliza as linhas da Matriz de Markov para somarem 1.0
                    matriz_markov = contagem_markov / contagem_markov.sum(axis=1, keepdims=True)
                    print("\n[+] Treinamento concluído! Matriz de Markov consolidada:")
                    print(np.round(matriz_markov, 4))
                    print("\n[*] Coletando 500 amostras Normais (Classe 0)...")
                    fase = "EVAL_NORMAL"

            elif fase == "EVAL_NORMAL":
                if "malware_sim" not in nome_tarefa:
                    modelo.eval()
                    with torch.no_grad():
                        predicao = modelo(x_tensor)
                        erro_lstm = abs(predicao.item() - delta_t_scaled)

                    erro_mk = calcular_erro_markov(matriz_markov, estado_anterior, estado_atual)
                    erro_hyb = (alpha_hibrido * erro_lstm) + ((1.0 - alpha_hibrido) * erro_mk)

                    y_true.append(0)
                    scores_lstm.append(erro_lstm)
                    scores_markov.append(erro_mk)
                    scores_hibrido.append(erro_hyb)

                    if len(y_true) % 250 == 0:
                        print(f"    [Avaliação Normal] {len(y_true)}/{meta_por_classe} amostras coletadas...")

                    if len(y_true) >= meta_por_classe:
                        print("\n[*] Disparando malware_sim para coletar 500 amostras de Ataque (Classe 1)...")
                        proc_malware = subprocess.Popen([caminho_malware])
                        time.sleep(0.5)
                        fase = "EVAL_MALWARE"

            elif fase == "EVAL_MALWARE":
                if "malware_sim" in nome_tarefa:
                    modelo.eval()
                    with torch.no_grad():
                        predicao = modelo(x_tensor)
                        erro_lstm = abs(predicao.item() - delta_t_scaled)

                    erro_mk = calcular_erro_markov(matriz_markov, estado_anterior, estado_atual)
                    erro_hyb = (alpha_hibrido * erro_lstm) + ((1.0 - alpha_hibrido) * erro_mk)

                    y_true.append(1)
                    scores_lstm.append(erro_lstm)
                    scores_markov.append(erro_mk)
                    scores_hibrido.append(erro_hyb)

                    amostras_malware = len(y_true) - meta_por_classe
                    if amostras_malware % 250 == 0:
                        print(f"    [Avaliação Malware] {amostras_malware}/{meta_por_classe} amostras coletadas...")

                    if len(y_true) >= meta_por_classe * 2:
                        fase = "FIM"

        estado_anterior = estado_atual
        if "malware_sim" not in nome_tarefa:
            historico.append(delta_t_scaled)

    b["eventos"].open_perf_buffer(processar_evento, lost_cb=ignorar_perdas, page_cnt=256)

    print("[*] Fase 1: Treinando LSTM e Cadeia de Markov com o comportamento normal...")
    while fase != "FIM":
        b.perf_buffer_poll(timeout=100)

    if proc_malware and proc_malware.poll() is None:
        proc_malware.terminate()

    # 4. CÁLCULO DAS 3 CURVAS ROC (COMPARATIVO PARA ARTIGO)
    print("\n[*] Gerando gráficos científicos comparativos (LSTM vs. Markov vs. Híbrido)...")
    y_true_np = np.array(y_true)
    s_lstm_np = np.array(scores_lstm)
    s_markov_np = np.array(scores_markov)
    s_hibrido_np = np.array(scores_hibrido)

    fpr_l, tpr_l, _ = roc_curve(y_true_np, s_lstm_np)
    auc_l = auc(fpr_l, tpr_l)

    fpr_m, tpr_m, _ = roc_curve(y_true_np, s_markov_np)
    auc_m = auc(fpr_m, tpr_m)

    fpr_h, tpr_h, thresholds_h = roc_curve(y_true_np, s_hibrido_np)
    auc_h = auc(fpr_h, tpr_h)

    # Limiar ótimo pelo Índice J de Youden sobre o Modelo Híbrido
    idx_otimo = np.argmax(tpr_h - fpr_h)
    limiar_otimo = float(thresholds_h[idx_otimo])

    # Gráfico 1: Curva ROC Comparativa Tripla
    caminho_roc = os.path.join(BASE_DIR, "metrics", "curva_roc.png")
    plt.figure(figsize=(8, 6))
    plt.plot(fpr_l, tpr_l, color='royalblue', lw=2, linestyle='-.', label=f'LSTM Isolada (AUC = {auc_l:.4f})')
    plt.plot(fpr_m, tpr_m, color='seagreen', lw=2, linestyle=':', label=f'Cadeia de Markov (AUC = {auc_m:.4f})')
    plt.plot(fpr_h, tpr_h, color='darkorange', lw=2.5, label=f'Híbrido LSTM + Markov (AUC = {auc_h:.4f})')
    plt.plot([0, 1], [0, 1], color='gray', lw=1.5, linestyle='--')
    plt.scatter(fpr_h[idx_otimo], tpr_h[idx_otimo], color='red', zorder=5, label=f'Limiar Ótimo Híbrido ({limiar_otimo:.4f})')
    plt.xlabel('Taxa de Falsos Positivos (FPR)')
    plt.ylabel('Taxa de Verdadeiros Positivos (TPR)')
    plt.title('Comparativo ROC: LSTM vs. Cadeia de Markov vs. Híbrido (v3)')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig(caminho_roc, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] Curva ROC Comparativa salva em '{caminho_roc}'")

    # Gráfico 2: Matriz de Confusão do Modelo Híbrido
    caminho_cm = os.path.join(BASE_DIR, "metrics", "matriz_confusao.png")
    y_pred_np = (s_hibrido_np >= limiar_otimo).astype(int)
    cm = confusion_matrix(y_true_np, y_pred_np, labels=[0, 1])
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal (0)", "Malware (1)"])

    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(cmap=plt.cm.Blues, ax=ax, values_format='d')
    plt.title('Matriz de Confusão - Modelo Híbrido (LSTM + Markov)')
    plt.savefig(caminho_cm, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] Matriz de Confusão salva em '{caminho_cm}'")

    # Gráfico 3: Mapa de Calor da Matriz de Transição de Markov
    caminho_mk = os.path.join(BASE_DIR, "metrics", "matriz_transicao_markov.png")
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(matriz_markov, cmap='Greens', vmin=0, vmax=1)
    fig.colorbar(cax)
    estados_labels = ['S0 (Leve)', 'S1 (Médio)', 'S2 (Exaustão)']
    ax.set_xticks([0, 1, 2])
    ax.set_yticks([0, 1, 2])
    ax.set_xticklabels(estados_labels)
    ax.set_yticklabels(estados_labels)
    ax.xaxis.set_ticks_position('bottom')
    for i in range(3):
        for j in range(3):
            ax.text(j, i, f"{matriz_markov[i, j]:.4f}", va='center', ha='center', color='black', fontweight='bold')
    plt.xlabel('Estado Seguinte (t+1)')
    plt.ylabel('Estado Atual (t)')
    plt.title('Matriz de Probabilidades de Transição de Markov (Baseline)')
    plt.savefig(caminho_mk, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] Matriz de Transição de Markov salva em '{caminho_mk}'")

    # 5. SERIALIZAÇÃO COM PICKLE (Incluindo Matriz de Markov e Peso Híbrido)
    artefato_modelo = {
        "model_state_dict": modelo.state_dict(),
        "markov_matrix": matriz_markov,
        "alpha_hibrido": alpha_hibrido,
        "threshold": limiar_otimo,
        "window_size": tamanho_janela,
        "max_norm_ms": max_norm_ms,
        "baseline_history": list(historico)
    }

    caminho_pkl = os.path.join(BASE_DIR, "artifacts", "sentinel_bundle.pkl")
    with open(caminho_pkl, "wb") as f:
        pickle.dump(artefato_modelo, f)

    print(f"[+] Bundle Híbrido salvo via Pickle em '{caminho_pkl}' (Limiar Híbrido: {limiar_otimo:.4f})")

if __name__ == "__main__":
    main()