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

# 2. CÓDIGO eBPF
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

    print("[*] Injetando eBPF para captura de treinamento e validação...")
    b = BPF(text=bpf_code)

    modelo = KernelLSTM()
    criterio = nn.MSELoss()
    otimizador = torch.optim.Adam(modelo.parameters(), lr=0.005)

    tamanho_janela = 30
    max_norm_ms = 50.0
    historico = deque(maxlen=tamanho_janela)

    # Fases: TREINO -> EVAL_NORMAL -> EVAL_MALWARE -> FIM
    fase = "TREINO"
    eventos_treino = 0
    meta_treino = 1500

    y_true = []
    y_scores = []
    meta_por_classe = 500  # 500 Normais (0) + 500 Malware (1) = 1000 amostras balanceadas
    proc_malware = None

    def ignorar_perdas(lost):
        pass

    def processar_evento(cpu, data, size):
        nonlocal fase, eventos_treino, proc_malware
        if fase == "FIM":
            return

        evento = b["eventos"].event(data)
        nome_tarefa = evento.comm.decode('utf-8', 'replace').strip()

        if "python" in nome_tarefa:
            return

        delta_t_ms = evento.delta_t_ns / 1000000.0
        delta_t_scaled = min(delta_t_ms / max_norm_ms, 1.0)

        if len(historico) == tamanho_janela:
            x_tensor = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)
            y_real = torch.tensor([[delta_t_scaled]], dtype=torch.float32)

            if fase == "TREINO":
                modelo.train()
                otimizador.zero_grad()
                predicao = modelo(x_tensor)
                perda = criterio(predicao, y_real)
                perda.backward()
                otimizador.step()

                eventos_treino += 1
                if eventos_treino % 300 == 0:
                    print(f"    [Treino] {eventos_treino}/{meta_treino} eventos | Loss: {perda.item():.6f}")

                if eventos_treino >= meta_treino:
                    print("\n[+] Treinamento concluído! Coletando 500 amostras Normais (Classe 0)...")
                    fase = "EVAL_NORMAL"

            elif fase == "EVAL_NORMAL":
                if "malware_sim" not in nome_tarefa:
                    modelo.eval()
                    with torch.no_grad():
                        predicao = modelo(x_tensor)
                        erro_abs = abs(predicao.item() - delta_t_scaled)

                    y_true.append(0)
                    y_scores.append(erro_abs)

                    if len(y_true) % 250 == 0:
                        print(f"    [Avaliação Normal] {len(y_true)}/{meta_por_classe} amostras coletadas...")

                    if len(y_true) >= meta_por_classe:
                        print("\n[*] Disparando malware_sim para coletar 500 amostras de Ataque (Classe 1)...")
                        proc_malware = subprocess.Popen([caminho_malware])
                        time.sleep(0.5)  # Aguarda o processo entrar em execução na CPU
                        fase = "EVAL_MALWARE"

            elif fase == "EVAL_MALWARE":
                # Filtra especificamente os eventos gerados pelas threads do malware_sim
                if "malware_sim" in nome_tarefa:
                    modelo.eval()
                    with torch.no_grad():
                        predicao = modelo(x_tensor)
                        erro_abs = abs(predicao.item() - delta_t_scaled)

                    y_true.append(1)
                    y_scores.append(erro_abs)

                    amostras_malware = len(y_true) - meta_por_classe
                    if amostras_malware % 250 == 0:
                        print(f"    [Avaliação Malware] {amostras_malware}/{meta_por_classe} amostras coletadas...")

                    if len(y_true) >= meta_por_classe * 2:
                        fase = "FIM"

        if "malware_sim" not in nome_tarefa:
            historico.append(delta_t_scaled)

    b["eventos"].open_perf_buffer(processar_evento, lost_cb=ignorar_perdas, page_cnt=256)

    print("[*] Fase 1: Treinando o modelo com o comportamento normal da máquina...")
    while fase != "FIM":
        b.perf_buffer_poll(timeout=100)

    if proc_malware and proc_malware.poll() is None:
        proc_malware.terminate()

    # 3. CÁLCULO DA CURVA ROC E MATRIZ DE CONFUSÃO
    print("\n[*] Calculando Curva ROC e Matriz de Confusão...")
    y_true_np = np.array(y_true)
    y_scores_np = np.array(y_scores)

    fpr, tpr, thresholds = roc_curve(y_true_np, y_scores_np)
    roc_auc = auc(fpr, tpr)

    idx_otimo = np.argmax(tpr - fpr)
    limiar_otimo = float(thresholds[idx_otimo])

    caminho_roc = os.path.join(BASE_DIR, "metrics", "curva_roc.png")
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'Curva ROC (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.scatter(fpr[idx_otimo], tpr[idx_otimo], color='red', zorder=5, label=f'Limiar Ótimo ({limiar_otimo:.4f})')
    plt.xlabel('Taxa de Falsos Positivos (FPR)')
    plt.ylabel('Taxa de Verdadeiros Positivos (TPR)')
    plt.title('Curva ROC - KernelOracle Sentinel v3')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig(caminho_roc, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] Curva ROC salva em '{caminho_roc}' (AUC = {roc_auc:.4f})")

    caminho_cm = os.path.join(BASE_DIR, "metrics", "matriz_confusao.png")
    y_pred_np = (y_scores_np >= limiar_otimo).astype(int)
    cm = confusion_matrix(y_true_np, y_pred_np, labels=[0, 1])
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal (0)", "Malware (1)"])

    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(cmap=plt.cm.Blues, ax=ax, values_format='d')
    plt.title('Matriz de Confusão - KernelOracle Sentinel v3')
    plt.savefig(caminho_cm, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] Matriz de Confusão salva em '{caminho_cm}'")

    # 4. SERIALIZAÇÃO COM PICKLE
    artefato_modelo = {
        "model_state_dict": modelo.state_dict(),
        "threshold": limiar_otimo,
        "window_size": tamanho_janela,
        "max_norm_ms": max_norm_ms,
        "baseline_history": list(historico)
    }

    caminho_pkl = os.path.join(BASE_DIR, "artifacts", "sentinel_bundle.pkl")
    with open(caminho_pkl, "wb") as f:
        pickle.dump(artefato_modelo, f)

    print(f"[+] Modelo e parâmetros salvos via Pickle em '{caminho_pkl}' (Limiar: {limiar_otimo:.4f})")

if __name__ == "__main__":
    main()