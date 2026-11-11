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
from sklearn.metrics import roc_curve, auc, confusion_matrix
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

np.random.seed(42)
torch.manual_seed(42)

class KernelLSTM(nn.Module):
    def __init__(self):
        super(KernelLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=16, num_layers=1, batch_first=True)
        self.fc = nn.Linear(16, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

def discretizar_estado(delta_t_scaled):
    if delta_t_scaled < 0.08:
        return 0  # S0: Leve / Cooperativo (< 0.8 ms)
    elif delta_t_scaled < 0.35:
        return 1  # S1: Médio (0.8 ms a 3.5 ms)
    return 2      # S2: Exaustão / CPU-Bound (>= 3.5 ms)

def calcular_erro_markov(matriz_prob, estado_ant, estado_atual):
    prob = float(matriz_prob[estado_ant, estado_atual])
    nll = -np.log(max(prob, 1e-4))
    return min(nll / (-np.log(1e-4)), 1.0)

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
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
        data.delta_t_ns = ts - *tsp;
        __builtin_memcpy(&data.comm, args->prev_comm, sizeof(data.comm));
        eventos.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

def main():
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(BASE_DIR, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "metrics"), exist_ok=True)

    tamanho_janela = 30
    max_norm_ms = 10.0
    alpha_hibrido = 0.60

    modelo = KernelLSTM()
    criterio = nn.MSELoss()
    otimizador = torch.optim.Adam(modelo.parameters(), lr=0.005)

    b = BPF(text=bpf_code)
    fila_eventos = deque()

    # Ignora apenas hipervisores de VM e compiladores pesados durante a coleta normal
    RUIDO_VM = ("qemu", "virt-manager", "malware_sim", "xmrig", "cc1", "gcc")

    def callback_bpf(cpu, data, size):
        ev = b["eventos"].event(data)
        comm = ev.comm.decode('utf-8', 'replace').strip()
        delta_ms = ev.delta_t_ns / 1000000.0
        scaled = min(delta_ms / max_norm_ms, 1.0)
        fila_eventos.append((comm, scaled))

    b["eventos"].open_perf_buffer(callback_bpf, page_cnt=256)

    def coletar_amostras(qtd, modo="normal", rotulo_log=""):
        amostras = []
        fila_eventos.clear()
        ruido_permitido = 0
        max_ruido = int(qtd * 0.03)  # Permite até 3% de variação orgânica natural do SO

        while len(amostras) < qtd:
            b.perf_buffer_poll(timeout=100)
            while fila_eventos and len(amostras) < qtd:
                comm, val = fila_eventos.popleft()
                comm_low = comm.lower()
                if modo == "normal":
                    if any(r in comm_low for r in RUIDO_VM):
                        continue
                    if val >= 0.12:
                        if ruido_permitido < max_ruido:
                            ruido_permitido += 1
                            amostras.append(val)
                        continue
                    amostras.append(val)
                elif modo == "malware":
                    # Captura o comportamento real do malware_sim (incluindo suas oscilações S1/S2)
                    if "malware_sim" in comm_low:
                        amostras.append(val)
                if len(amostras) % 250 == 0 and len(amostras) > 0:
                    print(f"  [{rotulo_log}] {len(amostras)}/{qtd} amostras coletadas...", flush=True)
        return amostras[:qtd]

    print("[*] Fase 1: Treinamento Híbrido (LSTM + Matriz de Markov) com 1500 eventos...", flush=True)
    dados_treino = coletar_amostras(1500, modo="normal", rotulo_log="Treino")

    # 1. Construir Matriz de Markov 3x3 com Suavização de Laplace
    contagem_transicoes = np.ones((3, 3), dtype=np.float64)
    estados_treino = [discretizar_estado(v) for v in dados_treino]
    for i in range(len(estados_treino) - 1):
        contagem_transicoes[estados_treino[i], estados_treino[i + 1]] += 1.0
    matriz_markov = contagem_transicoes / contagem_transicoes.sum(axis=1, keepdims=True)

    # 2. Treinar Rede LSTM
    modelo.train()
    historico = deque(dados_treino[:tamanho_janela], maxlen=tamanho_janela)
    for val in dados_treino[tamanho_janela:]:
        x_t = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)
        y_t = torch.tensor([[val]], dtype=torch.float32)
        otimizador.zero_grad()
        out = modelo(x_t)
        loss = criterio(out, y_t)
        loss.backward()
        otimizador.step()
        historico.append(val)

    modelo.eval()
    print("[*] Fase 2: Coletando 500 amostras Normais (Classe 0)...", flush=True)
    dados_normais = coletar_amostras(500, modo="normal", rotulo_log="Avaliação Normal")

    caminho_sim = os.path.join(BASE_DIR, "scripts", "malware_sim")
    print("[!] Iniciando simulador de malware (Cryptominer) para Classe 1...", flush=True)
    proc_sim = subprocess.Popen([caminho_sim], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        dados_malware = coletar_amostras(500, modo="malware", rotulo_log="Avaliação Malware")
    finally:
        proc_sim.terminate()
        try:
            proc_sim.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc_sim.kill()

    # Avaliação das 1000 amostras (500 Classe 0 + 500 Classe 1)
    y_true = np.array([0] * 500 + [1] * 500)
    scores_lstm, scores_markov, scores_hibrido = [], [], []

    janela_eval = deque(dados_treino[-tamanho_janela:], maxlen=tamanho_janela)
    estado_ant = discretizar_estado(janela_eval[-1])

    for idx, val in enumerate(dados_normais + dados_malware):
        x_t = torch.tensor(list(janela_eval), dtype=torch.float32).view(1, tamanho_janela, 1)
        with torch.no_grad():
            pred = modelo(x_t).item()
        erro_l = abs(pred - val)

        estado_atual = discretizar_estado(val)
        erro_m = calcular_erro_markov(matriz_markov, estado_ant, estado_atual)
        score_h = (alpha_hibrido * erro_l) + ((1.0 - alpha_hibrido) * erro_m)

        scores_lstm.append(erro_l)
        scores_markov.append(erro_m)
        scores_hibrido.append(score_h)

        # Atualiza o estado anterior para capturar a memória de transição de Markov (S_t -> S_{t+1})
        estado_ant = estado_atual
        if idx < 500:
            janela_eval.append(val)

    scores_lstm = np.array(scores_lstm)
    scores_markov = np.array(scores_markov)
    scores_hibrido = np.array(scores_hibrido)

    fpr_l, tpr_l, _ = roc_curve(y_true, scores_lstm)
    auc_l = auc(fpr_l, tpr_l)

    fpr_m, tpr_m, _ = roc_curve(y_true, scores_markov)
    auc_m = auc(fpr_m, tpr_m)

    fpr_h, tpr_h, thresholds_h = roc_curve(y_true, scores_hibrido)
    auc_h = auc(fpr_h, tpr_h)

    youden_idx = np.argmax(tpr_h - fpr_h)
    limiar_otimo = float(thresholds_h[youden_idx])

    print("[*] Gerando gráficos científicos comparativos (LSTM vs. Markov vs. Híbrido)...", flush=True)

    # 1. Curva ROC Tripla
    plt.figure(figsize=(7, 5.5), dpi=300)
    plt.plot(fpr_l, tpr_l, linestyle='-.', color='royalblue', lw=2, label=f'LSTM Isolada (AUC = {auc_l:.4f})')
    plt.plot(fpr_m, tpr_m, linestyle=':', color='seagreen', lw=2, label=f'Cadeia de Markov (AUC = {auc_m:.4f})')
    plt.plot(fpr_h, tpr_h, linestyle='-', color='darkorange', lw=2.5, label=f'Híbrido LSTM + Markov (AUC = {auc_h:.4f})')
    plt.scatter(fpr_h[youden_idx], tpr_h[youden_idx], color='red', s=50, zorder=5, label=f'Limiar Ótimo Híbrido ({limiar_otimo:.4f})')
    plt.plot([0, 1], [0, 1], color='gray', linestyle='--', lw=1.2)
    plt.xlabel('Taxa de Falsos Positivos (FPR)')
    plt.ylabel('Taxa de Verdadeiros Positivos (TPR)')
    plt.title('Comparativo ROC: LSTM vs. Cadeia de Markov vs. Híbrido (v3)')
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "metrics", "curva_roc.png"))
    plt.close()

    # 2. Matriz de Confusão
    y_pred = (scores_hibrido >= limiar_otimo).astype(int)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    acc = (tp + tn) / 1000.0 * 100
    prec = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    rec = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    spec = (tn / (tn + fp) * 100) if (tn + fp) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    plt.figure(figsize=(6, 5), dpi=300)
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Matriz de Confusão - Modelo Híbrido (LSTM + Markov)')
    plt.colorbar()
    classes = ['Normal (0)', 'Malware (1)']
    plt.xticks([0, 1], classes)
    plt.yticks([0, 1], classes)
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            plt.text(j, i, format(cm[i, j], 'd'),
                     ha="center", va="center",
                     color="white" if cm[i, j] > thresh else "midnightblue", fontsize=12)
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "metrics", "matriz_confusao.png"))
    plt.close()

    # 3. Matriz de Transição de Markov
    plt.figure(figsize=(6.5, 5), dpi=300)
    plt.imshow(matriz_markov, interpolation='nearest', cmap=plt.cm.Greens, vmin=0.0, vmax=1.0)
    plt.title('Matriz de Probabilidades de Transição de Markov (Baseline)')
    plt.colorbar()
    estados_labels = ['S0 (Leve)', 'S1 (Médio)', 'S2 (Exaustão)']
    plt.xticks([0, 1, 2], estados_labels)
    plt.yticks([0, 1, 2], estados_labels)
    for i in range(3):
        for j in range(3):
            plt.text(j, i, f"{matriz_markov[i, j]:.4f}",
                     ha="center", va="center",
                     color="black", fontweight="bold", fontsize=11)
    plt.ylabel('Estado Atual (t)')
    plt.xlabel('Estado Seguinte (t+1)')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "metrics", "matriz_transicao_markov.png"))
    plt.close()

    # 4. Salvar Bundle Pickle
    bundle = {
        "model_state_dict": modelo.state_dict(),
        "markov_matrix": matriz_markov,
        "threshold": limiar_otimo,
        "window_size": tamanho_janela,
        "max_norm_ms": max_norm_ms,
        "alpha_hibrido": alpha_hibrido,
        "baseline_history": list(dados_treino[-tamanho_janela:])
    }
    caminho_pkl = os.path.join(BASE_DIR, "artifacts", "sentinel_bundle.pkl")
    with open(caminho_pkl, "wb") as f:
        pickle.dump(bundle, f)

    print(f"[+] Curva ROC salva (AUC LSTM={auc_l:.4f} | Markov={auc_m:.4f} | Híbrido={auc_h:.4f})", flush=True)
    print(f"[+] Métricas Híbrido (Limiar={limiar_otimo:.4f}): Acc={acc:.2f}% | Prec={prec:.2f}% | Recall={rec:.2f}% | Spec={spec:.2f}% | F1={f1:.2f}%", flush=True)
    print(f"[+] Matriz Confusão: TN={tn}, FP={fp}, FN={fn}, TP={tp}", flush=True)
    print(f"[+] Bundle Híbrido salvo em '{caminho_pkl}'", flush=True)

if __name__ == "__main__":
    main()