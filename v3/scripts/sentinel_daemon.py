import os
import sys
import signal
import pickle
import numpy as np
import torch
import torch.nn as nn
from collections import deque, defaultdict
from bcc import BPF

class KernelLSTM(nn.Module):
    def __init__(self):
        super(KernelLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=16, num_layers=1, batch_first=True)
        self.fc = nn.Linear(16, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

def discretizar_estado(delta_t_scaled):
    if delta_t_scaled < 0.15:
        return 0
    elif delta_t_scaled < 0.50:
        return 1
    return 2

def calcular_erro_markov(matriz_prob, estado_ant, estado_atual):
    prob = float(matriz_prob[estado_ant, estado_atual])
    nll = -np.log(max(prob, 1e-4))
    return min(nll / (-np.log(1e-4)), 1.0)

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
    try:
        os.nice(-5)
    except PermissionError:
        pass

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    caminho_pkl = os.path.join(BASE_DIR, "artifacts", "sentinel_bundle.pkl")

    if not os.path.exists(caminho_pkl):
        print(f"[ERRO] Arquivo {caminho_pkl} não encontrado! Execute train_and_eval.py primeiro.", flush=True)
        sys.exit(1)

    with open(caminho_pkl, "rb") as f:
        bundle = pickle.load(f)

    tamanho_janela = bundle["window_size"]
    limite_erro_anomalia = bundle["threshold"]
    max_norm_ms = bundle["max_norm_ms"]
    matriz_markov = bundle["markov_matrix"]
    alpha_hibrido = bundle.get("alpha_hibrido", 0.60)
    historico = deque(bundle["baseline_history"], maxlen=tamanho_janela)

    modelo = KernelLSTM()
    modelo.load_state_dict(bundle["model_state_dict"])
    modelo.eval()

    print(f"[*] KernelOracle Híbrido (LSTM + Markov) IPS ativo | Limiar: {limite_erro_anomalia:.4f}", flush=True)

    b = BPF(text=bpf_code)

    WHITELIST = (
        "python", "fwupd", "Xorg", "systemd", "journald",
        "bash", "sudo", "sshd", "xfce4", "Thunar", "kworker"
    )

    # Rastreamento por processo: último estado de Markov e risco estocástico acumulado
    ultimo_estado_proc = defaultdict(int)
    risco_acumulado = defaultdict(float)
    LIMITE_RISCO_IPS = 8.0
    pids_neutralizados = set()

    def ignorar_perdas(lost):
        pass

    def processar_evento(cpu, data, size):
        evento = b["eventos"].event(data)
        nome_tarefa = evento.comm.decode('utf-8', 'replace').strip()
        pid_alvo = evento.tgid if evento.tgid != 0 else evento.pid

        if pid_alvo in pids_neutralizados or pid_alvo <= 100:
            return

        if any(w in nome_tarefa for w in WHITELIST):
            return

        delta_t_ms = evento.delta_t_ns / 1000000.0
        delta_t_scaled = min(delta_t_ms / max_norm_ms, 1.0)
        estado_atual = discretizar_estado(delta_t_scaled)
        estado_ant = ultimo_estado_proc[nome_tarefa]
        ultimo_estado_proc[nome_tarefa] = estado_atual

        if len(historico) == tamanho_janela:
            x_tensor = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)

            with torch.no_grad():
                predicao = modelo(x_tensor)
                erro_lstm = abs(predicao.item() - delta_t_scaled)

            erro_mk = calcular_erro_markov(matriz_markov, estado_ant, estado_atual)
            score_hibrido = (alpha_hibrido * erro_lstm) + ((1.0 - alpha_hibrido) * erro_mk)

            if score_hibrido > limite_erro_anomalia:
                # Incrementa o risco proporcionalmente à improbabilidade da transição de Markov
                incremento = 1.0 + erro_mk
                risco_acumulado[nome_tarefa] += incremento
                risco_atual = risco_acumulado[nome_tarefa]

                print(
                    f"[!] ALERTA HÍBRIDO (Risco: {risco_atual:.1f}/{LIMITE_RISCO_IPS}) | "
                    f"PID: {pid_alvo: <6} | Proc: {nome_tarefa: <12} | "
                    f"Transição: S{estado_ant}->S{estado_atual} | Score: {score_hibrido:.4f}",
                    flush=True
                )

                if risco_atual >= LIMITE_RISCO_IPS:
                    try:
                        os.kill(pid_alvo, signal.SIGKILL)
                        pids_neutralizados.add(pid_alvo)
                        risco_acumulado[nome_tarefa] = 0.0
                        print(f"[#] AÇÃO IPS: Ameaça '{nome_tarefa}' (PID {pid_alvo}) ABATIDA com SIGKILL!", flush=True)
                    except ProcessLookupError:
                        pass
                    except Exception as e:
                        print(f"[ERRO IPS] Falha ao encerrar PID {pid_alvo}: {e}", flush=True)
            else:
                # Decaimento estocástico: processos normais que voltam a S0 perdem risco acumulado
                risco_acumulado[nome_tarefa] = max(0.0, risco_acumulado[nome_tarefa] * 0.85)
                historico.append(delta_t_scaled)
        else:
            historico.append(delta_t_scaled)

    b["eventos"].open_perf_buffer(processar_evento, lost_cb=ignorar_perdas, page_cnt=256)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("[*] Sentinel IPS Daemon encerrado.", flush=True)

if __name__ == "__main__":
    main()