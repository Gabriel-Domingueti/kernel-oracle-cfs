import os
import sys
import signal
import pickle
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

int trace_sched_switch(struct pt_regs *ctx, bool preempt, struct task_struct *prev, struct task_struct *next) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = prev->pid;
    u32 next_pid = next->pid;

    bpf_map_update_elem(&start_time, &next_pid, &ts, BPF_ANY);

    u64 *tsp = start_time.lookup(&prev_pid);
    if (tsp != 0 && prev_pid != 0) {
        struct data_t data = {};
        data.pid = prev_pid;
        data.tgid = prev->tgid;
        data.delta_t_ns = ts - *tsp;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        eventos.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

def main():
    try:
        os.nice(-5)
    except PermissionError:
        pass

    # Deteta automaticamente a pasta v3/ independente do computador ou utilizador
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
    historico = deque(bundle["baseline_history"], maxlen=tamanho_janela)

    modelo = KernelLSTM()
    modelo.load_state_dict(bundle["model_state_dict"])
    modelo.eval()

    print(f"[*] KernelOracle IPS Daemon ativo | Limiar: {limite_erro_anomalia:.4f}", flush=True)

    b = BPF(text=bpf_code)
    b.attach_kprobe(event_re=r"^finish_task_switch$|^finish_task_switch\.isra\.\d$", fn_name="trace_sched_switch")

    # Lista de processos críticos do sistema operativo que nunca devem ser encerrados
    WHITELIST = (
        "python", "fwupd", "Xorg", "systemd", "journald",
        "bash", "sudo", "sshd", "xfce4", "Thunar", "kworker"
    )

    strikes = defaultdict(int)
    LIMITE_STRIKES = 8
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

        if len(historico) == tamanho_janela:
            x_tensor = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)

            with torch.no_grad():
                predicao = modelo(x_tensor)
                erro_absoluto = abs(predicao.item() - delta_t_scaled)

            if erro_absoluto > limite_erro_anomalia:
                strikes[nome_tarefa] += 1
                contagem_atual = strikes[nome_tarefa]

                print(f"[!] ALERTA IDS ({contagem_atual}/{LIMITE_STRIKES}) | PID: {pid_alvo: <6} | Processo: {nome_tarefa: <15} | Erro: {erro_absoluto:.4f}", flush=True)

                if contagem_atual >= LIMITE_STRIKES:
                    try:
                        os.kill(pid_alvo, signal.SIGKILL)
                        pids_neutralizados.add(pid_alvo)
                        strikes[nome_tarefa] = 0
                        print(f"[#] AÇÃO IPS: Ameaça '{nome_tarefa}' (PID {pid_alvo}) ABATIDA com SIGKILL!", flush=True)
                    except ProcessLookupError:
                        pass
                    except Exception as e:
                        print(f"[ERRO IPS] Falha ao encerrar PID {pid_alvo}: {e}", flush=True)
            else:
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