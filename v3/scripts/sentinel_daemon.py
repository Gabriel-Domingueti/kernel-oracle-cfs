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
    if delta_t_scaled < 0.08:
        return 0  # S0: Cooperativo / I/O-bound (< 0.8 ms)
    elif delta_t_scaled < 0.35:
        return 1  # S1: Moderado / Disputa Multi-thread (0.8 ms a 3.5 ms)
    return 2      # S2: Exaustão / CPU-bound (>= 3.5 ms)

def calcular_erro_markov(matriz_prob, estado_ant, estado_atual):
    prob = float(matriz_prob[estado_ant, estado_atual])
    nll = -np.log(max(prob, 1e-4))
    return min(nll / (-np.log(1e-4)), 1.0)

DIRETORIOS_CONFIAVEIS_SO = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/",
    "/snap/",
    "/var/lib/flatpak/"
)

# Assinaturas específicas sem substrings curtas ambíguas (evita falso match com 'sh' em 'sha256'/'shadow')
ASSINATURAS_PROTEGIDAS = (
    "firefox", "gecko", "glean", "chrom", "google-chrome", "brave", "vivaldi",
    "opera", "msedge", "epiphany", "midori", "tor-browser", "waterfox", "librewolf",
    "zen-browser", "webkit", "blink", "electron", "isolated web", "web content",
    "webextensions", "compositor", "renderer", "socket process", "dom worker",
    "utility process", "gpu-process", "crashpad", "sandbox", "zygote",
    "gnome", "mutter", "gsd-", "gvfs", "nautilus", "evolution", "kded", "kwin",
    "plasmashell", "akonadi", "dolphin", "krunner", "xfce", "xfwm", "xfdesktop",
    "xfsettingsd", "panel", "whisker", "thunar", "tumblerd", "cinnamon", "nemo",
    "muffin", "mate-", "caja", "marco", "lxqt", "openbox", "wayland", "xwayland",
    "xorg", "inputthread", "sway", "hyprland", "wlroots", "picom", "ibus",
    "systemd", "imedated", "journald", "udevd", "dbus", "polkit", "networkmanager",
    "nm-applet", "wpa_supplicant", "avahi", "cupsd", "bluetoothd", "upowerd", "udisksd",
    "pipewire", "wireplumber", "pulseaudio", "rtkit", "colord", "fwupd",
    "packagekit", "apt", "dpkg", "dnf", "pacman", "flatpak", "snapd", "lightdm",
    "gdm", "sddm", "bash", "zsh", "fish", "sudo", "sshd", "gpg-agent",
    "ssh-agent", "pg-agent", "gcr-", "gnome-keyring", "kwalletd", "python",
    "code", "codium", "nvim", "vim", "gmain", "gdbus", "dconf",
    "kworker", "ksoftirqd", "migration", "rcu_"
)

cache_proc_info = {}

def obter_info_processo_real(tid, comm_thread):
    if tid in cache_proc_info:
        return cache_proc_info[tid]

    tgid = tid
    ppid = 0
    uid = 1000
    caminho_exe = ""
    cmdline = ""
    nome_processo_pai = comm_thread

    try:
        with open(f"/proc/{tid}/status", "r") as f:
            for linha in f:
                if linha.startswith("Tgid:"):
                    tgid = int(linha.split()[1])
                elif linha.startswith("PPid:"):
                    ppid = int(linha.split()[1])
                elif linha.startswith("Uid:"):
                    uid = int(linha.split()[1])
                    break

        if tgid != tid and os.path.exists(f"/proc/{tgid}/comm"):
            with open(f"/proc/{tgid}/comm", "r") as f:
                nome_processo_pai = f.read().strip()

        if os.path.exists(f"/proc/{tgid}/exe"):
            caminho_exe = os.readlink(f"/proc/{tgid}/exe").replace(" (deleted)", "")

        if os.path.exists(f"/proc/{tgid}/cmdline"):
            with open(f"/proc/{tgid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        pass

    identidade = f"{comm_thread} {nome_processo_pai} {caminho_exe} {cmdline}".lower()
    protegido = False

    if uid < 1000 and caminho_exe.startswith(DIRETORIOS_CONFIAVEIS_SO):
        protegido = True
    elif caminho_exe.startswith(DIRETORIOS_CONFIAVEIS_SO):
        protegido = True
    elif any(assinatura in identidade for assinatura in ASSINATURAS_PROTEGIDAS):
        protegido = True

    info = (tgid, ppid, nome_processo_pai, caminho_exe, protegido)
    if len(cache_proc_info) > 4096:
        cache_proc_info.clear()
    cache_proc_info[tid] = info
    return info

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

    ultimo_estado_proc = defaultdict(int)
    risco_acumulado = defaultdict(float)
    LIMITE_RISCO_IPS = 8.0
    pids_neutralizados = set()

    def ignorar_perdas(lost):
        pass

    def processar_evento(cpu, data, size):
        evento = b["eventos"].event(data)
        tid = evento.pid
        if tid <= 300:
            return

        comm_thread = evento.comm.decode('utf-8', 'replace').strip()
        pid_alvo, ppid, nome_pai, caminho_exe, protegido = obter_info_processo_real(tid, comm_thread)

        if protegido or pid_alvo in pids_neutralizados or pid_alvo <= 300:
            return

        chave_proc = nome_pai if nome_pai else comm_thread

        delta_t_ms = evento.delta_t_ns / 1000000.0
        delta_t_scaled = min(delta_t_ms / max_norm_ms, 1.0)
        estado_atual = discretizar_estado(delta_t_scaled)
        estado_ant = ultimo_estado_proc[chave_proc]
        ultimo_estado_proc[chave_proc] = estado_atual

        if len(historico) == tamanho_janela:
            x_tensor = torch.tensor(list(historico), dtype=torch.float32).view(1, tamanho_janela, 1)

            with torch.no_grad():
                predicao = modelo(x_tensor)
                erro_lstm = abs(predicao.item() - delta_t_scaled)

            erro_mk = calcular_erro_markov(matriz_markov, estado_ant, estado_atual)
            score_hibrido = (alpha_hibrido * erro_lstm) + ((1.0 - alpha_hibrido) * erro_mk)

            if score_hibrido > limite_erro_anomalia and estado_atual >= 1:
                peso_estado = 1.5 if estado_atual == 2 else 1.0
                incremento = peso_estado + score_hibrido + erro_mk
                risco_acumulado[chave_proc] += incremento
                risco_atual = risco_acumulado[chave_proc]

                if risco_atual >= 3.5:
                    print(
                        f"[!] ALERTA HÍBRIDO (Risco: {risco_atual:.1f}/{LIMITE_RISCO_IPS}) | "
                        f"PID: {pid_alvo: <6} | Proc: {chave_proc: <14} | "
                        f"Transição: S{estado_ant}->S{estado_atual} | Score: {score_hibrido:.4f}",
                        flush=True
                    )

                if risco_atual >= LIMITE_RISCO_IPS:
                    try:
                        # Neutraliza o grupo de processos (mata pai e filhos forkados se for um payload malicioso)
                        try:
                            pgid = os.getpgid(pid_alvo)
                            if pgid > 300:
                                os.killpg(pgid, signal.SIGKILL)
                        except Exception:
                            pass
                        os.kill(pid_alvo, signal.SIGKILL)
                        pids_neutralizados.add(pid_alvo)
                        risco_acumulado[chave_proc] = 0.0
                        print(f"[#] AÇÃO IPS: Ameaça '{chave_proc}' (PID {pid_alvo}) ABATIDA com SIGKILL!", flush=True)
                    except ProcessLookupError:
                        pids_neutralizados.add(pid_alvo)
                        risco_acumulado[chave_proc] = 0.0
                        print(f"[#] AÇÃO IPS: Ameaça '{chave_proc}' (PID {pid_alvo}) ABATIDA com SIGKILL!", flush=True)
                    except Exception as e:
                        print(f"[ERRO IPS] Falha ao encerrar PID {pid_alvo}: {e}", flush=True)
            else:
                if estado_atual == 0 and risco_acumulado[chave_proc] > 0.0:
                    risco_acumulado[chave_proc] = max(0.0, risco_acumulado[chave_proc] - 0.15)
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