import streamlit as st
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

# 1. Recriar a mesma arquitetura LSTM usada no treinamento
class CFSOracle(nn.Module):
    def __init__(self, input_size, hidden_layer_size=64):
        super(CFSOracle, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_layer_size, batch_first=True)
        self.linear = nn.Linear(hidden_layer_size, 1)

    def forward(self, input_seq):
        lstm_out, _ = self.lstm(input_seq)
        predictions = self.linear(lstm_out[:, -1, :])
        return predictions

st.set_page_config(page_title="Oráculo do CFS", layout="wide")
st.title("Oráculo do CFS: Previsão de Escalonamento do Kernel")
st.markdown("Comparativo entre as fatias de tempo reais alocadas pelo escalonador do Linux e as previsões da LSTM.")

@st.cache_data
def carregar_dados_e_modelo():
    df = pd.read_csv('data/dataset_cfs.csv')
    scaler = StandardScaler()
    df['Delta_T_Scaled'] = scaler.fit_transform(df[['Delta_T']])
    
    tarefas_encoded = pd.get_dummies(df['Task'], dtype=float)
    dados_processados = np.hstack((df[['Delta_T_Scaled']].values, tarefas_encoded.values))
    
    # Preparar uma janela de teste (ex: 300 amostras)
    TAMANHO_SEQUENCIA = 50
    X_test, y_real = [], []
    for i in range(len(dados_processados) - TAMANHO_SEQUENCIA):
        X_test.append(dados_processados[i : i + TAMANHO_SEQUENCIA])
        y_real.append(dados_processados[i + TAMANHO_SEQUENCIA, 0])
        if len(y_real) > 300: # Limitar para visualização
            break
            
    X_test = torch.tensor(np.array(X_test), dtype=torch.float32)
    
    # Inicializar modelo e carregar pesos da pasta data/
    modelo = CFSOracle(input_size=dados_processados.shape[1])
    modelo.load_state_dict(torch.load('data/modelo_cfs_oracle.pth', weights_only=True))
    modelo.eval()
    
    return X_test, y_real, modelo

X_test, y_real, modelo = carregar_dados_e_modelo()

# 2. Executar a inferência
with torch.no_grad():
    y_pred = modelo(X_test).numpy().flatten()

# 3. Plotagem do Gráfico
fif, ax = plt.subplots(figsize=(12, 4))
ax.plot(y_real, label='CFS Real (Delta T)', color='blue', linewidth=1.5)
ax.plot(y_pred, label='Previsão LSTM', color='red', linestyle='--', linewidth=1.5)
ax.set_title("Previsão de Valores Futuros para Sequências Temporais")
ax.set_xlabel("Índice de Escalonamento Consecutivo")
ax.set_ylabel("Valor Escalonado (Delta T)")
ax.legend()
ax.grid(True, linestyle=':', alpha=0.6)

st.pyplot(fif)