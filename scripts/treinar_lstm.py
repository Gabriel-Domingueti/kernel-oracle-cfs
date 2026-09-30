import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, Dataset

print("Carregando os dados...")
# Lendo da pasta data/
df = pd.read_csv('data/dataset_cfs.csv')

print("Processando e normalizando...")
# Escalonamento do Delta_T para média zero e variância unitária
scaler = StandardScaler()
df['Delta_T_Scaled'] = scaler.fit_transform(df[['Delta_T']])

# One-hot encoding dos nomes das tarefas
tarefas_encoded = pd.get_dummies(df['Task'], dtype=float)
num_tarefas = tarefas_encoded.shape[1]

# Concatenando os dados processados e forçando float32 para economizar metade da memória
dados_processados = np.hstack((df[['Delta_T_Scaled']].values, tarefas_encoded.values)).astype(np.float32)

# 2. Classe Customizada para Geração de Sequências On-the-Fly (Evita estouro de RAM)
class CFSDataset(Dataset):
    def __init__(self, data, seq_length):
        self.data = torch.tensor(data)
        self.seq_length = seq_length

    def __len__(self):
        return len(self.data) - self.seq_length

    def __getitem__(self, index):
        # Retorna a janela e o alvo dinamicamente
        X_seq = self.data[index : index + self.seq_length]
        y_target = self.data[index + self.seq_length, 0:1] # Delta_T_Scaled é o índice 0
        return X_seq, y_target

TAMANHO_SEQUENCIA = 50
print("Montando o DataLoader otimizado...")
dataset = CFSDataset(dados_processados, TAMANHO_SEQUENCIA)
# Lote de 256 acelera o treino sem pesar na memória
dataloader = DataLoader(dataset, batch_size=256, shuffle=True) 

# 3. Definição da Arquitetura LSTM
class CFSOracle(nn.Module):
    def __init__(self, input_size, hidden_layer_size=64):
        super(CFSOracle, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_layer_size, batch_first=True)
        self.linear = nn.Linear(hidden_layer_size, 1)

    def forward(self, input_seq):
        lstm_out, _ = self.lstm(input_seq)
        predictions = self.linear(lstm_out[:, -1, :])
        return predictions

input_dim = 1 + num_tarefas
modelo = CFSOracle(input_size=input_dim)
funcao_perda = nn.MSELoss()
otimizador = torch.optim.Adam(modelo.parameters(), lr=0.001)

# 4. Treinamento do Modelo
print(f"Iniciando o treinamento da LSTM (Total de amostras: {len(dataset)})...")
epocas = 5 # Começamos com 5 épocas para validar rápido. Depois você pode subir para 30.

for epoca in range(epocas):
    perda_total = 0
    modelo.train()
    for lote_X, lote_y in dataloader:
        otimizador.zero_grad()
        previsoes = modelo(lote_X)
        perda = funcao_perda(previsoes, lote_y)
        perda.backward()
        otimizador.step()
        perda_total += perda.item()
    
    print(f'Época {epoca+1}/{epocas} | Perda de Treinamento Média: {perda_total/len(dataloader):.4f}')

print("Treinamento concluído!")
# Salvando na pasta data/ para organizar
torch.save(modelo.state_dict(), 'data/modelo_cfs_oracle.pth')
print("Modelo salvo em 'data/modelo_cfs_oracle.pth'")