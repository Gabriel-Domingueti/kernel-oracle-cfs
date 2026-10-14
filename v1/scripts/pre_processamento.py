import csv
import re

# Expressão regular usando grupos posicionais (sem os caracteres problemáticos)
regex = re.compile(r'^\s*([\w\-]+).*?\s+(\d+\.\d+):')

# Apontando para a pasta correta definida na arquitetura
input_file = 'data/escalonamento_raw.txt'
output_file = 'data/dataset_cfs.csv'

dados = []
ultimo_timestamp = None

print("Lendo e processando os dados brutos...")

try:
    with open(input_file, 'r') as f:
        for linha in f:
            match = regex.search(linha)
            if match:
                # O índice 1 pega o nome da tarefa e o 2 pega o timestamp
                task_name = match.group(1)
                timestamp = float(match.group(2))
                
                # Calcula a diferença de tempo (delta)
                if ultimo_timestamp is not None:
                    delta_t = timestamp - ultimo_timestamp
                    # Filtrar anomalias: descartar deltas irrealisticamente altos (ex: > 1 segundo)
                    if delta_t < 1.0: 
                        dados.append([task_name, delta_t])
                
                ultimo_timestamp = timestamp

    print(f"Total de amostras válidas capturadas: {len(dados)}")

    print("Salvando em CSV...")
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Task', 'Delta_T'])
        writer.writerows(dados)

    print(f"Dataset salvo com sucesso em {output_file}!")

except FileNotFoundError:
    print(f"Erro: O arquivo {input_file} não foi encontrado.")
    print("Certifique-se de executar os comandos do 'perf' primeiro e redirecionar a saída para a pasta 'data/'.")