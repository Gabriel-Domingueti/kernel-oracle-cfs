#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

#define NUM_CPU_THREADS 8
#define NUM_IO_THREADS 4

// Thread que monopoliza a CPU com cálculos
void *cpu_bound_task(void *arg) {
    double temp = 0.0;
    while (1) {
        for (int i = 0; i < 1000000; i++) {
            temp += i * 3.14159; // Simula cálculos pesados
        }
    }
    return NULL;
}

// Thread que simula operações de I/O (cede a CPU rapidamente)
void *io_bound_task(void *arg) {
    while (1) {
        usleep(5000); // Pausa de 5 milissegundos
        sched_yield(); // Cede a CPU para outras threads
    }
    return NULL;
}

int main() {
    pthread_t threads[NUM_CPU_THREADS + NUM_IO_THREADS];
    long int i;

    printf("Iniciando %d threads CPU-bound e %d threads I/O-bound...\n", NUM_CPU_THREADS, NUM_IO_THREADS);

    // Dispara as threads pesadas
    for (int i = 0; i < NUM_CPU_THREADS; i++) {
        pthread_create(&threads[i], NULL, cpu_bound_task, (void *)i);
    }

    // Dispara as threads leves
    for (int i = 0; i < NUM_IO_THREADS; i++) {
        pthread_create(&threads[NUM_CPU_THREADS + i], NULL, io_bound_task, (void *)i);
    }

    // Mantém o processo principal vivo
    for (int i = 0; i < (NUM_CPU_THREADS + NUM_IO_THREADS); i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}