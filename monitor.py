import time
import psutil
import sys

import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

p = psutil.Process(int(sys.argv[1]))

fig, ax = plt.subplots()
i = 0
cpu, memory = [], []

cpu = []
memory = []
def update(frame):
    cpu.append(p.cpu_percent())
    memory.append(p.memory_percent())
    ax.clear()
    plt.plot(cpu, label="CPU usage (%)", color="#537b42")
    plt.plot(memory, label="Memory usage (%)", color="#6cad50")
    plt.legend(loc="lower left")
    return plt.plot(cpu)


ani = FuncAnimation(fig, update,  blit=True)
plt.show()
