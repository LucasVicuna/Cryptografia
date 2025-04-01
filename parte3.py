from scapy.all import sniff, ICMP, Raw
from collections import Counter
from termcolor import colored
import string

# Fuerza bruta para descifrado Cesar
def descifrar_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            nuevo = (ord(caracter) - base - desplazamiento) % 26 + base
            resultado += chr(nuevo)
        else:
            resultado += caracter
    return resultado

# Heurística simple para elegir el mejor resultado
def es_mensaje_probable(texto, palabras_validas):
    palabras = texto.lower().split()
    return sum(1 for palabra in palabras if palabra in palabras_validas)

# Captura paquetes ICMP que contienen caracteres en Raw.load
def capturar_icmp_texto(tiempo):
    print(f"\nEscuchando paquetes ICMP durante {tiempo} segundos...")
    paquetes = sniff(filter="icmp", timeout=tiempo)
    caracteres = []

    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].type == 8 and Raw in pkt:
            data = pkt[Raw].load
            try:
                caracteres.append(data.decode('utf-8'))
            except:
                continue

    mensaje = ''.join(caracteres)
    print(f"\nMensaje capturado (cifrado): {mensaje}")
    return mensaje

def main():
    mensaje_cifrado = capturar_icmp_texto(tiempo=30)

    # Lista básica de palabras comunes para detectar texto probable
    palabras_comunes = {"hola", "este", "es", "un", "mensaje", "oculto", "secreto", "texto", "de", "prueba", "criptografia"}

    candidatos = {}
    for desplazamiento in range(1, 26):
        descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        puntuacion = es_mensaje_probable(descifrado, palabras_comunes)
        candidatos[desplazamiento] = (descifrado, puntuacion)

    # Elegir la mejor opción
    mejor = max(candidatos.items(), key=lambda x: x[1][1])

    print("\n--- Posibles combinaciones ---")
    for k, (msg, score) in candidatos.items():
        if k == mejor[0]:
            print(colored(f"[{k}] {msg}", "green"))
        else:
            print(f"[{k}] {msg}")

if __name__ == "__main__":
    main()
