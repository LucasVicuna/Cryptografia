from scapy.all import sniff, ICMP, Raw
from termcolor import colored
import string

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

def capturar_icmp_texto(tiempo=30):
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

# Diccionario básico que puedes extender o reemplazar con un archivo externo
PALABRAS_VALIDAS = {"hola", "mensaje", "secreto", "prueba", "oculto", "texto", "cesar", "criptografia", "clave", "codificar", "decodificar"}

def score_mensaje(texto):
    palabras = texto.lower().split()
    coincidencias = sum(1 for palabra in palabras if palabra in PALABRAS_VALIDAS)
    mayusculas = sum(1 for palabra in texto.split() if palabra.istitle())
    letras_validas = sum(1 for c in texto if c.isalpha())

    return coincidencias * 3 + mayusculas + letras_validas * 0.1  # ponderación ajustada

def main():
    mensaje_cifrado = capturar_icmp_texto()

    candidatos = {}
    for desplazamiento in range(1, 26):
        descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        score = score_mensaje(descifrado)
        candidatos[desplazamiento] = (descifrado, score)

    # Elegir el mejor según puntaje
    mejor_desplazamiento = max(candidatos.items(), key=lambda x: x[1][1])[0]

    print("\n--- Posibles combinaciones ---")
    for k, (msg, score) in candidatos.items():
        if k == mejor_desplazamiento:
            print(colored(f"[{k}] {msg}", "green"))
        else:
            print(f"[{k}] {msg}")

if __name__ == "__main__":
    main()
