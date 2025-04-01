def cifrado_cesar(texto, desplazamiento):
    resultado = ""

    for caracter in texto:
        if caracter.isalpha():  # Solo letras
            base = ord('A') if caracter.isupper() else ord('a')
            nuevo = (ord(caracter) - base + desplazamiento) % 26 + base
            resultado += chr(nuevo)
        else:
            resultado += caracter  # No modifica símbolos ni números

    return resultado

def pedir_entrada():
    print("=== CIFRADO CÉSAR ===")
    print("Este programa solo cifra letras del abecedario (mayúsculas y minúsculas).")
    print("No se cifran símbolos, números ni espacios.")
    print("El desplazamiento debe estar entre 1 y 25 (ambos incluidos).")

    texto = input("Ingresa el texto a cifrar: ")

    while True:
        try:
            desplazamiento = int(input("Ingresa el desplazamiento (1-25): "))
            if desplazamiento < 1 or desplazamiento > 25:
                print("Error: El desplazamiento debe estar entre 1 y 25. Intenta nuevamente.")
            else:
                break
        except ValueError:
            print("Error: Debes ingresar un número entero.")

    texto_cifrado = cifrado_cesar(texto, desplazamiento)
    print(f"\nTexto cifrado: {texto_cifrado}")

    return texto_cifrado

# Ejecutar programa
if __name__ == "__main__":
    pedir_entrada()