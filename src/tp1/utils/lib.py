import sys
import psutil


def hello_world() -> str:
    return "hello world"


def choose_interface() -> str:
    if not sys.stdin.isatty():
        return ""

    interfaces = list(psutil.net_if_addrs().keys())

    if not interfaces:
        print("Aucune interface réseau trouvée.")
        return ""

    print("Interfaces réseau disponibles")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")

    while True:
        try:
            choice = input("Choisissez une interface (numéro) : ").strip()
            index = int(choice)
            if 0 <= index < len(interfaces):
                selected = interfaces[index]
                print(f"Interface sélectionnée : {selected}")
                return selected
            else:
                print(f"Veuillez entrer un nombre entre 0 et {len(interfaces) - 1}.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer un numéro.")