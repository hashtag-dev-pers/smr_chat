#!/usr/bin/env python3
# chat_server.py
# Usage: python3 chat_server.py [port]
# Default port: 12345

import socket
import threading
import sys
import time

#Colors
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
BLUE = "\033[34m"
RESET = "\033[0m"

# Colores ANSI disponibles para los nombres
COLOR_CODES = {
    "rojo": "\033[31m",
    "verde": "\033[32m",
    "amarillo": "\033[33m",
    "azul": "\033[34m",
    "magenta": "\033[35m",
    "cian": "\033[36m",
    "blanco": "\033[37m",
    "reset": "\033[0m",
}

#Pixel art de bienvenida
welcome_art = f"""
{GREEN}Bienvenidos al chat SMR!{RESET}

{GREEN}
  █████ ██   ██ ███
 █      █ █ █ █ █  █
  ████  █  █  █ ███
      █ █     █ █  █
 █████  █     █ █  █
{RESET}

{GREEN}Escribe tu nombre para empezar...{RESET}
"""

HOST = '0.0.0.0'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 12345

clients = []            # list of (socket, name, color)
clients_lock = threading.Lock()

def timestamp():
    """Return [HH:MM:SS] formatted timestamp."""
    return f"{time.strftime('[%H:%M:%S]')}"

def find_client_by_name(name):
    """Find a client socket by name (case-insensitive)."""
    name = name.lower()
    with clients_lock:
        for sock, n, _ in clients:
            if n.lower() == name:
                return sock
    return None

def broadcast(message, exclude_sock=None):
    """Send message (str) to all clients except exclude_sock."""
    data = (message + '\n').encode('utf-8', errors='replace')
    with clients_lock:
        for sock, _name, _color in clients:
            if sock is exclude_sock:
                continue
            try:
                sock.sendall(data)
            except Exception:
                # ignore failures here; cleanup happens in handler
                pass

def handle_client(conn, addr):
    conn_file = conn.makefile('r')  # text mode to read lines
    name = None
    try:
        # First line from client is treated as the username
        conn.sendall(welcome_art.encode())
        name_line = conn_file.readline()
        if not name_line:
            return
        name = name_line.strip() or f'{addr[0]}:{addr[1]}'
        user_color = "\033[32m"
        with clients_lock:
            clients.append((conn, name, user_color))
        broadcast(f'{timestamp()} {GREEN}*** {name} ha entrado en chat ***{RESET}')
        help_text = (
            f"{GREEN}Comandos disponibles:{RESET}\n"
            f"  /who  - Mostrar usuarios conectados\n"
            f"  /msg <nombre> <texto>  - Enviar mensaje privado\n"
            f"  /color - Cambiar color de tu nombre\n"
            f"  /quit - Salir del chat\n\n"
        )
        conn.sendall(f"{timestamp()} Hola, {GREEN}{name}{RESET}! Ahora puedes escribir.\n".encode())
        conn.sendall(help_text.encode())

        for line in conn_file:
            line = line.rstrip('\n')
            if not line:
                continue

            # Commands
            if line.strip().lower() == '/quit':
                break

            elif line.strip().lower() == '/who':
                with clients_lock:
                    names = ", ".join(n for _, n, _ in clients)
                conn.sendall(f"{timestamp()} {GREEN} Usuarios conectados: {names}\n{RESET}".encode())
                continue

            elif line.startswith('/msg '):
                parts = line.split(' ', 2)
                if len(parts) < 3:
                    conn.sendall(b"Uso: /msg nombre texto\n")
                    continue
                target_name, msg_text = parts[1], parts[2]
                target_sock = find_client_by_name(target_name)
                if not target_sock:
                    conn.sendall(f"{timestamp()} {GREEN}Usuario {target_name} no encontrado.\n{RESET}".encode())
                    continue
                pm = f"{timestamp()} [PM de {name}] {msg_text}\n"
                try:
                    target_sock.sendall(pm.encode())
                    conn.sendall(f"{timestamp()} {GREEN}[PM a {target_name}] {msg_text}\n{RESET}".encode())
                except Exception:
                    conn.sendall(f"{timestamp()} {GREEN}No se pudo enviar el mensaje a {target_name}\n{RESET}".encode())
                continue

            elif line.startswith('/color '):
                parts = line.split(' ', 1)
                if len(parts) < 2:
                    conn.sendall(b"Uso: /color <nombre_color>\n")
                    continue
                color_name = parts[1].strip().lower()
                if color_name not in COLOR_CODES:
                    disponibles = ", ".join(COLOR_CODES.keys())
                    conn.sendall(f"{GREEN}Colores disponibles:{RESET} {disponibles}\n".encode())
                    continue
                new_color = COLOR_CODES[color_name]
                # Actualizar el color del usuario en la lista
                with clients_lock:
                    for i, (s, n, c) in enumerate(clients):
                        if s is conn:
                            clients[i] = (s, n, new_color)
                            break
                conn.sendall(f"{timestamp()} {GREEN}Has cambiado tu color a{user_color} {color_name}{RESET}.\n".encode())
                continue

            # Normal broadcast
            with clients_lock:
                user_color = next((c for s, n, c in clients if s is conn), "\033[36m")

            broadcast(f'{timestamp()} {user_color}<{name}>{RESET} {line}', exclude_sock=conn)

    except Exception:
        pass
    finally:
        with clients_lock:
            # remove this client's socket from list
            clients[:] = [(s,n,c) for (s,n,c) in clients if s is not conn]
        if name:
            broadcast(f'{timestamp()} {GREEN}*** {name} ha salido del chat ***{RESET}', exclude_sock=None)
        try:
            conn.close()
        except Exception:
            pass

def accept_loop(server_sock):
    while True:
        conn, addr = server_sock.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

def main():
    print(f'Starting chat at {HOST}:{PORT}')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(100)
        accept_loop(s)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        # Notify all clients before closing
        with clients_lock:
            for sock, name, color in clients:
                try:
                    sock.sendall(f"{timestamp()} {RED}*** El servidor se está cerrando ***{RESET}\n".encode())
                    sock.close()
                except Exception:
                    pass
            clients.clear()
        print('\nServer shutting down.')
        sys.exit(0)
