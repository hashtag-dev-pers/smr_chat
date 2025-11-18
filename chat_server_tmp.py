#!/usr/bin/env python3
# chat_server.py
# Usage: python3 chat_server.py [port]
# Default port: 12345

import socket
import threading
import sys
import time

# Admins
ADMIN_IPS = ['172.17.0.102']
BANNED_IPS = []

# Slow mode
slow_mode_enabled = False
slow_mode_interval = 0
last_message_time = {}

# Colors
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

HOST = 'localhost'
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
        for sock, n, _, _, _ in clients:
            if n.lower() == name:
                return sock
    return None

def broadcast(message, exclude_sock=None):
    """Send message (str) to all clients except exclude_sock."""
    data = (message + '\n').encode('utf-8', errors='replace')
    with clients_lock:
        for sock, _name, _color, _ip, _lock in clients:
            if sock is exclude_sock:
                continue
            try:
                _lock.acquire()
                sock.sendall(data)
                _lock.release()
                time.sleep(0.1)
            except Exception:
                # ignore failures here; cleanup happens in handler
                pass

def handle_client(conn, addr):
    global slow_mode_enabled, slow_mode_interval # global variables
    conn_file = conn.makefile('r')  # text mode to read lines
    name = None
    is_admin = addr[0] in ADMIN_IPS # admin check

    if addr[0] in BANNED_IPS: # ban check
      conn.sendall(f"{timestamp()} {RED}¡Tu IP está baneada! No puedes unirte al chat.\n{RESET}".encode())
      conn.close()
      return

    try:
        # First line from client is treated as the username
        conn.sendall(welcome_art.encode())
        name_line = conn_file.readline()
        if not name_line:
            return
        name = name_line.strip() or f'{addr[0]}:{addr[1]}'
        user_color = "\033[32m"

        with clients_lock:
            clients.append((conn, name, user_color, addr[0], threading.Lock()))
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

        if is_admin:
          admin_help_text = (
            f"{GREEN}Comandos del admin:\n"
            f" /kick <nombre/ip> - Expulsar a un usuario\n"
            f" /ban <nombre/ip> - Banear a un usuario\n"
            f" /unban <nombre/ip> - Desbanear a un usuario\n"
            f" /ip <nombre> - Ver IP del usuario\n"
            f" /slowmode <segundos> - Activar modo lento\n"
            f" /broadcast <mensaje> - Enviar un mensaje a todos los usuarios{RESET}\n\n"
          )
          conn.sendall(admin_help_text.encode())

        for line in conn_file:
            line = line.rstrip('\n')
            if not line:
                continue

            # Lock the client's message
            client_lock = next((lock for s, n, c, ip, lock in clients if s == conn), None)
            if client_lock:
                client_lock.acquire() # Lock the current client
    
            try:
                # Handle slow mode
                if slow_mode_enabled:
                    current_time = time.time()
                    if addr[0] in last_message_time:
                        time_since_last = current_time - last_message_time[addr[0]]
                        if time_since_last < slow_mode_interval:
                            conn.sendall(f"{timestamp()} {RED}Por favor espera {int(slow_mode_interval - time_since_last)} segundos antes de enviar otro mensaje.{RESET}\n".encode())
                            continue
                    last_message_time[addr[0]] = current_time
    
                if not line:
                    continue
    
                # Admin commands
                if is_admin:
                    if line.startswith('/kick '):
                        target_name = line.split(' ', 1)[1].strip()
                        target_sock = find_client_by_name(target_name)
                        if target_sock:
                            broadcast(f"{timestamp()} {RED}*** El admin ha expulsado a {target_name} ***{RESET}")
                            with clients_lock:
                                clients[:] = [(s, n, c, ip, lock) for (s, n, c, ip, lock) in clients if s != target_sock]
                            target_sock.sendall(f"{timestamp()} {RED}¡Has sido expulsado por un administrador!{RESET}\n".encode())
                            target_sock.close()
                        else:
                            conn.sendall(f"{timestamp()} {GREEN}Usuario {target_name} no encontrado.\n{RESET}".encode())
                        continue
    
                    elif line.startswith('/ban '):
                        target_name = line.split(' ', 1)[1].strip()
                        target_sock = find_client_by_name(target_name)
                        if target_sock:
                            # Find the user's IP and add it to the banned list
                            target_ip = next((ip for s, n, c, ip, lock in clients if s == target_sock), None)
                            if target_ip:
                                BANNED_IPS.append(target_ip)  # Ban the IP
                                broadcast(f"{timestamp()} {RED}*** El admin ha baneado a {target_name} (IP: {target_ip}) ***{RESET}")
                                with clients_lock:
                                    clients[:] = [(s, n, c, ip, lock) for (s, n, c, ip, lock) in clients if s != target_sock]
                                target_sock.sendall(f"{timestamp()} {RED}¡Tu IP ha sido baneada! No puedes volver a unirte al chat.\n{RESET}".encode())
                                target_sock.close()
                            else:
                                conn.sendall(f"{timestamp()} {GREEN}No se pudo encontrar la IP de {target_name}.\n{RESET}".encode())
                        else:
                            conn.sendall(f"{timestamp()} {GREEN}Usuario {target_name} no encontrado.\n{RESET}".encode())
                        continue
    
                    elif line.startswith('/unban '):
                        target_ip = line.split(' ', 1)[1].strip()
                        if target_ip in BANNED_IPS:
                            BANNED_IPS.remove(target_ip)  # Remove the IP from the banned list
                            # Notify the admin that the IP was unbanned
                            conn.sendall(f"{timestamp()} {GREEN}La IP {target_ip} ha sido desbaneada.\n{RESET}".encode())
                            # Notify all clients that the IP was unbanned
                            broadcast(f"{timestamp()} {GREEN}*** El admin ha desbaneado la IP {target_ip}. Los usuarios de esa IP pueden volver a conectarse. ***{RESET}")
                        else:
                            conn.sendall(f"{timestamp()} {RED}La IP {target_ip} no está en la lista de baneados.\n{RESET}".encode())
                        continue
    
    
                    elif line.startswith('/ip '):
                        target_name = line.split(' ', 1)[1].strip()
                        target_sock = find_client_by_name(target_name)
                        if target_sock:
                            # Find the user's IP
                            target_ip = next((ip for s, n, c, ip in clients if s == target_sock), None)
                            if target_ip:
                                conn.sendall(f"{timestamp()} {GREEN}La IP de {target_name} es {target_ip}\n{RESET}".encode())
                            else:
                                conn.sendall(f"{timestamp()} {GREEN}No se pudo encontrar la IP de {target_name}.\n{RESET}".encode())
                        else:
                            conn.sendall(f"{timestamp()} {GREEN}Usuario {target_name} no encontrado.\n{RESET}".encode())
                        continue
    
                    elif line.startswith('/slowmode '):
                        try:
                            interval = int(line.split(' ', 1)[1].strip())
                            if interval == 0:
                                slow_mode_enabled = False
                                # Notify that slowmode is off
                                conn.sendall(f"{timestamp()} {GREEN}El modo lento ha sido desactivado.\n{RESET}".encode())
                                # Notify all clients
                                broadcast(f"{timestamp()} {GREEN}*** El admin ha desactivado el modo lento. ***{RESET}")
                            else:
                                slow_mode_interval = interval
                                slow_mode_enabled = True
                                conn.sendall(f"{timestamp()} {GREEN}El modo lento ha sido activado con un intervalo de {slow_mode_interval} segundos.\n{RESET}".encode())
                                broadcast(f"{timestamp()} {GREEN}El modo lento ha sido activado con un intervalo de {slow_mode_interval} segundos.\n{RESET}")
                        except ValueError:
                            conn.sendall(f"{timestamp()} {RED}Uso incorrecto de /slowmode. Debes proporcionar un número de segundos.\n{RESET}".encode())
                        continue
    
                    elif line.startswith('/broadcast '):
                        message = line.split(' ', 1)[1].strip()
                        broadcast(f"{timestamp()} {RED}{message}\n{RESET}")
                        continue
    
                # Commands
                if line.strip().lower() == '/quit':
                    break
    
                elif line.strip().lower() == '/who':
                    with clients_lock:
                        names = ", ".join(n for _, n, _, _, _ in clients)
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
                        for i, (s, n, c, ip, lock) in enumerate(clients):
                            if s is conn:
                                clients[i] = (s, n, new_color, ip, lock)
                                break
                    conn.sendall(f"{timestamp()} {GREEN}Has cambiado tu color a{user_color} {color_name}{RESET}.\n".encode())
                    continue
    
                # Normal broadcast
                with clients_lock:
                    user_color = next((c for s, n, c, ip, lock in clients if s is conn), "\033[36m")
    
                broadcast(f'{timestamp()} {user_color}<{name}>{RESET} {line}', exclude_sock=conn)

            finally:
                if client_lock:
                    client_lock.release() # Unlock the client

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
        pass
    finally:
        with clients_lock:
            # remove this client's socket from list
            clients[:] = [(s, n, c, ip, lock) for (s, n, c, ip, lock) in clients if s != conn]
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
