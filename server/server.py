import socket
import threading
import secrets
import hashlib
import sqlite3
from datetime import datetime

HOST="0.0.0.0"
PORT=5000

DB_FILE="server.db"

def init_db():
    conn=sqlite3.connect(DB_FILE)

    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
      )
    """)

    conn.execute("""
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                username TEXT,
                event TEXT,
                result TEXT
            )
    """)

    password_hash=hashlib.sha256(
        "Labpassword123".encode()
    ).hexdigest()

    conn.execute(
        """INSERT OR IGNORE INTO users VALUES (?,?)""",
        ("testuser",password_hash)
    )

    conn.commit()
    conn.close()

def log_event(client_ip,username,event,result):
    timestamp=datetime.now().isoformat()

    conn=sqlite3.connect(DB_FILE)

    conn.execute("""
        INSERT INTO events (timestamp, client_ip, username,event, result)
        VALUES (?,?,?,?,?)
        """, (
            timestamp,
            client_ip,
            username,
            event,
            result
        )
    )

    conn.commit()
    conn.close()

    print(
        f"[{timestamp}]"
        f"{client_ip} | {username} | "
        f"{event} | {result}"
    )


def authenticate(username,password):
    conn=sqlite3.connect(DB_FILE)

    row=conn.execute(
        "SELECT password_hash FROM users WHERE username=?",
        (username,)
    ).fetchone()

    conn.close()

    if row is None:
        return False

    password_hash=hashlib.sha256(
        password.encode()
    ).hexdigest()

    return password_hash==row[0]

def register_user(username,password):
    conn=sqlite3.connect(DB_FILE)

    password_hash=hashlib.sha256(
        password.encode()
    ).hexdigest()

    try:
        conn.execute(
            "INSERT INTO users (username,password_hash) VALUES (?,?)",
            (username,password_hash)
        )
        conn.commit()

        return True

    except sqlite3.IntegrityError:
        return False

    finally:

        conn.close()

def handle_client(client_socket,client_address):
    client_ip=client_address[0]

    username=None
    authenticated=False
    session_token=None

    print(f"[+] Connection from {client_address}")

    client_socket.send(
        b"Welcome to the Cyber Lab TCP Server\n"
         b"LOGIN using : LOGIN username password\n"
    )
       
    

    try:

        while True:
            data=client_socket.recv(4096)

            if not data:
                break

            message=data.decode(
                "utf-8",
                errors="replace"
            ).strip()

            print(
                f"[REQUEST] {client_ip}: {message}"
            )

            if message.startswith("LOGIN "):

                if authenticated:
                    client_socket.send(b"ERROR: Already logged in\n")
                    continue

                
                parts=message.split(" ")

                if(len(parts)!=3):
                    client_socket.send(
                        b"ERROR: Invalid LOGIN formate\n"
                    )
                    log_event(
                        client_ip,
                        "-",
                        "LOGIN",
                        "INVALID_FORMAT"
                    )

                    continue

                username=parts[1]
                password=parts[2]

                if authenticate(username,password):

                    authenticated=True  
                    session_token=secrets.token_hex(16)

                    client_socket.send(
                        f"LOGIN SUCCESS {session_token}\n"
                        .encode()
                    )

                    log_event(
                        client_ip,
                        username,
                        "LOGIN",
                        "SUCCESS"
                    )

                else:
                    authenticated=False

                    client_socket.send(
                        b"LOGIN FAILED\n"
                    )

                    log_event(
                        client_ip,
                        username,
                        "LOGIN",
                        "FAILED"
                    )

                continue
            if message=="LOGOUT":
                if authenticated:
                    authenticated=False
                    session_token=None

                    client_socket.send(b"LOGOUT SUCCESS\n")

                    log_event(
                        client_ip,
                        username,
                        "LOGOUT",
                        "SUCCESS"
                    )

                    username=None
                else:
                    client_socket.send(b"ERROR: Not Logged in\n")

                    log_event(
                        client_ip,
                        username,
                        "LOGOUT",
                        "FAILED: Not logged in"
                    )

                continue
            if message.startswith("REGISTER "):
                parts=message.split(" ")

                if len(parts)!=3:
                    client_socket.send(b"ERROR: Invalid REGISTER format\n")

                    log_event(
                        client_ip,
                        username,
                        "REGISTER",
                        "FAILED"
                    )

                    continue

                username=parts[1]
                password=parts[2]
                

                if register_user(username,password):
                    client_socket.send(b"REGISTER SUCCESS\n")

                    log_event(
                        client_ip,
                        username,
                        "REGISTER",
                        "SUCCESS"
                    )


                else:
                    client_socket.send(b"REGISTER FAILED: Username already exists\n")

                    log_event(
                        client_ip,
                        username,
                        "REGISTER",
                        "User already exists"
                    )

                continue





    except ConnectionResetError:
        print(
            f"[!] Connection reset by {client_address}"
        )

    finally:
        client_socket.close()
        print(
            f"[-] Connection closed from {client_address}" 
        )
    

def start_server():
            
        init_db()


        server=socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
            )

        server.bind((HOST,PORT))

        server.listen(10)

        print("="*50)
        print("Cyber Security Lab TCP Server")
        print("="*50)
        print(f"Listening on {HOST}:{PORT}")
        print("Test Account: testuser")
        print("Press Ctrl+C to stop")
        print("="*50)

        try:

            
            while True:

                client_socket,client_address=server.accept()

                thread=threading.Thread(
                    target=handle_client,
                    args=(client_socket,client_address),
                    daemon=True
                    )
                thread.start()

        except KeyboardInterrupt:
            print("\n [!] Server shutting down...")

        finally:
             server.close()


if __name__=="__main__":
    start_server()

        





