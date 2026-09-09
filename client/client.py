import socket
HOST="127.0.0.1"
PORT=5000

client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

client_socket.connect((HOST,PORT))

message_welcome=client_socket.recv(4096)
print(message_welcome.decode())


# login_msg="LOGIN testuser Labpassword123\n"
# client_socket.send(login_msg.encode())

# Log_success=client_socket.recv(4096)
# print(Log_success.decode())




while True:
    register_msg=input("Enter command: ")
    client_socket.send(register_msg.encode())
    register_respond=client_socket.recv(4096)
    print(register_respond.decode())

    if register_msg=="EXIT":
        break
    

