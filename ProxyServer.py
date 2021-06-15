import socket
import sys
import threading
import ssl


class ProxyServer:
    def __init__(self, PORT):
        #Set the server's socket protocol to IPv4 and TCP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Make the server's socket reusable
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.PORT = PORT
        self.MAX_LEN = 4096
        self.DEFAULT_TIMEOUT = 5
        #Set the acceptable ip addresses and the port to listen to
        self.server_socket.bind(('0.0.0.0', self.PORT))
        print("[*] Binding Socket...")
        #Set the number of hosts who can be in the waiting list
        self.server_socket.listen(5)
        self.clients = {}

    def serve_forever(self):
        try:
            while True:
                (client_socket, client_address) = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, name=client_address, args=(client_socket, client_address))
                client_thread.setDaemon(True)
                print("[*] Handling client on "+str(client_address))
                client_thread.start()
                self.clients[client_address] = client_thread

        except KeyboardInterrupt:
            print("[!] Closing Proxy server...")

        finally:
            self.server_socket.close()
            sys.exit(0)

    def handle_client(self, client_socket, client_address):
        protocol = 'http'
        while True:
            if protocol != 'https':
                request = client_socket.recv(self.MAX_LEN)
                data = request.decode('utf-8', errors='replace')
            else:
                print("---------RECOGNIZED AS HTTPS---------")
                data = client_socket.read(self.MAX_LEN)
            (dest_ip, dest_port, protocol) = self.parse_request(data, protocol)
            rhost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == 'http':
                self.http_proxy_server(client_socket, rhost, request, dest_ip, dest_port)
            elif protocol == 'https':
                client_socket = self.https_proxy_server(client_socket, rhost, request, dest_ip, dest_port)


    def http_proxy_server(self, client_socket, rhost, request, dest_ip, dest_port):
        print("############ Handing in HTTP ############")
        rhost.connect((dest_ip, dest_port))
        rhost.sendall(request)

        while True:
            response = rhost.recv(self.MAX_LEN)
            if len(response) > 0:
                client_socket.send(response)
            else:
                rhost.close()
                break

    def https_proxy_server(self, client_socket, rhost, request, dest_ip, dest_port):
        print("############ Handing in HTTPS ############")
        # Create a SSL connection with the client
        client_socket.send(b'HTTP/1.1 200 OK\r\n\r\n')
        # Proxy Server's SSL Certification and Public Key
        client_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        client_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

        #Create a SSL connection with the server (Using TLSv1)
        ssl_client_socket = client_context.wrap_socket(client_socket, server_side=True)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ssl_server_sock = server_context.wrap_socket(rhost, server_hostname=dest_ip)
        ssl_server_sock.connect((dest_ip, dest_port))
        ssl_server_sock.send(request)

        while True:
            response = ssl_server_sock.read(self.MAX_LEN)
            print(response)
            if len(response) > 0:
                ssl_client_socket.write(response)
            else:
                ssl_server_sock.close()
                break
        return ssl_client_socket

    def parse_request(self, request, protocol):
        print(request)
        request = request.split(' ')
        method = request[0]
        url = request[1]
        http_index = url.find('://')
        if method == 'CONNECT':
            protocol = 'https'
        if http_index != -1:
            #protocol = url[:(http_index)]
            url = url[(http_index+3):]
        hostname = url.split('/')[0]
        hostname = hostname.split(':')
        port = 80
        if len(hostname) > 1:
            port = int(hostname[1])

        return (hostname[0], port, protocol)



if __name__ == '__main__':
    if len(sys.argv) == 1:
        PORT = 8080
    else:
        PORT = int(sys.argv[1])
    server = ProxyServer(PORT)
    server.serve_forever()