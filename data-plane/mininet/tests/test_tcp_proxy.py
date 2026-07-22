import socketserver
import threading
import unittest

from tcp_proxy import ThreadingTCPProxy


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class TCPProxyTests(unittest.TestCase):
    def test_relays_bidirectional_tcp_stream(self):
        try:
            echo = socketserver.ThreadingTCPServer(
                ("127.0.0.1", 0),
                EchoHandler,
            )
        except PermissionError:
            self.skipTest("test environment does not permit local sockets")
        proxy = ThreadingTCPProxy(
            ("127.0.0.1", 0),
            echo.server_address,
        )
        echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        echo_thread.start()
        proxy_thread.start()

        try:
            with self.subTest("payload crosses both relay directions"):
                import socket

                with socket.create_connection(proxy.server_address) as client:
                    client.sendall(b"mutillidae-test")
                    self.assertEqual(client.recv(4096), b"mutillidae-test")
        finally:
            proxy.shutdown()
            echo.shutdown()
            proxy.server_close()
            echo.server_close()


if __name__ == "__main__":
    unittest.main()
