import unittest
import http.client
import json
import threading
import requests
from mainjwks import hostName, serverPort, MyServer
from http.server import HTTPServer

class TestJWKSServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        #start server
        cls.server = HTTPServer((hostName, serverPort), MyServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        #close server
        cls.server.shutdown()
        cls.server_thread.join()

    def setUp(self):
        self.conn = http.client.HTTPConnection(hostName, serverPort)

    def tearDown(self):
        self.conn.close()

    def test_auth_without_expired(self):
        self.conn.request("POST", "/auth")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        token = response.read().decode()
        #test if token
        self.assertTrue(token)

    def test_auth_with_expired(self):
        self.conn.request("POST", "/auth?expired=1")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        token = response.read().decode()
        #test if token
        self.assertTrue(token)

    def test_jwks(self):
        self.conn.request("GET", "/.well-known/jwks.json")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        jwks = json.loads(response.read().decode())
        self.assertTrue("keys" in jwks)
        #test if keys
        self.assertTrue(jwks["keys"])

    def test_sql_injection_prevention(self):
        #attempt to delete keys table
        malicious_payload = "'; DROP TABLE keys; --"
        
        #try to get a token with malicious payload
        response = requests.post(f"http://localhost:8080/auth?expired={malicious_payload}")

        #if we still get valid JWKS the table wasn't dropped, SQL injection has failed.
        jwks_response = requests.get("http://localhost:8080/.well-known/jwks.json")
        
        assert jwks_response.status_code == 200, "Vulnerable to SQL injection!"
        assert "keys" in jwks_response.json(), "Vulnerable to SQL injection!"
    
    def test_put_method(self):
        response = requests.put("http://localhost:8080/some_endpoint")
        self.assertEqual(response.status_code, 405)

    def test_patch_method(self):
        response = requests.patch("http://localhost:8080/some_endpoint")
        self.assertEqual(response.status_code, 405)

    def test_delete_method(self):
        response = requests.delete("http://localhost:8080/some_endpoint")
        self.assertEqual(response.status_code, 405)

    def test_head_method(self):
        response = requests.head("http://localhost:8080/some_endpoint")
        self.assertEqual(response.status_code, 405)

if __name__ == "__main__":
    unittest.main()