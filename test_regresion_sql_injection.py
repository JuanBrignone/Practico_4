import pytest
import requests

BASE_URL = "http://localhost:3000"  

@pytest.mark.parametrize("payload", [
    "1 OR 1=1",
    "1' OR '1'='1",
    "1; DROP TABLE facturas;--",
    "' UNION SELECT * FROM usuarios--",
    "1'--"
])
def test_visualizar_factura_sql_injection(payload):
    """
    Prueba de regresión para asegurar que no existe inyección SQL (CWE-89)
    en el endpoint de visualización de facturas.
    """
    response = requests.get(f"{BASE_URL}/facturas/{payload}")
    

    assert response.status_code in [400, 404, 422], (
        f"Posible SQL Injection detectada: el servidor aceptó el payload {payload}"
    )

    forbidden_keywords = ["syntax error", "SQL", "mysql", "sqlite", "postgres", "ORA-"]
    assert not any(k.lower() in response.text.lower() for k in forbidden_keywords), (
        f"Respuesta contiene mensajes de error SQL con el payload {payload}"
    )
