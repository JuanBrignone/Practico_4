import pytest
import requests

BASE_URL = "http://localhost:5000"

@pytest.mark.parametrize("payload", [
    "1 OR 1=1",
    "1' OR '1'='1",
    "1; DROP TABLE invoices;--",
    "' UNION SELECT * FROM users--",
    "1'--"
])
def test_visualizar_factura_sql_injection(payload):
    """
    Prueba de regresión para asegurar que no existe inyección SQL (CWE-89)
    en el endpoint de visualización de facturas (invoices).
    
    El test verifica que el servidor rechace payloads maliciosos en el parámetro ID
    con códigos de error HTTP apropiados (400 Bad Request) y no ejecute consultas SQL peligrosas.
    
    COMPORTAMIENTO ESPERADO:
    - En la branch practico2: Los tests deben PASAR ✓
      El backend tiene validación que rechaza IDs no numéricos con status 400
      
    - En la branch main: Los tests deben FALLAR ✗
      El backend es vulnerable y acepta payloads maliciosos con status 200/500
    """
    response = requests.get(f"{BASE_URL}/invoices/{payload}")
    
    assert response.status_code in [400, 404, 422], (
        f"❌ Posible SQL Injection detectada: el servidor aceptó el payload '{payload}' "
        f"con status {response.status_code}. Se esperaba 400/404/422."
    )

    # Verificar que no se filtren mensajes de error SQL en la respuesta
    forbidden_keywords = ["syntax error", "SQL", "mysql", "sqlite", "postgres", "ORA-", "knex"]
    response_lower = response.text.lower()
    leaked_keywords = [kw for kw in forbidden_keywords if kw.lower() in response_lower]
    
    assert not leaked_keywords, (
        f"❌ La respuesta filtra información sensible de SQL con el payload '{payload}'. "
        f"Keywords encontradas: {leaked_keywords}"
    )
