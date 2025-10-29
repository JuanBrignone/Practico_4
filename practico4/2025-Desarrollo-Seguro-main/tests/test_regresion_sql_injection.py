import pytest
import requests
import time

BASE_URL = "http://localhost:5000"

TEST_USER_CREDENTIALS = {
    "username": "testuser_sql",
    "email": "testsql@example.local",
    "password": "TestPass123!",
    "first_name": "Test",
    "last_name": "SQLUser"
}

@pytest.fixture(scope="module")
def auth_token():
    """
    Fixture que obtiene un token de autenticación válido
    para realizar las pruebas
    """
    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/auth/", timeout=5)
            if response.status_code == 200:
                break
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                time.sleep(2)
            else:
                pytest.fail("No se pudo conectar con el backend después de 30 intentos")
    
    try:
        register_response = requests.post(
            f"{BASE_URL}/auth/register",
            json=TEST_USER_CREDENTIALS,
            timeout=10
        )
        
        if register_response.status_code not in [200, 201, 409]:
            print(f"Warning: Register response: {register_response.status_code} - {register_response.text}")
        
        seed_credentials = {
            "username": "test",
            "password": "password"
        }
        
        login_response = requests.post(
            f"{BASE_URL}/auth/login",
            json=seed_credentials,
            timeout=10
        )
        
        if login_response.status_code == 200:
            token = login_response.json().get("token")
            if token:
                return token
        
        print(f"Login failed: {login_response.status_code} - {login_response.text}")
            
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Error al obtener token de autenticación: {e}")

    pytest.fail("No se pudo obtener un token de autenticación válido")


def test_sql_injection_status_parameter_with_or_operator(auth_token):
    """
    TEST 1: SQL injection mediante parámetro status con operador OR.
    Verifica que payloads como paid OR 1=1 no exponen datos no autorizados.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    sql_injection_payloads = [
        "paid' OR '1'='1",
        "paid' OR 1=1--",
        "paid' OR 'x'='x",
        "' OR 1=1--"
    ]
    
    for payload in sql_injection_payloads:
        response = requests.get(
            f"{BASE_URL}/invoices",
            params={"status": payload, "operator": "="},
            headers=headers,
            timeout=10
        )
        
        assert response.status_code in [200, 400, 422], \
            f"Status code inesperado: {response.status_code} para payload: {payload}"
        
        if response.status_code == 200:
            data = response.json()
            response_text = str(data).lower()
            sql_error_keywords = [
                "syntax error", "sql", "mysql", "sqlite", 
                "postgres", "ora-", "query", "select", "from", "where"
            ]
            
            for keyword in sql_error_keywords:
                assert keyword not in response_text, \
                    f"Posible fuga de información SQL detectada con keyword {keyword} en payload: {payload}"
            
            if isinstance(data, list):
                # En sistema MITIGADO solo debe devolver facturas del usuario autenticado (max 3)
                assert len(data) <= 3, \
                    f"Posible SQL Injection: se devolvieron {len(data)} facturas con payload: {payload} (esperado max 3)"


def test_sql_injection_malicious_operator(auth_token):
    """
    TEST 2: SQL injection mediante operador SQL no autorizado.
    Verifica que solo se permiten operadores seguros (=, !=, <>, LIKE, NOT LIKE).
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    malicious_operators = [
        "= OR 1=1--",
        "UNION SELECT",
        "; DROP TABLE",
        "' OR '1'='1' --",
        "OR 1=1",
        "AND 1=1 UNION SELECT * FROM users--"
    ]
    
    for operator in malicious_operators:
        response = requests.get(
            f"{BASE_URL}/invoices",
            params={"status": "paid", "operator": operator},
            headers=headers,
            timeout=10
        )
        
        assert response.status_code == 400, \
            f"El sistema aceptó operador malicioso: {operator} (status code: {response.status_code})"

        if response.status_code == 400:
            response_data = response.json()
            assert "error" in response_data, \
                f"Respuesta 400 no contiene mensaje de error para operador: {operator}"


def test_sql_injection_union_based_attack(auth_token):
    """
    TEST 3: Ataque UNION-based SQL injection.
    Verifica que no se pueden extraer datos de otras tablas mediante UNION SELECT.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    union_payloads = [
        "paid' UNION SELECT id,email,password,NULL,NULL FROM users--",
        "paid' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3,4,5--",
        "paid' UNION ALL SELECT id,dni,email,name,role FROM users--"
    ]
    
    for payload in union_payloads:
        response = requests.get(
            f"{BASE_URL}/invoices",
            params={"status": payload, "operator": "="},
            headers=headers,
            timeout=10
        )
        
        # Sistema MITIGADO debe rechazar UNION o retornar error controlado
        assert response.status_code in [400, 422], \
            f"Sistema no rechazó UNION attack: status {response.status_code} para payload: {payload}"
        
        if response.status_code == 200:
            data = response.json()
            response_text = str(data).lower()
            
            sensitive_keywords = [
                "password", "hash", "bcrypt", "$2", 
                "admin@", "user@", "dni", "role"
            ]
            
            for keyword in sensitive_keywords:
                assert keyword not in response_text, \
                    f"Posible exposición de datos sensibles con keyword {keyword} mediante UNION attack"
            
            if isinstance(data, list) and len(data) > 0:
                # No debe devolver más facturas de las del usuario
                assert len(data) <= 3, \
                    f"UNION attack devolvió {len(data)} facturas (esperado max 3)"
                
                for invoice in data:
                    if isinstance(invoice, dict):
                        forbidden_keys = {"password", "email", "dni", "role", "name"}
                        actual_keys = set(invoice.keys())
                        
                        assert not (forbidden_keys & actual_keys), \
                            f"Estructura de respuesta contiene campos de otras tablas: {actual_keys}"


def test_sql_injection_comment_based_attack(auth_token):
    """
    TEST 4: Bypass mediante comentarios SQL (-- y #).
    Verifica que los comentarios SQL no permiten bypass de validaciones.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    comment_payloads = [
        "paid'--",
        "paid' --",
        "paid'#",
        "paid';--",
        "' OR 1=1--",
        "admin'--",
        "' OR '1'='1' --"
    ]
    
    for payload in comment_payloads:
        response = requests.get(
            f"{BASE_URL}/invoices",
            params={"status": payload, "operator": "="},
            headers=headers,
            timeout=10
        )
        
        assert response.status_code in [200, 400, 422, 500], \
            f"Status code inesperado: {response.status_code} para payload: {payload}"
        
        if response.status_code == 200:
            data = response.json()
            response_text = str(data).lower()
            sql_indicators = ["syntax", "error", "mysql", "postgres", "sql"]
            
            for indicator in sql_indicators:
                assert indicator not in response_text, \
                    f"Respuesta contiene indicador SQL {indicator} con payload: {payload}"
            
            if isinstance(data, list):
                # Solo debe devolver facturas del usuario (max 3)
                assert len(data) <= 3, \
                    f"Posible bypass de condiciones: se devolvieron {len(data)} facturas (esperado max 3)"


def test_sql_injection_special_characters_and_encoding(auth_token):
    """
    TEST 5: SQL injection con caracteres especiales y encoding.
    Verifica que caracteres especiales y URL encoding no permiten bypass.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    special_char_payloads = [
        "paid'; DROP TABLE invoices;--",
        "paid\"; DROP TABLE invoices;--",
        "paid' AND 1=1--",
        "paid' AND '1'='1",
        "paid\\' OR \\'1\\'=\\'1",
        "paid%27%20OR%20%271%27%3D%271",
        "paid' || '1'='1",
        "paid' AND SLEEP(5)--"
    ]
    
    for payload in special_char_payloads:
        response = requests.get(
            f"{BASE_URL}/invoices",
            params={"status": payload, "operator": "="},
            headers=headers,
            timeout=10
        )
        
        # Sistema MITIGADO debe rechazar caracteres especiales peligrosos
        assert response.status_code in [400, 422], \
            f"Sistema no rechazó payload malicioso: status {response.status_code} para: {payload}"
        
        if response.status_code == 200:
            data = response.json()
            response_text = str(data).lower()
            
            dangerous_indicators = [
                "drop", "delete", "insert", "update",
                "syntax error", "sql error", "query failed"
            ]
            
            for indicator in dangerous_indicators:
                assert indicator not in response_text, \
                    f"Posible inyección SQL con indicador {indicator} usando payload: {payload}"
            
            if isinstance(data, list):
                # Solo debe devolver facturas del usuario (max 3)
                assert len(data) <= 3, \
                    f"Respuesta sospechosa con {len(data)} facturas para payload: {payload} (esperado max 3)"
                
                for invoice in data:
                    if isinstance(invoice, dict):
                        assert "id" in invoice, \
                            f"Estructura de factura inválida con payload: {payload}"
                        assert "status" in invoice, \
                            f"Estructura de factura sin status con payload: {payload}"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
