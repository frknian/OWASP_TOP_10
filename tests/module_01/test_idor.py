import httpx
import pytest


@pytest.mark.integration
@pytest.mark.vulnerable
def test_vulnerable_idor_succeeds(idor_vulnerable_client: httpx.Client) -> None:
    # 1. Login as Alice
    login_res = idor_vulnerable_client.post(
        "/login",
        json={"username": "alice", "password": "AliceStrongPass!23"}
    )
    assert login_res.status_code == 200
    assert login_res.json()["message"] == "login successful"

    # 2. Query Alice's own account (ID = 1)
    own_res = idor_vulnerable_client.get("/api/accounts/1")
    assert own_res.status_code == 200
    assert own_res.json()["username"] == "alice"
    assert own_res.json()["email"] == "alice@example.com"

    # 3. Query Bob's account (ID = 2) - IDOR vulnerability
    bob_res = idor_vulnerable_client.get("/api/accounts/2")
    assert bob_res.status_code == 200
    assert bob_res.json()["username"] == "bob"
    assert bob_res.json()["email"] == "bob@example.com"
    assert "phone_number" in bob_res.json()

@pytest.mark.integration
@pytest.mark.fixed
def test_fixed_idor_is_blocked(idor_fixed_client: httpx.Client) -> None:
    # 1. Login as Alice
    login_res = idor_fixed_client.post(
        "/login",
        json={"username": "alice", "password": "AliceStrongPass!23"}
    )
    assert login_res.status_code == 200
    assert login_res.json()["message"] == "login successful"

    # 2. Query Alice's own account (ID = 1)
    own_res = idor_fixed_client.get("/api/accounts/1")
    assert own_res.status_code == 200
    assert own_res.json()["username"] == "alice"

    # 3. Try to query Bob's account (ID = 2) - Should be blocked by authorization check
    bob_res = idor_fixed_client.get("/api/accounts/2")
    assert bob_res.status_code == 403
    assert "bob@example.com" not in bob_res.text
    assert "phone_number" not in bob_res.json()
