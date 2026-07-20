import httpx
import pytest


@pytest.mark.integration
@pytest.mark.vulnerable
def test_vulnerable_sqli_succeeds(sqli_vulnerable_client: httpx.Client) -> None:
    # SQL Injection payload to bypass the ID check and retrieve all accounts
    payload = "1' OR '1'='1"
    response = sqli_vulnerable_client.get(f"/api/accounts?id={payload}")
    assert response.status_code == 200

    data = response.json()
    assert "results" in data
    # The vulnerability allows multiple (all) records to leak
    assert len(data["results"]) > 1

    names = [acc["name"] for acc in data["results"]]
    assert "Alice" in names
    assert "Bob" in names
    assert "Carol" in names

@pytest.mark.integration
@pytest.mark.fixed
def test_fixed_sqli_is_blocked(sqli_fixed_client: httpx.Client) -> None:
    # Same SQL Injection payload
    payload = "1' OR '1'='1"
    response = sqli_fixed_client.get(f"/api/accounts?id={payload}")
    assert response.status_code == 200

    data = response.json()
    assert "results" in data
    # Parameterized query searches for id="1' OR '1'='1", which returns nothing
    assert len(data["results"]) == 0
