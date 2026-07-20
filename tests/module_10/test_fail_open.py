import httpx
import pytest


@pytest.mark.integration
@pytest.mark.vulnerable
def test_vulnerable_fail_open_succeeds(failopen_vulnerable_client: httpx.Client) -> None:
    # 1. Normal state: unauthenticated user is denied access
    normal_res = failopen_vulnerable_client.get("/admin/dashboard")
    assert normal_res.status_code == 200
    assert normal_res.json()["access"] == "denied"

    try:
        # 2. Simulate auth service outage
        outage_res = failopen_vulnerable_client.post("/simulate-outage")
        assert outage_res.status_code == 200
        assert outage_res.json()["auth_service_down"] is True

        # 3. Access during outage - should fail-open and grant access (VULNERABILITY)
        vuln_res = failopen_vulnerable_client.get("/admin/dashboard")
        assert vuln_res.status_code == 200
        assert vuln_res.json()["access"] == "granted"
        assert vuln_res.json()["degraded_mode"] is True
        assert "GİZLİ: admin paneli verileri" in vuln_res.json()["data"]

    finally:
        # 4. Restore auth service
        restore_res = failopen_vulnerable_client.post("/restore-service")
        assert restore_res.status_code == 200

@pytest.mark.integration
@pytest.mark.fixed
def test_fixed_fail_secure(failopen_fixed_client: httpx.Client) -> None:
    # 1. Normal state: unauthenticated user gets 403 Forbidden
    normal_res = failopen_fixed_client.get("/admin/dashboard")
    assert normal_res.status_code == 403
    assert "Admin yetkisi yok" in normal_res.json()["detail"]

    try:
        # 2. Simulate auth service outage
        outage_res = failopen_fixed_client.post("/simulate-outage")
        assert outage_res.status_code == 200
        assert outage_res.json()["auth_service_down"] is True

        # 3. Access during outage - should fail-secure and return 503 Service Unavailable
        fixed_res = failopen_fixed_client.get("/admin/dashboard")
        assert fixed_res.status_code == 503
        assert "geçici olarak kullanılamıyor" in fixed_res.json()["detail"]
        assert "GİZLİ" not in fixed_res.text

    finally:
        # 4. Restore auth service
        restore_res = failopen_fixed_client.post("/restore-service")
        assert restore_res.status_code == 200
