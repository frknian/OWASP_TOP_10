import httpx
import pytest


@pytest.mark.integration
@pytest.mark.vulnerable
def test_vulnerable_stuffing_succeeds(stuffing_vulnerable_client: httpx.Client) -> None:
    # Vulnerable endpoint allows unlimited login attempts without blocking
    for i in range(10):
        res = stuffing_vulnerable_client.post(
            "/login",
            json={"username": "alice", "password": f"wrong-pass-{i}"}
        )
        assert res.status_code == 401
        assert "Geçersiz kullanıcı" in res.text

@pytest.mark.integration
@pytest.mark.fixed
def test_fixed_stuffing_is_blocked(stuffing_fixed_client: httpx.Client) -> None:
    # Ensure fresh state
    reset_res = stuffing_fixed_client.post("/reset")
    assert reset_res.status_code == 200

    try:
        # Submit 5 failed attempts (which is the MAX_ATTEMPTS limit)
        for i in range(5):
            res = stuffing_fixed_client.post(
                "/login",
                json={"username": "alice", "password": f"wrong-pass-{i}"}
            )
            # Up to 4 attempts returns 401. The 5th attempt triggers lockout and returns 429.
            # Let's check status codes.
            if i < 4:
                assert res.status_code == 401
                assert res.json()["detail"]["failed_attempts"] == i + 1
            else:
                assert res.status_code == 429
                assert "Çok fazla başarısız deneme" in res.json()["detail"]["error"]

        # The 6th attempt must be blocked immediately with 429, even with correct credentials
        res = stuffing_fixed_client.post(
            "/login",
            json={"username": "alice", "password": "Tr@ck3r-Alice-99!"}
        )
        assert res.status_code == 429
        assert "Retry-After" in res.headers
        assert int(res.headers["Retry-After"]) > 0

    finally:
        # Clean up state for other tests/runs
        stuffing_fixed_client.post("/reset")
