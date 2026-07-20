import httpx
import pytest


@pytest.mark.integration
@pytest.mark.vulnerable
def test_vulnerable_xss_succeeds(xss_vulnerable_client: httpx.Client) -> None:
    # XSS payload sent to search endpoint
    payload = "<script>alert('xss')</script>"
    response = xss_vulnerable_client.get(f"/search?q={payload}")
    assert response.status_code == 200

    # Vulnerable server reflects payload raw in HTML
    assert f"Arama sonucu: {payload}" in response.text
    assert f'"{payload}" için sonuç bulunamadı.' in response.text

@pytest.mark.integration
@pytest.mark.fixed
def test_fixed_xss_is_blocked(xss_fixed_client: httpx.Client) -> None:
    # Same XSS payload
    payload = "<script>alert('xss')</script>"
    response = xss_fixed_client.get(f"/search?q={payload}")
    assert response.status_code == 200

    # Fixed server escapes HTML tags before reflecting
    escaped_payload = "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    assert "<script>alert('xss')</script>" not in response.text
    assert escaped_payload in response.text
