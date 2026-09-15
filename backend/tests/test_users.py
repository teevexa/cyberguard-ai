def test_list_users_requires_admin(authed_client):
    assert authed_client.get("/users").status_code == 403


def test_list_users_requires_auth(client):
    assert client.get("/users").status_code == 401


def test_admin_can_list_users(admin_client, regular_user):
    resp = admin_client.get("/users")
    assert resp.status_code == 200
    emails = [u["email"] for u in resp.json()]
    assert "admin@test.local" in emails
    assert "user@test.local" in emails


def test_admin_can_change_role(admin_client, regular_user):
    resp = admin_client.patch(f"/users/{regular_user.id}/role", json={"role": "SecurityAnalyst"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "SecurityAnalyst"


def test_non_admin_cannot_change_role(authed_client, regular_user):
    resp = authed_client.patch(f"/users/{regular_user.id}/role", json={"role": "Admin"})
    assert resp.status_code == 403


def test_admin_cannot_change_own_role(admin_client, admin_user):
    # Mirrors the self-ban guard below: an Admin demoting themself with no
    # other Admin around has no self-service way back in.
    resp = admin_client.patch(f"/users/{admin_user.id}/role", json={"role": "user"})
    assert resp.status_code == 400

    users = {u["email"]: u["role"] for u in admin_client.get("/users").json()}
    assert users["admin@test.local"] == "Admin"  # unchanged, not just rejected in the response


def test_admin_can_ban_and_unban_another_user(admin_client, regular_user):
    resp = admin_client.patch(f"/users/{regular_user.id}/ban", json={"banned": True})
    assert resp.status_code == 200
    assert resp.json()["banned"] is True

    resp = admin_client.patch(f"/users/{regular_user.id}/ban", json={"banned": False})
    assert resp.json()["banned"] is False


def test_admin_cannot_ban_self(admin_client, admin_user):
    resp = admin_client.patch(f"/users/{admin_user.id}/ban", json={"banned": True})
    assert resp.status_code == 400


def test_ban_unknown_user_404s(admin_client):
    resp = admin_client.patch("/users/00000000-0000-0000-0000-000000000000/ban", json={"banned": True})
    assert resp.status_code == 404


def test_banned_user_is_rejected_by_get_current_user(client, db_session, mocker):
    """Exercises the real get_current_user code path end-to-end (real signed
    JWT, real DB lookup) rather than just asserting the DB row — same
    technique as test_auth.py's token tests."""
    import time
    from types import SimpleNamespace

    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sqlalchemy import text

    import auth

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    mocker.patch("auth._get_signing_key", return_value=SimpleNamespace(key=public_key))

    user_id = "00000000-0000-0000-0000-000000000077"
    db_session.execute(
        text('INSERT INTO neon_auth."user" (id, email, role, banned) VALUES (:id, :email, :role, true)'),
        {"id": user_id, "email": "banned@test.local", "role": "user"},
    )
    db_session.commit()

    now = int(time.time())
    token = pyjwt.encode(
        {"sub": user_id, "iat": now, "exp": now + 3600, "iss": auth.AUTH_ISSUER, "aud": auth.AUTH_ISSUER},
        private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key-1"},
    )

    resp = client.get("/threats", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert "suspended" in resp.json()["detail"].lower()
