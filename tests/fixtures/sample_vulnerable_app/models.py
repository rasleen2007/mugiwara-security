"""Data access helpers containing unsafe query construction."""

from app import _CONNECTION


def find_user_raw(user_id):
    """Fetch a user using a concatenated raw query."""
    return _CONNECTION.execute("SELECT * FROM users WHERE id = " + str(user_id))


class UserManager:
    """Object manager mimicking Django-style raw queries."""

    def __init__(self, objects=None):
        self.objects = objects

    def by_email(self, email):
        """Return rows for an email using an interpolated raw statement."""
        return self.objects.raw(f"SELECT * FROM auth_user WHERE email = '{email}'")
