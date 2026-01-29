from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, role=None, name=None):
        if not email:
            raise ValueError("Email is required")
        if not name:
            raise ValueError("Name is required")  # optional but good

        user = self.model(
            email=self.normalize_email(email),
            role=role,
            name=name
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, name=None):
        if not name:
            name = "Admin"  # default name for superuser
        user = self.create_user(
            email=email,
            password=password,
            role="admin",
            name=name
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
