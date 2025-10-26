import re
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.validators import RegexValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

# ==============================
#   CUSTOM BASE MODEL (UUID)
# ==============================
class BaseModel(models.Model):
    """Base model with UUID primary key and timestamp tracking."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# ==============================
#   USER MANAGER
# ==============================
class UserManager(BaseUserManager):
    """Custom manager for User model with email as unique identifier."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")

        if not password:
            raise ValueError("Superusers must have a password.")
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)

_mobile_regex = re.compile(r'^0\d{10}$')
mobile_validator = RegexValidator(
    regex=_mobile_regex,
    message=_("Enter a valid mobile number starting with 0 and exactly 11 digits.")
)
# ==============================
#   USER MODEL
# ==============================
class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    ROLE_CHOICES = [
        ("customer", "Customer"),
        ("vendor", "Vendor"),
        ("affiliate_marketer", "Affiliate Marketer"),
        ("vendor_staff", "Vendor Staff"),
        ("staff", "Platform Staff"),
        ("admin", "Admin"),
    ]

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        unique=True,
        validators=[mobile_validator],
    )
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default="customer")

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.role})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def soft_delete(self):
        """Mark user as deleted instead of actually removing it."""
        self.is_active = False
        self.is_deleted = True
        self.save(update_fields=["is_active", "is_deleted"])


# ==============================
#   PROFILES
# ==============================
class CustomerProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="customer_profile")
    shipping_address = models.TextField(blank=True)
    billing_address = models.TextField(blank=True)
    loyalty_points = models.PositiveIntegerField(default=0)
    total_orders = models.PositiveIntegerField(default=0)
    total_spent = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"CustomerProfile: {self.user.email}"


class VendorProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="vendor_profile")
    store_name = models.CharField(max_length=255)
    store_description = models.TextField(blank=True)
    business_license_number = models.CharField(max_length=100, blank=True)
    verified = models.BooleanField(default=False)
    rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    total_sales = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    followers_count = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"VendorProfile: {self.store_name} ({self.user.email})"


class AffiliateMarketerProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="affiliate_profile")
    website_url = models.URLField(blank=True)
    referral_code = models.CharField(max_length=20, unique=True)
    commission_rate = models.DecimalField(max_digits=5, decimal_places=2, default=5.0)
    total_referrals = models.PositiveIntegerField(default=0)
    total_earned = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"AffiliateProfile: {self.user.email}"


class StaffProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="staff_profile")
    department = models.CharField(max_length=100, blank=True)
    employee_id = models.CharField(max_length=50, unique=True)
    permissions_level = models.CharField(max_length=50, default="standard")

    def __str__(self):
        return f"StaffProfile: {self.user.email}"


# ==============================
#   SIGNAL: AUTO CREATE PROFILE
# ==============================
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a profile based on user role."""
    if not created:
        return

    try:
        role = instance.role
        if role == "customer" and not hasattr(instance, "customer_profile"):
            CustomerProfile.objects.create(user=instance)

        elif role == "vendor" and not hasattr(instance, "vendor_profile"):
            VendorProfile.objects.create(user=instance, store_name=f"{instance.first_name}'s Store")

        elif role == "affiliate_marketer" and not hasattr(instance, "affiliate_profile"):
            from uuid import uuid4
            AffiliateMarketerProfile.objects.create(
                user=instance, referral_code=str(uuid4()).split("-")[0]
            )

        elif role in ["staff", "admin","vendor_staff"] and not hasattr(instance, "staff_profile"):
            StaffProfile.objects.create(user=instance)

    except Exception as e:
        # Log errors but don't crash user creation
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error auto-creating profile for {instance.email}: {str(e)}")
