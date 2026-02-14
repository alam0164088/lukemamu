from rest_framework import serializers
from .models import User, Profile, Attorney
import re
import logging

logger = logging.getLogger(__name__)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    send_verification_otp = serializers.BooleanField(default=True, required=False)

    # রোল এবং অন্যান্য ফিল্ডগুলো যোগ করা হয়েছে
    role = serializers.ChoiceField(choices=['user', 'attorney'], default='user', required=False)
    gender = serializers.CharField(max_length=10, required=False, allow_blank=True)
    location = serializers.CharField(max_length=255, required=False, allow_blank=True)
    preferred_legal_area = serializers.CharField(max_length=255, required=False, allow_blank=True)
    designation = serializers.CharField(max_length=255, required=False, allow_blank=True)
    area_of_law = serializers.CharField(max_length=255, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm', 'full_name', 'send_verification_otp',
            'role', 'gender', 'location', 'preferred_legal_area',
            'designation', 'area_of_law'
        ]

    def validate(self, data):
        # পাসওয়ার্ড ম্যাচ চেক
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # পাসওয়ার্ড স্ট্রং কিনা চেক
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })

        # অ্যাটর্নি হলে designation ও area_of_law বাধ্যতামূলক
        role = data.get('role', 'user')
        if role == 'attorney':
            if not data.get('designation') or not data.get('area_of_law'):
                raise serializers.ValidationError({
                    "detail": "For attorney registration, 'designation' and 'area_of_law' are required."
                })

        # জেন্ডার চেক
        gender = data.get('gender')
        if gender and gender not in ['male', 'female', 'other']:
            raise serializers.ValidationError({"gender": "Gender must be 'male', 'female', or 'other'."})

        return data

    def create(self, validated_data):
        validated_data.pop("password_confirm", None)
        password = validated_data.pop("password")

        # non-User model fields remove
        validated_data.pop("send_verification_otp", None)
        validated_data.pop("designation", None)
        validated_data.pop("area_of_law", None)

        email = validated_data.get("email", "")
        if not validated_data.get("username"):
            base = email.split("@")[0] if email else "user"
            candidate = base
            i = 1
            while User.objects.filter(username=candidate).exists():
                candidate = f"{base}{i}"
                i += 1
            validated_data["username"] = candidate

        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email"),
            password=password,
            full_name=validated_data.get("full_name", ""),
            role=validated_data.get("role", "user"),
            gender=validated_data.get("gender", ""),
            location=validated_data.get("location", ""),
            preferred_legal_area=validated_data.get("preferred_legal_area", ""),
        )
        return user


# বাকি সিরিয়ালাইজারগুলো ঠিক আছে — শুধু VerifyOTPSerializer-এ purpose যোগ করুন (ভালো প্র্যাকটিস)
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)
    purpose = serializers.ChoiceField(
        choices=['email_verification', 'password_reset', 'two_factor'],
        required=False,
        help_text="Optional if context is clear, but recommended."
    )


# বাকি সব সিরিয়ালাইজার অপরিবর্তিত থাকবে
class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=['email_verification', 'password_reset', 'two_factor'])


class Verify2FASerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    method = serializers.ChoiceField(choices=['email'])


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False)


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class VerifyResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)


class ResetPasswordSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "new_password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "new_password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        return data


class Enable2FASerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['email', 'auth_app', 'sms'])


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=['email_verification'])


# Profile Serializers (ঠিক আছে, কোনো চেঞ্জ লাগবে না)
class ProfileUpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', required=False)
    gender = serializers.CharField(source='user.gender', required=False)
    location = serializers.CharField(source='user.location', required=False, allow_blank=True)
    preferred_legal_area = serializers.CharField(source='user.preferred_legal_area', required=False, allow_blank=True)
    image = serializers.ImageField(required=False)

    class Meta:
        model = Profile
        fields = ['full_name', 'phone', 'gender', 'location', 'preferred_legal_area', 'image']

    def validate_gender(self, value):
        if value and value not in ['male', 'female', 'other']:
            raise serializers.ValidationError("Gender must be 'male', 'female', or 'other'.")
        return value

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})

        if 'full_name' in user_data:
            instance.user.full_name = user_data['full_name']
        if 'gender' in user_data:
            instance.user.gender = user_data['gender']
        if 'location' in user_data:
            instance.user.location = user_data['location']
        if 'preferred_legal_area' in user_data:
            instance.user.preferred_legal_area = user_data['preferred_legal_area']

        instance.user.save()

        instance.phone = validated_data.get('phone', instance.phone)
        if 'image' in validated_data:
            instance.image = validated_data['image']

        instance.save()
        return instance


class UserProfileSerializer(serializers.ModelSerializer):
    profile_image = serializers.SerializerMethodField()
    phone = serializers.SerializerMethodField()
    email_verified = serializers.BooleanField(source="is_email_verified", read_only=True)
    attorney = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "full_name",
            "gender",
            "email_verified",
            "created_at",
            "role",
            "profile_image",
            "phone",
            "location",
            "preferred_legal_area",
            "attorney",
        ]

    def get_profile_image(self, obj):
        request = self.context.get("request")
        try:
            img = obj.profile.image.url
            return request.build_absolute_uri(img) if request else img
        except Exception:
            return None

    def get_phone(self, obj):
        try:
            return obj.profile.phone
        except Exception:
            return ""

    def get_attorney(self, obj):
        if obj.role != "attorney":
            return None
        ap = getattr(obj, "attorney_profile", None)
        if not ap:
            return None
        return {
            "designation": ap.designation,
            "area_of_law": ap.area_of_law,
            "bar_license_number": ap.bar_license_number,
            "bio": ap.bio,
            "languages": ap.languages,
            "experience": ap.experience,
            "response_time": ap.response_time,
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "full_name",
            "role",
            "gender",
            "location",
            "preferred_legal_area",
            "profile_image",
        ]