from rest_framework.serializers import ModelSerializer

from Users.models import User


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id',
            'first_name',
            'last_name',
            'is_staff',
            'is_active',
            'email'
        )
        extra_kwargs = {
            'id': {'read_only': True},
            'is_staff': {'read_only': True},
            'is_active': {'read_only': True},
            'email': {'read_only': True},
        }
