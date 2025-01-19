from rest_framework.serializers import ModelSerializer

from CloudCart.utils import SerializerOptimizeMixin
from Users.models import User


class UserSerializer(ModelSerializer, SerializerOptimizeMixin):
    only_fields = [
        'id',
        'first_name',
        'last_name',
        'is_staff',
        'is_active',
        'email'
    ]

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
