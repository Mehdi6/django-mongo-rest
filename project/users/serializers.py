from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework_mongoengine.serializers import DocumentSerializer
from mongoengine.fields import ObjectIdField

from users.models import User


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=_("Username"))
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                # From Django 1.10 onwards the `authenticate` call simply
                # returns `None` for is_active=False users.
                # (Assuming the default `ModelBackend` authentication backend.)
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)
            else:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg)

        attrs['user'] = user
        return attrs


class UserSerializer(DocumentSerializer):
    #id = serializers.IntegerField(read_only=False)
    user_id = ObjectIdField(source='id')
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'bio', )
        read_only_fields = ('email', )
    

class SignUpSerializer(DocumentSerializer):
    #id = serializers.IntegerField(read_only=False)
    user_id = ObjectIdField(source='id')
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password']#, 'first_name', 'last_name']

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    
    
    #set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)
        self.error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'password_constraints': _("Password constraints not respected."),
        }
        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError('Invalid password')
        
        return value

    def validate(self, attrs):
        # validate the passwords
        old_pwd = attrs.get('old_password')#getattr(self.request, 'old_password')
        self.validate_old_password(old_pwd)
        
        new_pwd1 = attrs.get('new_password1')
        new_pwd2 = attrs.get('new_password2')
        
        if new_pwd1 == new_pwd2:
            # validate password constraints : length and characters user
            if not self.validate_password_constraints(new_pwd1):
                # save the new password
                raise serializers.ValidationError(self.error_messages['password_constraints'])
        else:
            raise serializers.ValidationError(self.error_messages['password_mismatch'])
        
        self.new_pwd = new_pwd1
        
        return attrs
    
    def validate_password_constraints(self, pwd):
        if len(pwd) < 8:
            return False
        
        return True
        
    def save(self):
        # save the new password in the database
        self.user.set_password(self.new_pwd)
        self.user.save()
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(self.request, self.user)
