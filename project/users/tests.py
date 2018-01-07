from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework.reverse import reverse

from users.models import *


def create_superuser():
    """
    Creates and retuns a superuser - instance of settings.MONGOENGINE_USER_DOCUMENT
    """
    new_admin = User(
        username="admin",
        email="admin@example.com",
        first_name="admin",
        last_name="nimda",
        is_active=True,
        is_staff=True
    )
    new_admin.set_password('foobar')
    new_admin.save()
    return new_admin


def create_user():
    """
    Creates and returns a regular user - object of settings.MONGOENGINE_USER_DOCUMENT
    """
    new_user = User(
        username="testuser",
        email="testuser@test.com",
        first_name="test",
        last_name="user",
        bio="A funny guy!",
        is_active=True,
        is_staff=False
    )
    new_user.set_password('foobar')
    new_user.save()
    return new_user


class ObtainAuthTokenTestCase(APITestCase):
    def setUp(self):
        self.new_user = create_user()
        self.url = reverse("api:auth")

    def doCleanups(self):
        User.drop_collection()

    def test_post_correct_credentials(self):
        c = APIClient()
        print (self.url)
        response = c.post(self.url, {"username": "user@example.com", "password": "foobar"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertRegexpMatches(response.content.decode('UTF-8'), r'{"token":"\S+"}')

        token = Token.objects.get(user=self.new_user)
        self.assertRegexpMatches(token.key, "\S+")

    def test_post_incorrect_credentials(self):
        c = APIClient()

        response = c.post(self.url, {"username": "user@example.com", "password": ""})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserViewSetTestCase(APITestCase):
    def setUp(self):
        self.new_user = create_user()
        self.url = reverse("api:user-list")
        self.auth_header = 'Token 2c7e9e9465e917dcd34e620193ed2a7447140e5b'

        Token.objects.create(key='2c7e9e9465e917dcd34e620193ed2a7447140e5b', user=self.new_user)

    def doCleanups(self):
        User.drop_collection()
        Token.drop_collection()

    def test_get_unauthorized(self):
        c = APIClient()

        response = c.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_authorized(self):
        c = APIClient()

        response = c.get(self.url, HTTP_AUTHORIZATION=self.auth_header)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class UserUpdateViewTest(APITestCase):
    def setUp(self):
        self.new_user = create_user()
        self.superuser = create_superuser()
        self.url = reverse("api:updateuser")
        
        self.auth_header = "Token 2c7e9e9465e917dcd34e620193ed2a7447140e5b"
        self.token = Token.objects.create(key='2c7e9e9465e917dcd34e620193ed2a7447140e5b', user=self.new_user)
    
    def doCleanups(self):
        #self.new_user.delete()
        #token.delete()
        
        User.drop_collection()
        Token.drop_collection()
        
    def test_get_unauthorized(self):
        c = APIClient()
        
        response = c.post(self.url)
        print (response.status_code)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_existing_username(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        fresh_updates = {"username":"admin","first_name":"fresh_firstname","last_name":"mimi"\
                            ,"bio":"fresh bio my friend", "email":"fresh_email@gmail.com"}
        response = c.put(self.url, fresh_updates)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_existing_email(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        fresh_updates = {"username":"freshuser","first_name":"fresh_firstname","last_name":"mimi"\
                            ,"bio":"fresh bio my friend", "email":"admin@example.com"}
        response = c.put(self.url, fresh_updates)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
class PasswordChaneViewTest(APITestCase):
    def setUp(self):
        self.new_user = create_user()
        self.url = reverse("api:pwd_change")
        
        self.auth_header = "Token 2c7e9e9465e917dcd34e620193ed2a7447140e5b"
        self.token = Token.objects.create(key='2c7e9e9465e917dcd34e620193ed2a7447140e5b', user=self.new_user)
    
    def doCleanups(self):
        #self.new_user.delete()
        #token.delete()
        
        User.drop_collection()
        Token.drop_collection()

    def test_old_password(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        data = {"old_password":"oldpwd", "new_password1":"azerty123", "new_password2":"azerty123"}
        response = c.post(self.url, data)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_new_password_no_match(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        data = {"old_password":"foobar", "new_password1":"azerty", "new_password2":"azdqsd"}
        response = c.post(self.url, data)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_new_password_constraints(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        data = {"old_password":"foobar", "new_password1":"azerty1", "new_password2":"azerty1"}
        response = c.post(self.url, data)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_everything_is_ok(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=self.auth_header)
        data = {"old_password":"foobar", "new_password1":"azerty123", "new_password2":"azerty123"}
        response = c.post(self.url, data)
        print (response.content, response.status_code)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.new_user = User.objects.get(username=self.new_user.username)
        # Check if password edited
        if self.new_user.check_password("azerty123"): print ("Password did change.")
        else:
            print ("Something went wrong, password has not been changed.")
        
    
def execute_test() :
    
    new_test = PasswordChaneViewTest()
    new_test.doCleanups()
    new_test.setUp()
    #print ("first test: old password")
    #new_test.test_old_password()
    #print ("second test: new password no match")
    #new_test.test_new_password_no_match()
    #print ("third test: new password constraints")
    #new_test.test_new_password_constraints()
    print ("Fourth test: everything is ok")
    new_test.test_everything_is_ok()
    