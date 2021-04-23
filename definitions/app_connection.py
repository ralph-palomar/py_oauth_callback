
class OAuthConnection:
    def __init__(self, connection_name, connection_type, client_id, client_secret, access_token, access_token_secret, user_id, user_name):
        self.connection_name = connection_name
        self.connection_type = connection_type
        self.user_id = user_id
        self.user_name = user_name
        self.access_token = access_token
        self.access_token_secret = access_token_secret
        self.client_id = client_id
        self.client_secret = client_secret


class ConnectionType:
    TWITTER = "Twitter"
    GOOGLE = "Google"
