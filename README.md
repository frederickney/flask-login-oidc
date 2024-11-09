# flask-login-oidc
Flask OpenID with flask-login

## Installation

```bash
pip install flask-login-oidc
```

## Setup

- Base login configuration

```python 
import flask

from flask_login import LoginManager, login_required, current_user
from flask_login_oidc import FlaskOIDC

app = flask.Flask('flask')
oidc = FlaskOIDC()


def redirect_login():
    return flask.redirect(flask.url_for('oidc.login'))


@app.route('/oidc/login/', endpoint='oidc.login', methods=['GET'])
def login():
    return oidc.login()


@app.route('/oidc/authorize/', endpoint='oidc.authorize', methods=['GET'])
def authorize():
    return oidc.authorize()


@app.route('/oidc/logout/', endpoint='oidc.logout', methods=['GET'])
@login_required
def logout():
    return oidc.logout()


@app.route('/', methods=['GET'])
@login_required
def index():
    return current_user.email


if __name__ == '__main__':
    lm = LoginManager(app)
    lm.unauthorized_handler(redirect_login)
    lm.user_loader(oidc.user)
    app.config['OIDC_CLIENT_SECRETS'] = 'secrets.json'
    app.config['OIDC_OPENID_REALM'] = 'realm'
    app.config['SECRET_KEY'] = 'secret'
    app.config['SESSION_TYPE'] = 'filesystem'
    oidc.init_app(app)
    app.run()

```

- Custom login configuration

```python
import flask

from flask_login import LoginManager, login_required, current_user
from flask_login_oidc import FlaskOIDC

app = flask.Flask('flask')
oidc = FlaskOIDC(prefix='SSO')


def redirect_login():
    return flask.redirect(flask.url_for('sso.login'))


@app.route('/sso/login/', endpoint='sso.login', methods=['GET'])
def login():
    return oidc.login()


@app.route('/sso/authorize/', endpoint='sso.authorize', methods=['GET'])
def authorize():
    return oidc.authorize()


@app.route('/sso/logout/', endpoint='sso.logout', methods=['GET'])
@login_required
def logout():
    return oidc.logout()


@app.route('/', methods=['GET'])
@login_required
def index():
    return current_user.email


if __name__ == '__main__':
    lm = LoginManager(app)
    lm.unauthorized_handler(redirect_login)
    lm.user_loader(oidc.user)
    app.config['SSO_CLIENT_SECRETS'] = 'secrets.json'
    app.config['SSO_OPENID_REALM'] = 'realm'
    app.config['SECRET_KEY'] = 'secret'
    app.config['SESSION_TYPE'] = 'filesystem'
    oidc.init_app(app)
    app.run()
```

## Using custom user model

Must be used after FlaskOIDC.init_app() or FlaskOIDC() if you are not using it

```python
oidc.user_model(UserModel)
```

See [user.py](https://github.com/frederickney/flask-login-oidc/blob/master/flask_login_oidc/user.py for more information about user model

## Custom login

Must be used after FlaskOIDC.init_app() or FlaskOIDC() if you are not using it

```python
def login(oidc_auth, model,  token):
    """
    
    :param oidc_auth: oauth client
    :type oidc_auth: OAuth2Mixin
    :param model: user model
    :param token: user's oauth token
    :return: 
    """
    pass

oidc.login_user(login)
```

## Custom logout

Must be used after FlaskOIDC.init_app() or FlaskOIDC() if you are not using it

```python

def logout(oidc_auth):
    """
    
    :param oidc_auth: auth client
    :type oidc_auth: OAuth2Mixin
    :return: 
    """
    pass

oidc.logout_user(logout)
```

## Custom client

Must be used after FlaskOIDC.init_app() or FlaskOIDC() if you are not using it

```python
def client(prefix):
    """

    :param prefix:
    :type prefix: str
    :return:
    :rtype: OAuth2Mixin
    """
    pass

oidc.client(client)
```

## Custom secret load

Must be used after FlaskOIDC.init_app() or FlaskOIDC() if you are not using it

```python
def secret(app, prefix):
    """

    :param app:
    :type app: flask.Flask
    :param prefix:
    :type prefix:str
    :return:
    :rtype: dict
    """
    pass

oidc.secret(secret)
```

Enjoy

# LICENSE

#### See [License file](LICENSE)