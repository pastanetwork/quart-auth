Quart-Auth Extended
===================

|Build Status| |docs| |pypi| |python| |license|

Quart-Auth Extended is a fork of `Quart-Auth
<https://github.com/pgjones/quart-auth>`_ with additional features for storing
secure user data in authentication cookies.

**New Features:**

- 🔒 **Store and modify user data** securely in authentication cookies
- 📝 **Mutable current_user** - works exactly like Quart's session
- ⚡ **orjson optimization** for better performance (optional)
- 🔄 **100% backward compatible** with original Quart-Auth
- 🚀 **Serverless-friendly** - no server-side session storage needed

Original Quart-Auth provides secure cookie authentication (session management)
for `Quart <https://gitlab.com/pgjones/quart>`_. This extended version adds
the ability to store arbitrary user data directly in the signed cookie.

Usage
-----

To use Quart-Auth with a Quart app you have to create an QuartAuth and
initialise it with the application,

.. code-block:: python

    app = Quart(__name__)
    QuartAuth(app)

or via the factory pattern,

.. code-block:: python

    auth_manager = QuartAuth()

    def create_app():
        app = Quart(__name__)
        auth_manager.init_app(app)
        return app

In addition you will need to configure Quart-Auth, which defaults to
the most secure. At a minimum you will need to set secret key,

.. code-block:: python

    app.secret_key = "secret key"  # Do not use this key

which you can generate via,

.. code-block:: python

    >>> import secrets
    >>> secrets.token_urlsafe(16)

You may also need to disable secure cookies to use in development, see
configuration below.

With QuartAuth initialised you can use the ``login_required``
function to decorate routes that should only be accessed by
authenticated users,

.. code-block:: python

    from quart_auth import login_required

    @app.route("/")
    @login_required
    async def restricted_route():
        ...

If no user is logged in, an ``Unauthorized`` exception is raised. To catch it,
install an error handler,

.. code-block:: python

    @app.errorhandler(Unauthorized)
    async def redirect_to_login(*_: Exception) -> ResponseReturnValue:
        return redirect(url_for("login"))

You can also use the ``login_user``, and ``logout_user`` functions to
start and end sessions for a specific ``AuthenticatedUser`` instance,

.. code-block:: python

    from quart_auth import AuthUser, login_user, logout_user

    @app.route("/login")
    async def login():
        # Check Credentials here, e.g. username & password.
        ...
        # We'll assume the user has an identifying ID equal to 2
        login_user(AuthUser(2))
        ...

    @app.route("/logout")
    async def logout():
        logout_user()
        ...

Extended Features
~~~~~~~~~~~~~~~~~

**current_user as Mutable Dictionary (like session):**

.. code-block:: python

    from quart_auth import create_user_with_data, login_user, current_user

    @app.route("/login/<username>")
    async def login(username):
        # Create user with initial data
        user = create_user_with_data(
            auth_id=f"user_{username}",
            remember_me=True,  # Will create permanent session
            username=username,
            email=f"{username}@example.com",
            role="admin" if username == "admin" else "user",
            preferences={"theme": "dark", "language": "en"}
        )
        login_user(user, remember=True)
        return f"Logged in as {username}"

    @app.route("/profile")
    @login_required
    async def profile():
        # Read user data and session info
        return {
            "auth_id": current_user.auth_id,
            "username": current_user.get("username"),
            "email": current_user.get("email"),
            "role": current_user.get("role"),
            "preferences": current_user.get("preferences"),
            # System properties (read-only)
            "remember_me": current_user.remember_me,
            "expires_at": current_user.expires_at.isoformat() if current_user.expires_at else None
        }

    @app.route("/update-preferences", methods=['POST'])
    @login_required
    async def update_preferences():
        # Modify user data directly like session!
        current_user['preferences']['theme'] = 'light'
        current_user['last_updated'] = '2024-03-15'
        current_user.update({'visit_count': current_user.get('visit_count', 0) + 1})

        # Cookie automatically updated on response!
        return {"message": "Preferences updated"}

**All dictionary operations work:**

.. code-block:: python

    # Set values
    current_user['key'] = 'value'

    # Update multiple values
    current_user.update({'key1': 'value1', 'key2': 'value2'})

    # Delete values
    del current_user['key']
    old_value = current_user.pop('key', 'default')

    # Clear all data (keeps auth_id)
    current_user.clear()

    # Get values
    value = current_user.get('key', 'default')
    value = current_user['key']

**System properties (read-only):**

.. code-block:: python

    # Session information
    is_permanent = current_user.remember_me
    expiration = current_user.expires_at  # Returns datetime object or None
    time_left = current_user.remaining    # Returns timedelta object or None

    # Check session expiration
    if current_user.remaining:
        from datetime import timedelta
        if current_user.remaining < timedelta(days=7):
            print(f"Session expires in {current_user.remaining.days} days!")

        # Or check hours remaining
        hours_left = current_user.remaining.total_seconds() // 3600
        print(f"Session expires in {hours_left:.0f} hours")

**Auto-renewal configuration:**

.. code-block:: python

    # Default: auto-renewal enabled
    auth = QuartAuth(app)

    # Disable auto-renewal (preserve original expiration)
    auth = QuartAuth(app, auto_renew_on_modification=False)

    # Or via config
    app.config['QUART_AUTH_AUTO_RENEW_ON_MODIFICATION'] = False

**Performance optimization with orjson (optional):**

.. code-block:: bash

    # Install with orjson for better performance
    pip install git+https://github.com/pastanetwork/quart-auth.git
    pip install orjson

    # Or add to requirements.txt
    git+https://github.com/pastanetwork/quart-auth.git
    orjson

**Key benefits:**

- **Session-like**: current_user works exactly like Quart's session - modify data directly
- **System properties**: Built-in remember_me, expires_at (datetime), auth_id - all read-only
- **Auto-renewal**: Configurable session renewal on data modification (default: enabled)
- **Serverless-friendly**: All user data stored in signed cookies, no server-side sessions
- **Secure**: Data is cryptographically signed and encrypted, system properties protected
- **Fast**: Optional orjson support for better JSON serialization performance
- **Compatible**: Works as a drop-in replacement for original Quart-Auth

The user (authenticated or not) is available via the global
``current_user`` including within templates,

.. code-block:: python

    from quart import render_template_string
    from quart_auth import current_user

    @app.route("/")
    async def user():
        return await render_template_string("{{ current_user.is_authenticated }}")

Installation
------------

**From GitHub (recommended for this extended version):**

.. code-block:: bash

    pip install git+https://github.com/pastanetwork/quart-auth.git
    pip install orjson  # Optional, for better performance

**Or add to requirements.txt:**

.. code-block:: text

    git+https://github.com/pastanetwork/quart-auth.git
    orjson

Contributing
------------

This is a fork of the original `Quart-Auth
<https://github.com/pgjones/quart-auth>`_ by pgjones.

For the extended version, please open issues or pull requests on this fork.
For the original Quart-Auth, visit the `original repository
<https://github.com/pgjones/quart-auth>`_.

Testing
~~~~~~~

The best way to test Quart-Auth is with Tox,

.. code-block:: console

    $ pip install tox
    $ tox

this will check the code style and run the tests.

Help
----

For the original Quart-Auth features, the `documentation
<https://quart-auth.readthedocs.io>`_ is the best place to start.

For the extended features (mutable current_user), see the examples in this repository:

- ``examples/extended_auth_demo.py`` - Complete demo with data modification and session-like usage
- ``examples/README.md`` - Detailed examples documentation

If you need help, try searching `stack overflow
<https://stackoverflow.com/questions/tagged/quart>`_ or ask for help
`on gitter <https://gitter.im/python-quart/lobby>`_. For issues specific
to the extended features, please open an issue on this fork's repository.


.. |Build Status| image:: https://github.com/pgjones/quart-auth/actions/workflows/ci.yml/badge.svg
   :target: https://github.com/pgjones/quart-auth/commits/main

.. |docs| image:: https://img.shields.io/badge/docs-passing-brightgreen.svg
   :target: https://quart-auth.readthedocs.io

.. |pypi| image:: https://img.shields.io/pypi/v/quart-auth.svg
   :target: https://pypi.python.org/pypi/Quart-Auth/

.. |python| image:: https://img.shields.io/pypi/pyversions/quart-auth.svg
   :target: https://pypi.python.org/pypi/Quart-Auth/

.. |license| image:: https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/pgjones/quart-auth/blob/main/LICENSE
