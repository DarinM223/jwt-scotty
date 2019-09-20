A self-contained example of JWT authentication with Scotty. Everything other than the JWT authentication parts is simplified for easier understanding.

To build the project, you need to have GHC 8.6.5 installed through ghcup. Run `cabal new-build` and `cabal new-exec jwt-scotty` to start the server.

Logging in as a user and being granted a token:

![Screenshot](/images/login.png)

Using the token to verify logged-in user:

![Screenshot](/images/validation.png)