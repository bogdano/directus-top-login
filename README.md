# directus-otp-login
An endpoint extension that takes in a user id and an OTP (input by the user) from a POST request and returns an access token and refresh token, like `/auth/login` does.

`directus_users` needs **3 additional fields** for this extension:
 - `otp` for storing a randomly generated One-Time-Passkey,
 - `otp_expires` which is a datetime field set to now + 10 minutes on OTP generation, and
 - `otp_attempts` to prevent more than 3 attempts at verifying a generated key at a time, in a simple way.

The extension accepts a `userId` and an `otp` from user input as a `POST` request to `https://directus.your-app.com/otp-login/`. It returns a `400` error message when either one of those two parameters are missing from the payload, catches invalid user ids, prevents more than 3 failed attempts, checks `otp` from `directus_users` against the input `otp`, checks whether `otp_expires` is less than now (i.e. the generated OTP has expired).

It then generates an access token and a refresh token, _which is still in the testing phase_.


Intended to be called from a Flow Webhook/Request URL operation.
