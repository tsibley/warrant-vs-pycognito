# Warrant vs. pyCognito

Warrant and pyCognito are two Python libraries for talking to AWS Cognito.  The
latter is a fork of the former, and this repo is supporting material for
comparing where they've diverged (at least as of this moment in time).

The commit history in this repo detail how the source of each was transformed
to make comparison more informative, as well as the git commit ids of the
initial unmodified sources being compared.

## Notes

### SRP challenge response

pyCognito uses a slightly different username in parts of the SRP challenge
response, under the claim that it is more correct.  Two commits highlight the
differences:

```patch
commit 1a0b89c30d818652c031bf2b9ed00e3d55238ed1
Author: Pascal Vizeli <pascal.vizeli@syshack.ch>
Date:   Wed Feb 26 15:03:54 2020 +0100

    align flow to official java sdk (#1)
    
    Co-authored-by: Boris Erdmann <boris.erdmann@gmail.com>

diff --git a/warrant/aws_srp.py b/warrant/aws_srp.py
index 3b53f34..123c354 100644
--- a/warrant/aws_srp.py
+++ b/warrant/aws_srp.py
@@ -173,6 +173,7 @@ class AWSSRP(object):
         return base64.standard_b64encode(hmac_obj.digest()).decode('utf-8')
 
     def process_challenge(self, challenge_parameters):
+        internal_username = challenge_parameters['USERNAME']
         user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
         salt_hex = challenge_parameters['SALT']
         srp_b_hex = challenge_parameters['SRP_B']
@@ -188,13 +189,13 @@ class AWSSRP(object):
         hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
         signature_string = base64.standard_b64encode(hmac_obj.digest())
         response = {'TIMESTAMP': timestamp,
-                    'USERNAME': user_id_for_srp,
+                    'USERNAME': internal_username,
                     'PASSWORD_CLAIM_SECRET_BLOCK': secret_block_b64,
                     'PASSWORD_CLAIM_SIGNATURE': signature_string.decode('utf-8')}
         if self.client_secret is not None:
             response.update({
                 "SECRET_HASH":
-                self.get_secret_hash(self.username, self.client_id, self.client_secret)})
+                self.get_secret_hash(internal_username, self.client_id, self.client_secret)})
         return response
 
     def authenticate_user(self, client=None):
```

```patch
commit 0a18e889bf32b89b0005e26bfd4d26f2f9098604
Author: Kieren Eaton <circulon@users.noreply.github.com>
Date:   Sun Jan 10 21:31:59 2021 +0800

    Use same username as challenge parameters (#23)
    
    * Use same username as challenge parameters
    
    * Adjusted layout
    
    * Fixes for tests
    
    * Fixes for tests

diff --git a/pycognito/aws_srp.py b/pycognito/aws_srp.py
index c4f5d11..6077067 100644
--- a/pycognito/aws_srp.py
+++ b/pycognito/aws_srp.py
@@ -287,8 +287,12 @@ class AWSSRP:
             )
 
             if tokens["ChallengeName"] == self.NEW_PASSWORD_REQUIRED_CHALLENGE:
+                challenge_parameters = response["ChallengeParameters"]
                 challenge_response.update(
-                    {"USERNAME": auth_params["USERNAME"], "NEW_PASSWORD": new_password}
+                    {
+                        "USERNAME": challenge_parameters["USERNAME"],
+                        "NEW_PASSWORD": new_password,
+                    }
                 )
                 new_password_response = boto_client.respond_to_auth_challenge(
                     ClientId=self.client_id,
```

### Features

pyCognito does more stringent verification of JWTs received from Cognito after
authentication and provides methods for re-performing that verification if
you've restored the tokens from external storage.  While the secure
cryptographic signature still provides a good level of assurance and we can
broadly trust AWS, in security code it's often better to be exceedingly
stringent.  (Disclaimer: I contributed this code.)

pyCognito provides easy access to the verified claims in the id and access
tokens.  (Disclaimer: I contributed this code.)

pyCognito paginates the `get_users()` method so it actually returns all users
in a large pool.

pyCognito supports several admin actions/methods that Warrant does not.

### Tests

The tests are largely the same and don't appear to meaningfully differ in
functionality.  Both libraries have woefully poor tests for code involved in
authentication.  There are too many mocks of critical code and no actual
coverage or functionality tested.  The tests mostly test themselves or very
small units of library code, with no integration or end-to-end testing.

### Dependencies

pyCognito requires a newer minimum version of `python-jose[cryptography]`,
which is the library used for verifying JWTs.  Warrant pins to an older
version.  There may be no meaningful difference, but in general it's best to
stay current on security libraries.
