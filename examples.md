# Autodesk Platform Services – OpenAPI REST Example code

## SSA secure service accounts Example code / Get 3LO access token, generate robot service account, alternative 3LO Authentication workflow
- [Secure Service Accounts Example for creating SA accounts, and generating 3LO access tokens in 3 languages (SSA)](https://developer.doc.autodesk.com/bPlouYTd/cloud-platform-ssa-docs-main-460369/ssa/v1/tutorials/getting-started-with-ssa/about-this-walkthrough.html)



This walkthrough demonstrates how to create a secure service account, provision that account, and obtain an access token using the service account.

The workflow representation of the steps are:

The following code snippets implement the REST API calls illustrated with cURL in this walkthrough:

### Create an SSA Robot Service Account

Install Python libraries and provide appropriate inputs before running the script.

```
# Install dependencies
# > pip install requests
import requests

# Configuration
APS_CLIENT_ID = "your_client_id"
APS_SECRET_ID = "your_client_secret"
FIRST_NAME = "service"                    # Service account first name
LAST_NAME = "mycompany-filesync"          # Service account last name
BASE_URL = "https://developer.api.autodesk.com/authentication/v2"
SCOPE_ADMIN = [
    "application:service_account:read",
    "application:service_account:write",
    "application:service_account_key:write"
]

# Get admin token using client credentials.
def get_admin_token():
    url = f"{BASE_URL}/token"
    data = {
        "grant_type": "client_credentials",
        "scope": " ".join(SCOPE_ADMIN)
    }
    response = requests.post(url, data=data, auth=(APS_CLIENT_ID, APS_SECRET_ID))
    response.raise_for_status()
    return response.json()["access_token"]


# Create a new service account with firstName, lastName, and concatenated name.
def create_service_account(admin_token):
    url = f"{BASE_URL}/service-accounts"
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "name": f"{FIRST_NAME}-{LAST_NAME}",
        "firstName": FIRST_NAME,
        "lastName": LAST_NAME
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print("Error creating service account:", response.text)
    response.raise_for_status()
    return response.json()


# Create a key for the specified service account.
def create_service_account_key(admin_token, service_account_id):
    url = f"{BASE_URL}/service-accounts/{service_account_id}/keys"
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = requests.post(url, headers=headers)
    if response.status_code != 200:
        print("Error creating service account key:", response.text)
    response.raise_for_status()
    return response.json()

def main():
    admin_token = get_admin_token()
    account_data = create_service_account(admin_token)
    SSA_EMAIL = account_data["email"]
    SERVICE_ACCOUNT_ID = account_data["serviceAccountId"]
    key_data = create_service_account_key(admin_token, SERVICE_ACCOUNT_ID)
    KEY_ID = key_data["kid"]
    PRIVATE_KEY = key_data["privateKey"]

    print(f'''
APS_CLIENT_ID="{APS_CLIENT_ID}"
APS_SECRET_ID="{APS_SECRET_ID}"
SERVICE_ACCOUNT_ID="{SERVICE_ACCOUNT_ID}"
KEY_ID="{KEY_ID}"
SSA_EMAIL="{SSA_EMAIL}"
PRIVATE_KEY="{PRIVATE_KEY}"''')

if __name__ == "__main__":
    main()
```

### Generate an (3LO) 3-Legged Access Token using SSA.  Examples in js, python and c# :

#### JavaScript
```
// Install dependencies before running:
// > npm install jsonwebtoken

import jwt from 'jsonwebtoken';

const CONFIG = {
  APS_CLIENT_ID: "your-client-id",
  APS_SECRET_ID: "your-client-secret",
  SERVICE_ACCOUNT_ID: "your-service-account-id",
  KEY_ID: "your-key-id",
  PRIVATE_KEY: `-----BEGIN RSA PRIVATE KEY-----
your-private-key
-----END RSA PRIVATE KEY-----`,
  SCOPE: ["data:read", "data:write"],
  TOKEN_URL: "https://developer.api.autodesk.com/authentication/v2/token" // Autodesk API token endpoint
};

// Generates a JWT assertion with RS256 using config credentials.
const generateJwtAssertion = () =>
  jwt.sign(
    {
      iss: CONFIG.APS_CLIENT_ID,
      sub: CONFIG.SERVICE_ACCOUNT_ID, // updated key reference
      aud: CONFIG.TOKEN_URL,
      exp: Math.floor(Date.now() / 1000) + 300,
      scope: CONFIG.SCOPE,
    },
    CONFIG.PRIVATE_KEY,
    {
      algorithm: "RS256",
      header: { alg: "RS256", kid: CONFIG.KEY_ID },
    }
  );

// Requests an access token using a JWT assertion from Autodesk API.
const getAccessToken = async (jwtAssertion) => {
  const basicAuth = `Basic ${Buffer.from(
    `${CONFIG.APS_CLIENT_ID}:${CONFIG.APS_SECRET_ID}`
  ).toString("base64")}`;

  const response = await fetch(CONFIG.TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuth,
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwtAssertion,
      scope: CONFIG.SCOPE.join(" "),
    }),
  });
  return response.json();
};

(async () => {
  try {
    const jwtAssertion = generateJwtAssertion();
    const result = await getAccessToken(jwtAssertion);
    console.log(JSON.stringify(result, null, 4));
  } catch (error) {
    console.error("Error fetching access token:", error);
  }
})();
```


#### Python

```
# install dependencies
# pip install requests
import jwt, time, requests, json

# === update hardcoded config values ===
APS_CLIENT_ID = "your-client-id"
APS_SECRET_ID = "your-client-secret"
SERVICE_ACCOUNT_ID = "your-service-account-id"
KEY_ID = "your-key-id"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
your-private-key
-----END RSA PRIVATE KEY-----"""
SCOPE = ["data:read", "data:write"]


def generate_jwt_assertion():
    return jwt.encode({
        "iss": APS_CLIENT_ID,
        "sub": SERVICE_ACCOUNT_ID,
        "aud": "https://developer.api.autodesk.com/authentication/v2/token",
        "exp": int(time.time()) + 300,
        "scope": SCOPE
    }, PRIVATE_KEY, algorithm="RS256", headers={"alg": "RS256", "kid": KEY_ID})


def get_access_token(jwt_assertion):
    response = requests.post('https://developer.api.autodesk.com/authentication/v2/token', headers={
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }, data={
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': jwt_assertion,
        'scope': ' '.join(SCOPE)
    }, auth=(APS_CLIENT_ID, APS_SECRET_ID))
    return response.json()


if __name__ == "__main__":
    jwt_assertion = generate_jwt_assertion()
    token_response = get_access_token(jwt_assertion)
    print(json.dumps(token_response, indent=2))
```

#### C#

``` 
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace AutodeskJWTExample
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string APS_CLIENT_ID = "your-client-id";
            string APS_SECRET_ID = "your-client-secret";
            string SERVICE_ACCOUNT_ID = "your-service-account-id";
            string KEY_ID = "your-key-id";
            string PRIVATE_KEY = @"-----BEGIN RSA PRIVATE KEY-----
your-private-key
-----END RSA PRIVATE KEY-----";
            string[] SCOPE = new string[] { "data:read", "data:write" };

            string jwtAssertion = GenerateJwtAssertion(KEY_ID, PRIVATE_KEY, APS_CLIENT_ID, SERVICE_ACCOUNT_ID, SCOPE);
            string tokenResponse = await GetAccessToken(jwtAssertion, APS_CLIENT_ID, APS_SECRET_ID, SCOPE);

            Console.WriteLine("Access Token Response:");
            Console.WriteLine(tokenResponse);
        }

        static string GenerateJwtAssertion(string keyId, string privateKeyPem, string clientId, string ssa_id, string[] scope)
        {
            // Create RSA from the PEM-formatted private key
            using RSA rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem.ToCharArray());

            var securityKey = new RsaSecurityKey(rsa)
            {
                KeyId = keyId
            };

            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            // Build JWT claims
            var claims = new List<Claim>
            {
                new Claim("iss", clientId),
                new Claim("sub", ssa_id),
                new Claim("aud", "https://developer.api.autodesk.com/authentication/v2/token"),
                new Claim("scope", string.Join(" ", scope))
            };

            // Create the token with a 5-minute expiration
            var jwtToken = new JwtSecurityToken(
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddSeconds(300),
                signingCredentials: signingCredentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(jwtToken);
        }

        static async Task<string> GetAccessToken(string jwtAssertion, string clientId, string clientSecret, string[] scope)
        {
            using HttpClient client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Post, "https://developer.api.autodesk.com/authentication/v2/token");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                { "assertion", jwtAssertion },
                { "scope", string.Join(" ", scope) }
            });

            // Encode client ID and secret for basic auth
            var authenticationString = $"{clientId}:{clientSecret}";
            var base64EncodedAuthenticationString = Convert.ToBase64String(Encoding.ASCII.GetBytes(authenticationString));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);

            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }
    }
}
```

# Autodesk Forge Viewer SDK – Example code

html
```
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="icon" href="data:,">
	<script src="https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*/viewer3D.min.js"></script>
	<link href="https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*/style.min.css" rel="stylesheet">
</head>

<body style="margin:0; overflow-y: hidden;">	
	<div id="Viewer"></div>
</body>
```

js
```
const AV = Autodesk.Viewing;
const div = document.getElementById("Viewer");

async function startViewer(urn) {
	const token = (await (await fetch("/api/token")).json()).access_token;

	AV.Initializer({ env: "AutodeskProduction2", api: 'streamingV2', accessToken: token }, () => {
        const options = { extensions: ["Autodesk.SmartSection"] }; // more extensions go here
        const viewer = new AV.Private.GuiViewer3D(div, options);
        viewer.start();
        viewer.setTheme("light-theme");

        // now, load a model urn
        AV.Document.load(`urn:${urn}`, (doc) => {
            const viewables = doc.getRoot().getDefaultGeometry();
            viewer.loadDocumentNode(doc, viewables).then(async (model)=>{
				await viewer.waitForLoadDone({ propDb: true, geometry: true });
			});
        });
    });
}
const encodedUrn = "dXJuOmFkc2sud2lwcHJvZDpmcy5maWxlOnZmLjIzWFR0R0pIUzJld1FxdDVOS1ppRGc";
startViewer(encodedUrn);
```

# Autodesk APS File upload to OSS

For uploading files to OSS Bucket storage using 2-legged, you must use the "signed url via s3" upload sequence (refer to the 'signeds3upload' code below).

python
```
import requests
import os
import json
import base64

class APSClient:
    def __init__(self):
        self.client_id = os.getenv('APS_CLIENT_ID')
        self.client_secret = os.getenv('APS_CLIENT_SECRET')
        self.bucket_key = os.getenv('APS_BUCKET_KEY')
        self.base_url = 'https://developer.api.autodesk.com'
        self._token = None

    def token(self):
        if self._token:
            return self._token
        
        url = f'{self.base_url}/authentication/v2/token'
        data = {
            'grant_type': 'client_credentials',
            'scope': 'data:read data:write'
        }
        response = requests.post(url, data=data, auth=(self.client_id, self.client_secret))
        token_data = response.json()
        self._token = token_data['access_token']
        return self._token

    def ensure_bucket(self):
        headers = {'Authorization': f'Bearer {self.token()}'}
        url = f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/details'
        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            create_url = f'{self.base_url}/oss/v2/buckets'
            payload = {
                'bucketKey': self.bucket_key,
                'policyKey': 'transient'
            }
            requests.post(create_url, json=payload, headers=headers)

    def upload(self, file_name, file_content):
        self.ensure_bucket()
        headers = {'Authorization': f'Bearer {self.token()}'}
        
        # Step 1: POST /signeds3upload
        url = f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/objects/{file_name}/signeds3upload'
        response = requests.post(url, headers=headers)
        s3_data = response.json()
        
        # Step 2: PUT to S3
        s3_response = requests.put(s3_data['uploadKey'], data=file_content)
        
        # Step 3: GET /signeds3upload to finalize
        finalize_response = requests.get(url, headers=headers)
        object_data = finalize_response.json()
        
        return object_data

    def translate(self, urn):
        headers = {
            'Authorization': f'Bearer {self.token()}',
            'Content-Type': 'application/json'
        }
        
        url = f'{self.base_url}/modelderivative/v2/designdata/job'
        payload = {
            'input': {'urn': urn},
            'output': {
                'formats': [{
                    'type': 'svf2',
                    'views': ['2d', '3d']
                }]
            }
        }
        
        response = requests.post(url, json=payload, headers=headers)
        return response.json()

    def status(self, urn):
        headers = {'Authorization': f'Bearer {self.token()}'}
        url = f'{self.base_url}/modelderivative/v2/designdata/{urn}/manifest'
        response = requests.get(url, headers=headers)
        return response.json()

    def list(self):
        headers = {'Authorization': f'Bearer {self.token()}'}
        url = f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/objects'
        response = requests.get(url, headers=headers)
        return response.json() 
```
