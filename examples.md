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
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>APS Model Viewer</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*/style.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { height: 100vh; overflow: hidden; font-family: Arial, sans-serif;}
        .header { padding: 4px; background: #3f51b5; color: white; display: flex; align-items: center; gap: 16px; height: 48px; }
        .header h1 { flex: 1; font-size: 16px; font-weight: normal; }
        .nav { display: flex; align-items: center; gap: 16px; }
        .adsk-viewing-viewer { height: calc(100vh - 48px) !important; }
        #fileInput { display: none; }
        #status { font-size: 14px; min-width: 80px; }
        select, button { padding: 8px; border: none; border-radius: 4px; }
        button { background: #2196f3; color: white; cursor: pointer; display: flex; align-items: center; gap: 8px; }
        select { background: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>APS Model Viewer</h1>
        <div class="nav">
            <input type="file" id="fileInput">
            <span id="status"></span>
            <select id="modelSelect" onchange="loadModel()">
                <option value="">Select Model</option>
            </select>
            <button onclick="$('fileInput').click()">
                <i class="material-icons">upload</i> Upload
            </button>
        </div>
    </div>
    <div id="viewer"></div>

    <script src="https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*/viewer3D.min.js"></script>
    <script>
        const $ = id => document.getElementById(id);
        const api = async (url, opt = {}) => (await fetch(url, opt)).json();
        const load = urn => Autodesk.Viewing.Document.load(`urn:${urn}`, d => viewer.loadDocumentNode(d, d.getRoot().getDefaultGeometry()));
        let viewer, token;

        async function init() {
            token = (await api('/api/token')).access_token;
            Autodesk.Viewing.Initializer({ env: 'AutodeskProduction', api: 'streamingV2', accessToken: token }, () => {
		const options = { extensions: ["Autodesk.SmartSection"] }; // more extensions go here
                viewer = new Autodesk.Viewing.GuiViewer3D($('viewer'), options);
                viewer.start();
	        viewer.setTheme("light-theme");

            });
            list();
        }
        
        const viewer = new AV.Private.GuiViewer3D(div, options);
        viewer.start();

        async function list() {
            const data = await api('/api/list');
            const s = $('modelSelect');
            s.innerHTML = '<option value="">Select Model</option>';
            data.items?.forEach(item => {
                const o = document.createElement('option');
                o.value = btoa(item.objectId);
                o.textContent = item.objectKey;
                s.appendChild(o);
            });
        }

        async function upload(file) {
            const fd = new FormData();
            fd.append('file', file);
            const data = await api('/api/upload', { method: 'POST', body: fd });
            monitor(data.urn);
            list();
        }

        async function monitor(urn) {
            const st = $('status');
            for (let i = 0; i < 30; i++) {
                const d = await api(`/api/status/${urn}`);
                if (d.status === 'success') {
                    st.textContent = 'Complete';
                    load(urn);
                    break;
                }
                if (d.status === 'failed') {
                    st.textContent = 'Failed';
                    break;
                }
                st.textContent = (d.progress?.match(/\d+/)?.[0] || '...') + '%';
                await new Promise(r => setTimeout(r, 2000));
            }
        }

        function loadModel() {
            const urn = $('modelSelect').value;
            if (urn) load(urn);
        }

        $('fileInput').onchange = e => e.target.files[0] && upload(e.target.files[0]);
        init();
    </script>
</body>
</html> 
```


# Autodesk APS File upload to OSS

For uploading files to OSS Bucket storage using 2-legged, you must use the "signed url via s3" upload sequence (refer to the 'signeds3upload' code below).

utils.py
```
import requests
import os
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
        response = requests.post(f'{self.base_url}/authentication/v2/token', 
                               data={'grant_type': 'client_credentials', 'scope': 'data:read data:write bucket:create'}, 
                               auth=(self.client_id, self.client_secret))
        self._token = response.json()['access_token']
        return self._token

    def ensure_bucket(self):
        headers = {'Authorization': f'Bearer {self.token()}'}
        response = requests.get(f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/details', headers=headers)
        if response.status_code in [403, 404]:
            create_headers = {**headers, 'x-ads-region': 'US'} # US, EMEA, AUS
            requests.post(f'{self.base_url}/oss/v2/buckets', 
                         json={'bucketKey': self.bucket_key, 'policyKey': 'transient'}, headers=create_headers)

    def upload(self, file_name, file_content):
        self.ensure_bucket()
        headers = {'Authorization': f'Bearer {self.token()}'}
        url = f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/objects/{file_name}/signeds3upload'
        
        s3_data = requests.get(url, headers=headers).json()
        requests.put(s3_data['urls'][0], data=file_content)
        
        return requests.post(url, json={'uploadKey': s3_data['uploadKey']}, 
                           headers={**headers, 'Content-Type': 'application/json'}).json()

    def translate(self, urn):
        return requests.post(f'{self.base_url}/modelderivative/v2/designdata/job',
                           json={'input': {'urn': base64.b64encode(urn.encode()).decode()},
                                'output': {'formats': [{'type': 'svf2', 'views': ['2d', '3d']}]}},
                           headers={'Authorization': f'Bearer {self.token()}', 'Content-Type': 'application/json'}).json()

    def status(self, urn):
        encoded_urn = base64.b64encode(urn.encode()).decode()
        return requests.get(f'{self.base_url}/modelderivative/v2/designdata/{encoded_urn}/manifest',
                          headers={'Authorization': f'Bearer {self.token()}'}).json()

    def list(self):
        return requests.get(f'{self.base_url}/oss/v2/buckets/{self.bucket_key}/objects',
                          headers={'Authorization': f'Bearer {self.token()}'}).json() 
```

server.py
```
from flask import Flask, request, jsonify, send_file
from dotenv import load_dotenv
import base64
from utils import APSClient

load_dotenv()

app = Flask(__name__)
aps_client = APSClient()

@app.route('/api/token')
def get_token():
    return jsonify({'access_token': aps_client.token()})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    result = aps_client.upload(file.filename, file.read())
    object_id = result['objectId']
    aps_client.translate(object_id)
    return jsonify({'objectId': object_id, 'urn': base64.b64encode(object_id.encode()).decode()})

@app.route('/api/status/<urn>')
def get_status(urn):
    return jsonify(aps_client.status(base64.b64decode(urn).decode()))

@app.route('/api/list')
def list_objects():
    return jsonify(aps_client.list())

@app.route('/')
def index():
    return send_file('viewer.html')

if __name__ == '__main__':
    app.run(debug=False, port=8080) 
```

