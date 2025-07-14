# APS Developer Support Q&A Knowledge Base

## Documentation Queries

### Why does my refresh token keep expiring and how can I handle it properly?

Refresh tokens expire after 15 days for security reasons. To handle this:

#### Step 1: Store tokens securely
Store both access and refresh tokens securely

#### Step 2: Check access token expiration
Access tokens have a 1 hour lifetime

#### Step 3: Implement token refresh logic
```javascript
if (isTokenExpired()) {
  const newTokens = await getNewTokensWithRefresh(refreshToken);
  if (!newTokens) {
    // Redirect to login
    initiateThreeLeggedAuth();
  }
}
```

#### Step 4: Consider Service Account for long-term access
For long-term access, consider using a Service Account (SSA) with 2-legged authentication

### How do I set up my first ACC (Autodesk Construction Cloud) integration?

#### Step 1: Create an app
Create an app on [APS Developer Portal](https://aps.autodesk.com/)

#### Step 2: Request ACC API access
Request ACC API access through support

#### Step 3: Add required scopes
- account:read
- account:write
- data:read
- data:write

#### Step 4: Implement 3-legged OAuth

#### Step 5: Use Account Admin API
```http
GET /construction/admin/v1/accounts
```

Create project:
```http
POST /construction/admin/v1/accounts/{accountId}/projects
```

#### Step 6: Test with sample data
Test with sample data before production use

### What's the difference between 2-legged and 3-legged authentication for ACC?

**2-legged OAuth (app-only):**
- For non-user-specific operations
- Accessing public data
- Service-to-service communication

**3-legged OAuth (user context):**
- Required for ACC operations
- Accessing user's data
- Project management
- Document operations

**Choose based on:**
- Data access needs
- User context requirements
- Security requirements

ACC specifically requires 3-legged for most operations

### How do I handle file uploads to ACC correctly?

#### Step 1: Get project/folder context
```http
GET /data/v1/projects/{project_id}/folders/{folder_id}
```

#### Step 2: Create storage location
```http
POST /data/v1/projects/{project_id}/storage
```

#### Step 3: Upload file to signed URL

#### Step 4: Create item
```http
POST /data/v1/projects/{project_id}/items
```

#### Step 5: Create version
```http
POST /data/v1/projects/{project_id}/versions
```

#### Step 6: Monitor status
```http
GET /data/v1/projects/{project_id}/items/{item_id}
```

### Why am I getting 403 Forbidden errors with the Hubs API?

**Common causes and solutions:**

#### Check app provisioning:
- Verify BIM 360/ACC admin enabled the app
- Confirm correct account association

#### Verify scopes:
- data:read
- data:write (if needed)

#### Validate token:
- Correct 3-legged token
- Token not expired

#### Check user permissions in ACC/BIM360
#### Verify correct API endpoint usage

### How do I properly set up a Service Account (SSA) for automated ACC access?

#### Step 1: Create a Service Account in APS
- Generate unique email identifier
- Create private/public key pair

#### Step 2: Configure SSA
- Store private key securely
- Register public key with Autodesk Identity

#### Step 3: Generate JWT token using private key

#### Step 4: Exchange JWT for 3-legged token
```http
POST /authentication/v2/token
```
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
  "assertion": "<your_jwt_token>"
}
```

#### Step 5: Use token for API calls

### What's the process for handling 'Quota Limit Exceeded' errors in APS?

#### Step 1: Check current limits
- 500 calls/minute for authentication
- API-specific limits for other services

#### Step 2: Implement rate limiting
- Track API calls
- Use exponential backoff

#### Step 3: Monitor headers
- Retry-After
- X-RateLimit-Remaining

#### Step 4: Cache responses where possible
#### Step 5: Batch operations when available

### How do I create and manage issues in ACC via API?

#### Step 1: Get issue types
```http
GET /construction/issues/v1/projects/{projectId}/issue-types
```

#### Step 2: Create issue
```http
POST /construction/issues/v1/projects/{projectId}/issues
```

#### Step 3: Required fields
- title
- description
- issue_type_id
- issue_subtype_id

#### Step 4: Optional additions
Add attachments, assignees

#### Step 5: Monitor status
Use GET endpoint

### What's the correct way to handle file downloads from ACC/BIM360?

#### Step 1: Get item details
```http
GET /data/v1/projects/{project_id}/items/{item_id}
```

#### Step 2: Get version details
```http
GET /data/v1/projects/{project_id}/versions/{version_id}
```

#### Step 3: Get download URL
```http
GET /data/v1/projects/{project_id}/versions/{version_id}/downloads
```

#### Step 4: Handle large files
- Use chunked downloads
- Implement resume capability

#### Step 5: Verify download completion

### How do I set up webhooks for ACC file changes?

#### Step 1: Create webhook
```http
POST /webhooks/v1/systems/data/events/dm.version.added
```

#### Step 2: Configure callback URL
- Must be HTTPS
- Must respond to challenge

#### Step 3: Specify event types
- dm.version.added
- dm.version.modified

#### Step 4: Handle notifications
- Validate webhook signature
- Process async

#### Step 5: Implement retry logic

## How-To Queries

### How do I fix selection issues with individual parts in the Forge Viewer (v7.108.0) where the wrong hierarchy level is selected?

This is a common issue related to the viewer's selection behavior. Here's how to fix it:

#### Step 1: Set correct selection mode
```javascript
viewer.setSelectionMode(Autodesk.Viewing.SelectionMode.LEAF_OBJECT);
```

#### Step 2: Implement custom selection filter
```javascript
viewer.addEventListener(Autodesk.Viewing.SELECTION_CHANGED_EVENT, (event) => {
  const dbIds = event.dbIdArray;
  const model = viewer.model;

  // Get leaf nodes only
  const leafNodes = dbIds.filter(dbId => {
    return !model.getInstanceTree().getChildCount(dbId);
  });

  viewer.select(leafNodes);
});
```

#### Step 3: Add type checking for specific components
```javascript
function isSelectableComponent(dbId) {
  const model = viewer.model;
  const tree = model.getInstanceTree();
  const props = model.getProperties(dbId);
  
  return props.components && !tree.getChildCount(dbId);
}
```

### How do I activate the 'DiffTool' extension in APS Viewer?

#### Step 1: Load the extension
```javascript
viewer.loadExtension('Autodesk.Viewing.DiffTool').then(() => {
  // Extension loaded successfully
});
```

#### Step 2: Configure the diff tool
```javascript
const diffToolConfig = {
  mode: 'overlay', // or 'side-by-side'
  showDiffColor: true,
  diffColor: {
    added: new THREE.Vector4(0, 1, 0, 1), // Green
    removed: new THREE.Vector4(1, 0, 0, 1), // Red
    modified: new THREE.Vector4(0, 0, 1, 1) // Blue
  }
};

viewer.getDiffTool(diffToolConfig);
```

#### Step 3: Compare models
```javascript
const versionA = 'urn:version1';
const versionB = 'urn:version2';

viewer.diff(versionA, versionB);
```

### How do I determine if an ACC model is a Bridged model using APS?

You can determine this by checking the model's metadata and relationships through the Data Management API:

#### Step 1: Get item details
```http
GET /data/v1/projects/:project_id/items/:item_id
```

Response:
```json
{
  "data": {
    "type": "items",
    "relationships": {
      "refs": {
        "data": [{
          "type": "xrefs",
          "id": "..."
        }]
      }
    }
  }
}
```

#### Step 2: Check metadata properties
```http
GET /data/v1/projects/:project_id/items/:item_id/metadata
```

Response:
```json
{
  "data": {
    "type": "metadata",
    "attributes": {
      "extension": {
        "data": {
          "modelType": "bridged",
          "sourceSystem": "..."
        }
      }
    }
  }
}
```

### How do I handle SSO Login Issues with SamlNoUserFound Error on Autodesk Partner Portal?

#### Step 1: Verify SSO Configuration
```javascript
const config = {
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  callbackUrl: 'YOUR_CALLBACK_URL',
  scope: 'data:read data:write account:read'
};
```

#### Step 2: Implement proper error handling
```javascript
try {
  const response = await fetch('/api/forge/oauth/token', {
    method: 'POST',
    body: JSON.stringify(config)
  });

  if (response.status === 401) {
    // Handle SAML errors
    const error = await response.json();
    if (error.code === 'SamlNoUserFound') {
      // Redirect to account linking flow
      window.location.href = '/account/link';
    }
  }
} catch (error) {
  console.error('Authentication failed:', error);
}
```

#### Step 3: Add account linking flow
```javascript
app.get('/account/link', async (req, res) => {
  const { userId, email } = req.session;
  
  // Create or link Autodesk account
  const accountService = new AutodeskAccountService();
  await accountService.linkUserAccount(userId, email);
  
  res.redirect('/dashboard');
});
```

## Bug Reports and Issues

### Model Derivative APIs running slow / Model Derivative Timeout

#### Step 1: Implement chunked translation for large files
```http
POST /modelderivative/v2/designdata/job
```
```json
{
  "input": {
    "urn": "your_base64_urn",
    "compressedUrn": true,
    "rootFilename": "main.rvt"
  },
  "output": {
    "formats": [{
      "type": "svf2",
      "advanced": {
        "generateMasterViews": true,
        "maxFileSize": 1024
      }
    }]
  }
}
```

#### Step 2: Monitor job progress
```http
GET /modelderivative/v2/designdata/{urn}/manifest
```
```json
{
  "status": "inprogress",
  "progress": "80%",
  "messages": [{
    "type": "info",
    "message": "Translating geometry"
  }]
}
```

### Selection bug when using the APS viewer / Unpredictable box-selection behavior

#### Step 1: Implement proper selection handler
```javascript
viewer.addEventListener(Autodesk.Viewing.SELECTION_CHANGED_EVENT, (event) => {
  const selection = event.dbIdArray;

  // Filter out unwanted selections
  const validSelection = selection.filter(dbId => {
    const instanceTree = viewer.model.getInstanceTree();
    return instanceTree && !instanceTree.getChildCount(dbId);
  });

  // Force update selection
  viewer.select(validSelection);
});
```

#### Step 2: Fix box selection
```javascript
viewer.toolController.registerTool({
  getNames: () => ['box-select'],
  activate: () => {
    // Clear previous selection state
    this.selectedDbIds = new Set();
  },
  handleMouseMove: (event) => {
    // Update selection box
    this.updateSelectionBox(event);
    
    // Get elements under cursor
    const result = viewer.impl.hitTest(event.canvasX, event.canvasY, false);
    if (result) {
      this.selectedDbIds.add(result.dbId);
    }
  },
  handleButtonUp: () => {
    viewer.select([...this.selectedDbIds]);
  }
});
```

### Missing Hub when listing Hubs using Data Exchange GraphQL Query

#### Step 1: Use correct query structure
```graphql
query GetHubs {
  hubs {
    results {
      id
      name
      region
      extension {
        type
        version
        data {
          hostingType
          region
        }
      }
    }
    pagination {
      limit
      offset
      totalResults
    }
  }
}
```

#### Step 2: Include proper authorization
```javascript
const headers = {
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
};

const response = await fetch('/graphql', {
  method: 'POST',
  headers,
  body: JSON.stringify({
    query: query,
    variables: variables
  })
});
```

## Security and Authentication

### Autodesk Refresh Token keeps Expiring / Refresh Token - tree keeps Expiring in 14 days

#### Step 1: Implement proper token refresh flow
```javascript
async function refreshTokens(refreshToken) {
  const response = await fetch('https://developer.api.autodesk.com/authentication/v2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: YOUR_CLIENT_ID,
      client_secret: YOUR_CLIENT_SECRET
    })
  });
  return await response.json();
}
```

#### Step 2: Set up proactive token refresh
```javascript
// Refresh token when it's close to expiring (e.g., 1 hour before)
const REFRESH_THRESHOLD = 60 * 60 * 1000; // 1 hour in milliseconds

function shouldRefreshToken(expiresAt) {
  return Date.now() >= (expiresAt - REFRESH_THRESHOLD);
}
```

### Model don't load in Forge Viewer -- always gets OBJECT_TREE_UNAVAILABLE_EVENT

#### Step 1: Ensure proper model translation
```http
POST /modelderivative/v2/designdata/job
```
```json
{
  "input": {
    "urn": "YOUR_BASE64_URN"
  },
  "output": {
    "formats": [{
      "type": "svf2",
      "views": ["2d", "3d"]
    }]
  }
}
```

#### Step 2: Check translation status before loading
```javascript
async function checkTranslationStatus(urn) {
  const response = await fetch(`https://developer.api.autodesk.com/modelderivative/v2/designdata/${urn}/manifest`);
  const manifest = await response.json();
  return manifest.status === 'success';
}
```

#### Step 3: Implement proper viewer initialization
```javascript
function initializeViewer(urn) {
  const options = {
    env: 'AutodeskProduction2',
    api: 'streamingV2',
    getAccessToken: (onTokenReady) => {
      onTokenReady(accessToken, expiresIn);
    }
  };

  Autodesk.Viewing.Initializer(options, () => {
    const viewer = new Autodesk.Viewing.GuiViewer3D(document.getElementById('forgeViewer'));
    viewer.start();
    viewer.loadDocumentNode(urn, viewableId);
  });
}
```

## File Operations and Storage

### Autodesk OSS v2 API returns 404 when uploading IFC file

#### Step 1: Get signed URL for upload
```http
POST /oss/v2/buckets/:bucketKey/objects/:objectName/signeds3upload
```
```json
{
  "minutesExpiration": 60,
  "success_action_status": "201"
}
```

#### Step 2: Use proper content type and upload in chunks
```javascript
const uploadFile = async (signedUrl, file) => {
  await fetch(signedUrl, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': file.size.toString()
    },
    body: file
  });
};
```

#### Step 3: Complete the upload
```http
POST /oss/v2/buckets/:bucketKey/objects/:objectName/signeds3upload/complete
```
```json
{
  "uploadKey": "YOUR_UPLOAD_KEY"
}
```

### How to handle OSS Endpoints deprecation

#### Step 1: Update your endpoints
```javascript
// OLD (Deprecated)
const legacyEndpoints = {
  upload: '/oss/v1/buckets/{bucketKey}/objects/{objectName}',
  download: '/oss/v1/buckets/{bucketKey}/objects/{objectName}'
};

// NEW (Recommended)
const newEndpoints = {
  upload: '/oss/v2/buckets/{bucketKey}/objects/{objectName}/signeds3upload',
  download: '/oss/v2/signedcookies/{bucketKey}/objects/{objectName}'
};
```

#### Step 2: Implement signed URL workflow
```javascript
async function uploadFile(bucketKey, objectName, fileData) {
  // Get signed URL
  const signedUrlResponse = await fetch(`/oss/v2/buckets/${bucketKey}/objects/${objectName}/signeds3upload`);
  const { uploadKey, urls } = await signedUrlResponse.json();
  
  // Upload using signed URL
  await fetch(urls[0], {
    method: 'PUT',
    body: fileData,
    headers: {
      'Content-Type': 'application/octet-stream'
    }
  });
  
  // Complete upload
  await fetch(`/oss/v2/buckets/${bucketKey}/objects/${objectName}/signeds3upload`, {
    method: 'POST',
    body: JSON.stringify({ uploadKey })
  });
}
```

## Webhook Management

### Webhooks API - Auto-Reactivate Hook

#### Step 1: Create webhook with auto-reactivation
```http
POST /webhooks/v1/systems/derivative/hooks
```
```json
{
  "callbackUrl": "your_callback_url",
  "scope": {
    "workflow": "your_workflow_id"
  },
  "autoReactivateHook": true,
  "hookAttribute": {
    "projectId": "your_project_id",
    "hubId": "your_hub_id"
  }
}
```

#### Step 2: Monitor webhook status
```http
GET /webhooks/v1/systems/derivative/hooks/{hook_id}/status
```

#### Step 3: Implement retry logic in callback
```javascript
async function handleWebhookCallback(event) {
  const maxRetries = 3;
  let retryCount = 0;

  while (retryCount < maxRetries) {
    try {
      await processWebhookEvent(event);
      break;
    } catch (error) {
      retryCount++;
      await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
    }
  }
}
```

### How to handle multiple notifications for file modified events in BIM360

#### Step 1: Register webhook with proper scope
```http
POST /webhooks/v1/systems/data/events/dm.version.modified
```
```json
{
  "callbackUrl": "your_callback_url",
  "scope": {
    "folder": "your_folder_urn"
  },
  "filter": "version.type=items:autodesk.bim360:File"
}
```

#### Step 2: Implement idempotency in webhook handler
```javascript
async function handleWebhook(event) {
  const eventId = event.hook.event.id;

  // Check if event was already processed
  if (await isEventProcessed(eventId)) {
    return;
  }

  // Process event
  await processEvent(event);

  // Mark event as processed
  await markEventProcessed(eventId);
}
```

## Performance and Optimization

### Autodesk Viewer freezes when using SceneBuilder with Minimap3DExtension

#### Step 1: Implement progressive loading
```javascript
viewer.setProgressiveRendering(true);
viewer.setQualityLevel(false, false);
viewer.setGroundShadow(false);
```

#### Step 2: Optimize extensions
```javascript
class OptimizedMinimap3DExtension extends Autodesk.Viewing.Extension {
  load() {
    // Defer heavy operations
    requestAnimationFrame(() => {
      this.initializeMinimap();
    });
    
    // Use throttling for updates
    this.updateMinimap = _.throttle(this.updateMinimap, 100);
    return true;
  }

  initializeMinimap() {
    // Use lightweight geometry
    const minimapGeometry = this.simplifyGeometry(
      viewer.model.getGeometryList()
    );
  }
}
```

## Rate Limiting and Error Handling

### How to handle the 'Retry-After' header in API responses

#### Step 1: Check response headers
```javascript
if (response.headers['Retry-After']) {
  const waitTime = response.headers['Retry-After']
}
```

#### Step 2: Implement exponential backoff
- Start with header value
- Double wait time on subsequent failures

#### Step 3: Set maximum retries
- Set reasonable limit (e.g., 5)
- Log failures after limit

#### Step 4: Handle rate limits gracefully
#### Step 5: Cache successful responses

### Rate Limit change request for ACC Reviews API private beta

#### Step 1: Implement rate limit monitoring
```javascript
class RateLimitHandler {
  constructor() {
    this.remainingCalls = null;
    this.resetTime = null;
  }
  
  updateLimits(headers) {
    this.remainingCalls = headers.get('x-ratelimit-remaining');
    this.resetTime = headers.get('x-ratelimit-reset');
  }
  
  async makeRequest(endpoint) {
    if (this.remainingCalls === 0) {
      const waitTime = this.calculateWaitTime();
      await this.wait(waitTime);
    }
    
    const response = await fetch(endpoint);
    this.updateLimits(response.headers);
    return response;
  }
}
```

## Design Automation

### How to fix 'failed Instructions' status in Revit Design Automation

#### Step 1: Check your AppBundle configuration
```json
{
  "id": "YourAppBundle",
  "engine": "Autodesk.Revit+2024",
  "description": "Description",
  "settings": {
    "memoryLimit": 8192,
    "timeoutInMinutes": 60
  }
}
```

#### Step 2: Implement proper error handling in your add-in
```csharp
public class Commands : IExternalDBApplication
{
  public ExternalDBApplicationResult OnStartup(ControlledApplication app)
  {
    try {
      // Your code
      return ExternalDBApplicationResult.Succeeded;
    }
    catch (Exception ex) {
      LogError(ex);
      return ExternalDBApplicationResult.Failed;
    }
  }
}
```

#### Step 3: Check workitem payload
```json
{
  "activityId": "YourActivity",
  "arguments": {
    "rvtFile": {
      "url": "signed_url_to_input_file",
      "headers": {
        "Authorization": "Bearer " + token
      }
    },
    "result": {
      "verb": "put",
      "url": "signed_url_for_output"
    }
  }
}
```

## Best Practices and Recommendations

### APS導入に伴うAzureサーバーの推奨スペックにつきまして (Recommended Azure server specs for APS implementation)

#### Basic setup requirements
```json
{
  "minimum": {
    "cpu": "4 cores",
    "memory": "16 GB",
    "storage": "100 GB SSD",
    "network": "1 Gbps"
  },
  "recommended": {
    "cpu": "8 cores",
    "memory": "32 GB",
    "storage": "256 GB SSD",
    "network": "2+ Gbps"
  },
  "scaling": {
    "model_translation": "+4 cores per concurrent job",
    "viewer_hosting": "+2 GB memory per 100 concurrent users"
  }
}
```

#### Load balancing configuration
```javascript
const serverConfig = {
  autoscaling: {
    minInstances: 2,
    maxInstances: 10,
    metrics: {
      cpu: {
        target: 70,
        scaleUp: 85,
        scaleDown: 40
      },
      memory: {
        target: 75,
        scaleUp: 90,
        scaleDown: 50
      }
    }
  }
};
```

### Use of SVG file as Ribbon Icons - What's recommended?

#### Step 1: Icon preparation
```xml
<!-- Recommended SVG format -->
<svg width="16" height="16" viewBox="0 0 16 16">
  <path d="..." fill="currentColor" />
</svg>
```

#### Step 2: Implementation in ribbon
```javascript
const ribbonConfig = {
  icons: {
    format: 'svg',
    size: {
      small: 16,
      large: 32
    },
    states: {
      default: { opacity: 1 },
      disabled: { opacity: 0.5 }
    },
    theming: {
      useCurrentColor: true,
      supportsDarkMode: true
    }
  }
};
```

## Security Best Practices

### Your APS developer credentials are exposed in public GitHub project

#### Step 1: Immediate actions
```javascript
// Instead of:
const CLIENT_ID = "ABCD1234";
const CLIENT_SECRET = "XYZ789";

// Use:
const CLIENT_ID = process.env.APS_CLIENT_ID;
const CLIENT_SECRET = process.env.APS_CLIENT_SECRET;
```

#### Step 2: Implement secure credential management
```javascript
const config = {
  loadFromEnvironment: () => ({
    clientId: process.env.APS_CLIENT_ID,
    clientSecret: process.env.APS_CLIENT_SECRET,
    scope: process.env.APS_SCOPE
  }),
  validate: (credentials) => {
    if (!credentials.clientId || !credentials.clientSecret) {
      throw new Error('Missing required credentials');
    }
  }
};
```

## Feature Requests and Enhancements

### Interested in Exporting ACC/BIM360 markups / Filter issue markup pins while exporting sheet/files

Proposed API enhancement:
```http
GET /construction/markups/v1/projects/{project_id}/sheets/{sheet_id}/markups
```
```json
{
  "filter": {
    "type": ["pin", "cloud", "text"],
    "author": ["userId"],
    "dateRange": {
      "from": "2024-01-01",
      "to": "2024-03-21"
    }
  },
  "include": ["comments", "attachments"],
  "format": "pdf|json|csv"
}
```

### APS - How to know in ACC if the developer uses 2-legged or 3-legged authentication

Proposed enhancement:
```http
GET /authentication/v2/token/info
```
```json
{
  "token": "YOUR_TOKEN",
  "response": {
    "auth_type": "2-legged|3-legged",
    "scopes": ["data:read", "data:write"],
    "context": {
      "isServiceAccount": true|false,
      "userContext": true|false
    }
  }
}
```

### Select returned fields from API call / Need help for Data Management API

Proposed field selection system:
```http
GET /data/v1/projects/{project_id}/items
```
```json
{
  "fields": {
    "include": [
      "displayName",
      "createTime",
      "lastModifiedTime",
      "customAttributes.specific_field"
    ],
    "exclude": [
      "versions",
      "relationships"
    ]
  }
}
```

## Autodesk AEC Integration

### Want to select only reference planes with specific names and subcategories in RVT file

Using Model Derivative API to get element properties:
```http
GET /modelderivative/v2/designdata/{urn}/metadata
```
```json
{
  "filter": {
    "category": "Reference Planes",
    "properties": {
      "name": ["specific_name_1", "specific_name_2"],
      "subcategory": ["subcategory_1"]
    }
  }
}
```

Viewer implementation:
```javascript
viewer.addEventListener(Autodesk.Viewing.SELECTION_CHANGED_EVENT, (event) => {
  const selection = event.dbIdArray;
  viewer.getProperties(selection[0], (props) => {
    if (props.properties.some(p =>
      p.displayName === "Category" &&
      p.displayValue === "Reference Planes" &&
      matchesFilter(props.properties))) {
      // Handle reference plane selection
    }
  });
});
```

### Opening documents for Projects Hosted in ACC (API)

#### Step 1: Get project information
```http
GET /project/v1/hubs/{hub_id}/projects/{project_id}
```
```json
{
  "included": ["folders", "permissions"]
}
```

#### Step 2: Access document
```http
GET /data/v1/projects/{project_id}/items/{item_id}
```
```json
{
  "included": ["versions", "storage"]
}
```

#### Step 3: Download or view
For download:
```http
GET /oss/v2/buckets/{bucketKey}/objects/{objectName}
```

For viewing:
```http
POST /modelderivative/v2/designdata/job
```
```json
{
  "input": {
    "urn": "base64_encoded_urn"
  },
  "output": {
    "formats": [{
      "type": "svf2",
      "views": ["2d", "3d"]
    }]
  }
}
```

## Common Error Patterns

### projects/:project_id/versions (Create Version Endpoint) throwing error 403 (FOLDER VIOLATION)

#### Step 1: Check folder permissions
```http
GET /data/v1/projects/{project_id}/folders/{folder_id}/permissions
```

#### Step 2: Ensure proper scopes in your token
```javascript
const scopes = [
  'data:write',
  'data:create',
  'bucket:create',
  'bucket:read'
];
```

#### Step 3: Verify folder access level
```json
{
  "folder": {
    "id": "folder_id",
    "permissions": {
      "createVersions": true,
      "createItems": true
    }
  }
}
```

### Unable to get Hubs with SSA

#### Step 1: Generate JWT token
```javascript
const jwt = require('jsonwebtoken');

const token = jwt.sign({
  iss: your_client_id,
  sub: your_client_id,
  aud: 'https://developer.api.autodesk.com/authentication/v2/token',
  scope: 'data:read'
}, privateKey, {
  algorithm: 'RS256'
});
```

#### Step 2: Exchange for access token
```http
POST /authentication/v2/token
```
```json
{
  "grant_type": "client_credentials",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "scope": "data:read"
}
```

#### Step 3: Use token to access hubs
```http
GET /project/v1/hubs
```
Headers:
```json
{
  "Authorization": "Bearer " + access_token
}
```

### Unintended Camera View Change after Sketch edit Exit on a Face

#### Step 1: Save camera state before operation
```javascript
const state = viewer.getState({
  viewport: true,
  objectSet: true,
  renderOptions: true
});
```

#### Step 2: Handle sketch exit event
```javascript
viewer.addEventListener(Autodesk.Viewing.GEOMETRY_LOADED_EVENT, () => {
  if (savedState) {
    viewer.restoreState(savedState, {
      viewport: true,
      renderOptions: true
    });
  }
});
```

#### Step 3: Implement camera lock
```javascript
viewer.navigation.setLockSettings({
  orbit: true,
  pan: true,
  zoom: true,
  roll: true
});
```

### About Data Management API buckets

#### Step 1: Create bucket
```http
POST /oss/v2/buckets
```
```json
{
  "bucketKey": "your_bucket_key",
  "policyKey": "transient",
  "allow": ["read", "write"]
}
```

#### Step 2: Upload file to bucket
```javascript
// Get upload URL
POST /oss/v2/buckets/{bucketKey}/objects/{objectName}/signeds3upload

// Upload using signed URL
PUT {signedUrl}
```
Headers:
```json
{
  "Content-Type": "application/octet-stream"
}
```

#### Step 3: Check bucket info
```http
GET /oss/v2/buckets/{bucketKey}/details
```

## Model Conversion and Translation

### Missing elements when converting RVT to IFC / IFC v4 translation failed

#### Step 1: Use proper translation settings
```http
POST /modelderivative/v2/designdata/job
```
```json
{
  "input": {
    "urn": "your_base64_urn"
  },
  "output": {
    "formats": [{
      "type": "ifc",
      "advanced": {
        "conversionMethod": "modern",
        "buildingStoreys": {
          "generateIfcSiteElevation": true,
          "generateSpatialStructure": true
        },
        "spaces": {
          "generateSpaceBoundaries": true
        }
      }
    }]
  }
}
```

#### Step 2: Monitor conversion status
```http
GET /modelderivative/v2/designdata/{urn}/manifest
```

#### Step 3: Implement error handling
```javascript
async function checkTranslationStatus(urn) {
  const response = await fetch(`/modelderivative/v2/designdata/${urn}/manifest`);
  const data = await response.json();

  if (data.status === 'failed') {
    const errors = data.derivatives
      .filter(d => d.status === 'failed')
      .map(d => d.messages)
      .flat();
    
    // Log errors for debugging
    console.error('Translation failed:', errors);
    
    // Retry with different settings if needed
    await retryTranslation(urn);
  }
}
```

### Why don't we have any API for extraction without Unit Format?

The Model Derivative API actually supports unit format control through the following methods:

#### Step 1: When translating a model
```http
POST /modelderivative/v2/designdata/job
```
```json
{
  "input": {
    "urn": "your_base64_urn"
  },
  "output": {
    "formats": [{
      "type": "svf",
      "advanced": {
        "formatOptions": {
          "exportCoordinationView": true,
          "keepOriginalCoordinates": true
        }
      }
    }]
  }
}
```

#### Step 2: When fetching properties
```http
GET /modelderivative/v2/designdata/{urn}/metadata/{guid}/properties
```
```json
{
  "options": {
    "returnUnits": false
  }
}
```

## Advanced Workflows

### How to handle point cloud (RCP) files in the APS Viewer

#### Step 1: Upload RCP file
```http
POST /data/v1/projects/{project_id}/storage
```

#### Step 2: Translate file
```http
POST /modelderivative/v2/designdata/job
```

#### Step 3: Configure viewer
- Enable point cloud extension
- Set performance options

#### Step 4: Handle large datasets
- Use progressive loading
- Implement LOD controls

#### Step 5: Monitor memory usage

### How to handle metadata for multiple documents in ACC

#### Step 1: Get item IDs
```http
GET /data/v1/projects/{project_id}/items
```

#### Step 2: For each item
- Check current metadata
- Prepare metadata payload

#### Step 3: Update metadata in batch
- Use custom attributes
- Include version info

#### Step 4: Verify updates
```http
GET /data/v1/projects/{project_id}/items/{item_id}
```

#### Step 5: Handle errors individually

### What's the process for converting Autodesk file formats?

#### Step 1: Upload source file to OSS
```http
POST /oss/v2/buckets/{bucketKey}/objects/{objectName}
```

#### Step 2: Get design URN (base64 encoded)

#### Step 3: Submit translation job
```http
POST /modelderivative/v2/designdata/job
```

#### Step 4: Specify output format
- SVF for viewer
- DWG, PDF, etc.

#### Step 5: Monitor job status until completion

### How do I manage company information in ACC projects?

#### Step 1: Get companies list
```http
GET /construction/admin/v1/accounts/{accountId}/companies
```

#### Step 2: Manage company access
- Add to project
- Set permissions

#### Step 3: Update company info
- Company details
- Contact information

#### Step 4: Monitor company activity
- Track user access
- Review permissions

#### Step 5: Handle pagination for large lists

### How do I handle file relationships in ACC?

#### Step 1: Get item relationships
```http
GET /data/v1/projects/{project_id}/items/{item_id}/relationships/refs
```

#### Step 2: Create relationships
- Link related files
- Set relationship type

#### Step 3: Handle custom refs
- xrefs
- Dependencies

#### Step 4: Monitor relationship status
- Check validity
- Update as needed

#### Step 5: Clean up orphaned relationships

## SDK and Development Issues

### APS SDK for .Net states that requires .Net 8, but Authentication requires .Net 9

Current workaround:
```xml
<TargetFramework>net8.0</TargetFramework>
<TreatWarningsAsErrors>false</TreatWarningsAsErrors>
```

### The .Net API equivalent for assigning coordinate system

```csharp
public async Task AssignCoordinateSystem(string urn, CoordinateSystem coords)
{
  var endpoint = $"/modelderivative/v2/designdata/{urn}/metadata";
  
  var payload = new {
    coordinateSystem = new {
      type = coords.Type,
      origin = new[] { coords.Origin.X, coords.Origin.Y, coords.Origin.Z },
      xAxis = new[] { coords.XAxis.X, coords.XAxis.Y, coords.XAxis.Z },
      yAxis = new[] { coords.YAxis.X, coords.YAxis.Y, coords.YAxis.Z }
    }
  };
  
  await _client.PostAsync(endpoint, payload);
}
```

### Error detection in Revit 2024

#### Implement comprehensive error handling:
```http
GET /data/v1/projects/{project_id}/items/{item_id}/health
```
```json
{
  "status": {
    "overall": "healthy|warning|error",
    "details": {
      "modelIntegrity": "ok|corrupted",
      "elementCount": 1234,
      "warnings": [{
        "code": "REVIT_2024_001",
        "severity": "warning",
        "message": "Detailed message",
        "affectedElements": ["element_ids"]
      }]
    }
  }
}
```

### Autodesk Revit | Extensible Storage

#### Step 1: Define schema
```csharp
public class ExtensibleStorageSchema
{
  public static Schema GetSchema()
  {
    var schemaBuilder = new SchemaBuilder(new Guid("your-guid"));
    schemaBuilder.SetSchemaName("YourSchema");
    schemaBuilder.AddSimpleField("FieldName", typeof(string));
    return schemaBuilder.Finish();
  }
}
```

#### Step 2: Access via API
```http
GET /data/v1/projects/{project_id}/items/{item_id}/storage
```
```json
{
  "schema": "schema_guid",
  "fields": ["field1", "field2"],
  "format": "json"
}
```

### How to avoid "DRIVER OVERRAN STACK BUFFER" in AutoCAD 2025 add-in development

#### Step 1: Implement safe buffer handling
```csharp
public class SafeBufferHandler 
{
  private const int MAX_BUFFER_SIZE = 8192;

  public void ProcessBuffer(byte[] buffer) 
  {
    // Validate buffer size
    if (buffer.Length > MAX_BUFFER_SIZE)
      throw new ArgumentException("Buffer too large");

    // Use safe copy
    byte[] safeCopy = new byte[buffer.Length];
    Buffer.BlockCopy(buffer, 0, safeCopy, 0, buffer.Length);
    
    // Process in chunks
    const int chunkSize = 1024;
    for (int i = 0; i < safeCopy.Length; i += chunkSize) 
    {
      int size = Math.Min(chunkSize, safeCopy.Length - i);
      ProcessChunk(safeCopy, i, size);
    }
  }
}
```

## Custom Attributes and Metadata

### Question regarding the Custom Attributes / upload a file to ACC files with custom attributes

#### Step 1: Creating custom attributes
```http
POST /data/v1/projects/:project_id/custom-attributes
```
```json
{
  "name": "attributeName",
  "displayName": "Attribute Display Name",
  "dataType": "text",
  "category": "Properties",
  "value": "attributeValue"
}
```

#### Step 2: Uploading file with custom attributes
```javascript
// First upload the file
const uploadResponse = await fetch('/data/v1/projects/:project_id/storage', {
  method: 'POST',
  body: formData
});

// Then set custom attributes
const setAttributesResponse = await fetch('/data/v1/projects/:project_id/items/:item_id/custom-attributes', {
  method: 'PATCH',
  body: JSON.stringify({
    attributes: [{
      name: "customAttribute",
      value: "attributeValue"
    }]
  })
});
```

### Regarding Folder 'Notes' and File Custom Attributes

Proposed enhanced attributes API:
```http
POST /data/v1/projects/{project_id}/items/{item_id}/attributes
```
```json
{
  "notes": {
    "text": "Note content",
    "visibility": "private|public",
    "mentions": ["userId1", "userId2"]
  },
  "custom_attributes": {
    "attribute1": {
      "value": "value1",
      "type": "string|number|date",
      "metadata": {
        "searchable": true,
        "indexed": true
      }
    }
  }
}
```

## Asset and Photo Management

### ACC Assets APIs / ACC Photos Write API

#### Assets management
```http
POST /construction/assets/v1/projects/{project_id}/assets
```
```json
{
  "asset": {
    "name": "Asset Name",
    "category": "Equipment",
    "status": "Active",
    "location": {
      "coordinates": [x, y, z],
      "level": "Level 1"
    }
  }
}
```

#### Photos management
```http
POST /construction/photos/v1/projects/{project_id}/photos
```
```json
{
  "photo": {
    "file": "base64_encoded_image",
    "metadata": {
      "location": {
        "lat": 123.456,
        "long": 789.012
      },
      "timestamp": "2024-03-21T14:30:00Z",
      "tags": ["progress", "safety"]
    }
  }
}
```

## Workflow Automation

### Auto Approval of Workflows / Possibility of starting Approval workflows through the API

Proposed workflow automation endpoints:
```http
POST /construction/workflows/v1/projects/{project_id}/workflows
```
```json
{
  "type": "approval",
  "template_id": "template_guid",
  "auto_approve": {
    "enabled": true,
    "conditions": {
      "user_roles": ["project_admin", "project_engineer"],
      "document_types": ["drawings", "submittals"],
      "custom_rules": []
    }
  }
}
```

## Best Practices Summary

### Version Management
- Always check file compatibility
- Implement proper version control
- Handle format conversions carefully

### Performance Optimization
- Use appropriate level of detail
- Implement progressive loading
- Cache frequently accessed data

### Security
- Implement proper authentication
- Handle permissions correctly
- Validate all inputs

### Error Handling
- Provide detailed error messages
- Implement retry mechanisms
- Log all critical operations

### Development Guidelines
- Follow APS best practices
- Maintain backward compatibility
- Document all integrations
- Handle localization properly
- Implement proper logging

## Rate Limits and Quotas

### Standard Rate Limits
- Authentication: 500 calls/minute
- Data Management: Varies by endpoint
- Model Derivative: Varies by operation
- Webhooks: 100 registrations per app

### Error Handling Best Practices
```javascript
async function makeAPICall(endpoint, options = {}) {
  const maxRetries = 3;
  let attempt = 0;
  
  while (attempt < maxRetries) {
    try {
      const response = await fetch(endpoint, options);
      
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        attempt++;
        continue;
      }
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      attempt++;
      if (attempt >= maxRetries) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}
```

## Common Integration Patterns

### Authentication Flow
1. Register application in APS Developer Portal
2. Implement OAuth 2.0 flow (2-legged or 3-legged)
3. Handle token refresh
4. Store tokens securely

### File Upload Pattern
1. Create storage location
2. Upload file to signed URL
3. Create item and version
4. Monitor processing status

### Webhook Pattern
1. Register webhook endpoint
2. Implement callback handler
3. Validate webhook signatures
4. Handle idempotency

### Error Recovery Pattern
1. Implement exponential backoff
2. Log errors with context
3. Provide fallback mechanisms
4. Monitor error rates

This knowledge base covers the most common questions, issues, and solutions for APS (Autodesk Platform Services) development. Use it as a reference for troubleshooting and implementing best practices in your APS integrations.