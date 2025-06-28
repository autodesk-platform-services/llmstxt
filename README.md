# 🚀 Getting Started with APS's LLMS.TXT and Cursor IDE

Welcome! This is the repo for the APS `llms.txt` file(s).  
It is also a short guide for developers, citizen developers, and domain experts who want to **vibe code** Autodesk Platform Services (APS) APIs using the AI-powered [Cursor IDE](https://www.cursor.so/). With just a few steps, you’ll be setup to generate and test real API code using plain-English prompts—powered by APS + CursorAI + `llms.txt`.

## 🧠 What’s “Vibe Coding”?

Vibe coding is the new way of working in AI-assisted IDEs. You don’t start with a blank file. You **talk to your editor**, describe what you want, and let it scaffold, correct, and enhance your code. It's part code generation, part pair programming, and 100% about speed, flow, and creativity.

> 💡 New to Cursor or vibe coding?
> Don’t worry if this feels unfamiliar—part of the magic is letting the AI help you work through it. Think of Cursor as your coding partner. Start by describing what you want, and let it guide you. You’ll be surprised how far you can get with just a good prompt.
> .


---

## 🎥 3-Step Intro: Watch & Learn

> Each step includes a short video (30 seconds) to help you follow along.

### ▶️ Step 1: Add LLMS.TXT to CursorAI
- Open Cursor IDE
- Go to 'Settings' -> `Indexing & Docs` and click `Add Doc`
- Type in `https://aps.autodesk.com/llms-full.txt` and add the name `Autodesk APS APIs` and click `Confirm`

<video src="https://github.com/user-attachments/assets/0bbb7b67-f305-4619-b898-2263bb5b28bb"></video>



---

### ▶️ Step 2: Test It Out
- Point Cursor AI to our `Autodesk APS APIs` using the @Docs feature
- Select 'Ask'
- Now try asking:  
  _“Can you see the APS docs?  what is SSA ?”_

<video src="https://github.com/user-attachments/assets/321bb801-b8b6-466d-a028-8d6f5be38109"></video>

---


### ▶️ Step 3: Build a "List Hubs" Example (Python)
- Use prompt-driven coding to "list all my hubs from a simple command line tool" - using Python.
- Switch to Agent mode.
- Now try asking:
_“create a python script that uses ssa, gets an access token using ssa rest apis and uses an example.env file containing aps key/secret, private key, scope, etc and lists the acc hubs. ignore error checking and no comments.”_

`The end result ?`  I run the command `python3 list_hubs.py` and it shows the hubs my robot (SSA) has access to using 3LO access tokens.

ps.  Here is my `example.env' file I used in the video.  I asked Cursor to use these variable names, instead of the ones it initially suggested:

```
APS_CLIENT_ID=XLA....................................0ep3i
APS_CLIENT_SECRET=RCB...................................................84e
SERVICE_ACCOUNT_ID=VR2........V5
KEY_ID=288........8322d
APS_SCOPE="data:read data:write"
APS_PRIVATE_KEY="--- ....................... 6FsPjyf\n-----END RSA PRIVATE KEY-----"
```

<a href="https://public-blogs.s3.us-west-2.amazonaws.com/step3-get-list-of-hubs.mp4"><img width="1368" alt="Image" src="https://github.com/user-attachments/assets/7012de00-a352-449c-beff-0655521cddef" /></a>

---

### ▶️ Step 4: Vibe Code - View a Revit model in a browser.  (Python)
- Use prompt-driven coding to build a command line tool, that let's you upload and view a Revit model in a browser using APS.  We'll use python to do the file upload, Model Derivative API to convert RVT to SVF2, and use the Viewer SDK inside our custom webpage. Let's call it `upload-and-view.py` example.
- Switch to Agent mode
- Try asking:
`Create a Flask server with minimal code without comments or error checking.  Use APS APIs to provide endpoints /api/token, /api/upload, /api/status/<urn>, /api/list using 2-legged OAuth credentials and APS_BUCKET_KEY stored in a sample.env. Put APS logic in utils.py class (APSClient with methods for token, upload, translate, status, list, ensure_bucket), server code in server.py. Use proper APS signed S3 upload workflow (GET /signeds3upload, PUT S3, then finally POST /signeds3upload as per the docs), translate to SVF2 with base64-encoded URNs.`

`Create viewer.html with MDL lite css component featuring top bar (title, translation status label, model dropdown, upload button) and Autodesk Viewer filling remaining screen space. When the model succeeds in translating, then load the models urn.  Write optimized, minimal code with async/await, without comments or error checking. Final result: complete 3D model upload, translation, and viewing application. Create a readme.md file with complete newbie instructions on signing up for APS, installing python and where to find sample revit models from autodesk`

Three Parts...

Step 1 - Create the Server https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-1-create-server.mp4
<a href="https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-1-create-server.mp4"><img width="1368" alt="Image" src="https://github.com/user-attachments/assets/725677cc-6f62-4c35-b8e7-012490466086" /></a>

Step 2 - Create the Viewer https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-2-create-webpage.mp4
<a href="https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-2-create-webpage.mp4"><img width="1368" alt="Image" src="https://github.com/user-attachments/assets/4089f084-80fc-4ce3-a142-e9ebb11c0c05" /></a>

Step 3 - `Uh-oh`, how to fix the upload bug with vibe-coding https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-3-vibe-fix.mp4
<a href="https://public-blogs.s3.us-west-2.amazonaws.com/sviewer-3-vibe-fix.mp4"><img width="1368" alt="Image" src="https://github.com/user-attachments/assets/725677cc-6f62-4c35-b8e7-012490466086" /></a>


```
Explanation of these three to come
```


---
That's a wrap!
