# Demo: Deploying the Vulnerability agent on Openshell

## 1. Install Openshell

```shell
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
```

The script picks a package for your platform and starts the gateway. Confirm the CLI can reach it:

```shell
openshell status
```

## 2. Configure what the agent has access to


First, we configure a provider profile. A provider profile defines the credentials, service endpoints, and executable paths an agent may use. Let's create on for our localhost inference server. 

Save this as `sio2-local.yml`:

```yaml
id: sio2-local
display_name: sio2 local model
description: OpenAI-compatible endpoint for the sio2 Python client
category: inference
inference_capable: true

credentials:
    - name: api_key
      description: Optional model server token
      env_vars: [LOCAL_MODEL_KEY]
      required: false
      auth_style: bearer
      header_name: authorization

discovery:
    credentials: [api_key]

endpoints:
    - host: host.lima.internal   # Docker resolves host.lima.internal to 192.168.5.2.
      port: 8080
      protocol: rest
      access: read-write
      enforcement: enforce
      allowed_ips: ["192.168.5.2/32"]

binaries:
    - /usr/local/bin/python3.12   # Python in the sio2 image resolves to /usr/local/bin/python3.12
```

Next, we import the provider profile into Openshell:

```shell
openshell profile import -f ./deploy/providers/sio2-local.yml
```

Then we create the provider using the imported profile:

```shell
openshell provider create --name sio2-local --type sio2-local
```

## 3. Prepare the Agent

### 3.1 Build the Docker Image for the Agent

Let's contaierize `sio2` with docker and then we can have the sandbox take it up.

```shell
docker build -f Dockerfile.openshell -t sio2-openshell:local .
```

> Note: Openshell does not build a Docker image for you. You need to build it manually as shown above. Then you can use the built image with the sandbox.

If you take a closer look at the Dockerfile, you will see that the built image contains the following:

 - `sio2` and its Python dependencies.
 - Bandit and the supporting system tools.
 - A non-root agent account.
 - Directories for runtime inputs and generated results.

The target application and scan configuration remain outside the image. We will supply them when we create the sandbox.

Check to make sure that the Docker image was built successfully by running:

```
┌─────────────────────┬────────────────────────────────────────────────┐
│ Container path      │ Purpose                                        │
├─────────────────────┼────────────────────────────────────────────────┤
│ /opt/sio2           │ Agent code, dependencies, prompts, and schemas │
├─────────────────────┼────────────────────────────────────────────────┤
│ /inputs/target      │ Target source, supplied at runtime             │
├─────────────────────┼────────────────────────────────────────────────┤
│ /inputs/config.toml │ Scan configuration, supplied at runtime        │
├─────────────────────┼────────────────────────────────────────────────┤
│ /sandbox/runs       │ Generated reports, traces, and patches         │
├─────────────────────┼────────────────────────────────────────────────┤
│ /tmp                │ Disposable analysis workspaces                 │
└─────────────────────┴────────────────────────────────────────────────┘
```
Check that the image can execute sio2:

```shell
docker run --rm --network=none \
    sio2-openshell:local \
    sio2 --help
```
The command should print sio2’s command-line options. This checks the image only. It does not test OpenShell policy enforcement.

### 3.2 Prepare an Approved Input Volume

OpenShell must authorize external volumes before attaching them to a sandbox. We will use a Docker-managed volume.

#### 3.2.1 Allow approved volume attachments

For this Homebrew installation, edit the gateway configuration:

```text
   ~/.config/openshell/gateway.toml
```

Merge these settings into the file. Preserve the existing socket_path, grpc_endpoint, and other settings. Do not duplicate an existing TOML table.

```toml
   [openshell.drivers.docker]
   allow_driver_config = true
   enable_bind_mounts = false

   [openshell.drivers.docker.resource_admission]
   enabled = true

   [openshell.drivers.docker.resource_admission.required_labels]
   "openshell.ai/sandbox-attachable" = "true"
   "openshell.ai/sandbox-attachable-workspace" = "${workspace}" # Don't change this placeholder (it is openshell's workspace variable)
```

These settings allow per-sandbox driver configuration.

Validate the configuration:

```shell
   openshell-gateway config preflight \
     --path "$HOME/.config/openshell/gateway.toml"
```

If validation succeeds, restart the gateway:

```shell
   brew services restart openshell
   openshell status
```

#### 3.2.2 Create the approved volume

These commands use the OpenShell workspace named default:

```shell
   docker volume create \
     --label openshell.ai/sandbox-attachable=true \
     --label openshell.ai/sandbox-attachable-workspace=default \
     sio2-inputs
```

Check the approval labels:

```shell
   docker volume inspect sio2-inputs \
     --format '{{json .Labels}}'
```

The labels authorize attachment to sandboxes in that workspace. They do not make the volume read-only. We will specify read-only access when creating the sandbox.

> Only the trusted operator should control Docker access and approval labels. The agent receives neither Docker access nor its socket.


### 3.3 Populate the Input Volume

We will copy the target source and scan configuration into `sio2-inputs`.

Essentially, a temporary helper container populates the volume before OpenShell attaches it read-only.

#### 3.3.1 Prepare the scan configuration

For the OWASP example, copy the existing scan configuration:

```shell
cp configs/owasp-full.toml configs/local-owasp.toml
```
Be sure to replace its entire `[model]` block with:

```toml
[model]
provider = "openai-compatible"
name = "YOUR_MODEL_ID"
host = "http://host.lima.internal:8080"
api_key_var = "LOCAL_MODEL_KEY"
temperature = 0.0
```

Replace `YOUR_MODEL_ID` with the identifier your server accepts (sol, luna, whatever else), but keep the scan, budget, and agent sections unchanged.

`LOCAL_MODEL_URL` overrides `model.host` for either supported client. `api_key_var` names the credential environment variable, not its secret value.

Under OpenShell, that name must match an alias in the provider profile's `env_vars` list. The proxy substitutes the real credential only for an authorized endpoint.

> Do not include API keys in this file. The OpenShell provider handles credentials.

#### 3.3.2 Copy the target source

Use the empty volume created in section 3.2!

> Note: Do not reuse a populated volume for a different snapshot, because old files could remain.

```shell
set -o pipefail

# Root of the target application checkout. For this example, the OWASP clone from the main README.
TARGET_DIR="$PWD/targets/owasp-benchmark-python"

# COPYFILE_DISABLE=1 keeps macOS tar from archiving Apple extended attributes.
COPYFILE_DISABLE=1 tar \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='.env' \
  --exclude='.env.*' \
  -C "$TARGET_DIR" -cf - . |
docker run --rm -i \
  --network=none \
  --user 0:0 \
  --mount type=volume,src=sio2-inputs,dst=/inputs \
  --entrypoint /bin/sh \
  sio2-openshell:local \
  -c 'mkdir -p /inputs/target &&
      tar --no-same-owner -xf - -C /inputs/target &&
      chmod -R a+rX /inputs/target'
```

This transfers an archive through standard input. It does not need a host-directory bind mount.

Keep `.git` in the snapshot so sio2 can identify the target commit. The agent's disposable analysis workspace excludes it.

#### 3.3.3 Copy the scan configuration

```shell
# The scan configuration created in section 3.3.1
CONFIG_FILE="$PWD/configs/local-owasp.toml"

docker run --rm -i \
  --network=none \
  --user 0:0 \
  --mount type=volume,src=sio2-inputs,dst=/inputs \
  --entrypoint /bin/sh \
  sio2-openshell:local \
  -c 'cat > /inputs/config.toml &&
      chmod 644 /inputs/config.toml' \
  < "$CONFIG_FILE"
```

The resulting volume contains:

```text
/inputs/
├── target/
│   └── target application source
└── config.toml
```

> These helper containers run as root only to populate the Docker volume. The sio2 agent still runs as non-root inside OpenShell.

### 3.4 Create Sandbox Policy File

By default, the sandbox comes with an uber-restrictive policy that limits filesystem and network access. You can customize this policy by creating a new sandbox policy file.

Let's create a policy file in `deploy/policy/sio2.yaml`, to grant the necessary permissions for running `sio2`.

> ** What is the difference between a provider profile and a sandbox policy?**
> 
> The two files serve different purposes:
> 
> - Provider profile: Authorizes the model endpoint and handles credentials.
> - Sandbox policy: Controls filesystem access and any additional network access.

```yaml
   version: 1

   filesystem_policy:
     include_workdir: false

     read_only:
       - /bin
       - /usr
       - /lib
       - /etc
       - /proc
       - /dev/urandom
       - /var/log
       - /opt/sio2
       - /inputs
       - /sandbox

     read_write:
       - /sandbox/runs
       - /tmp
       - /dev/null

   landlock:
     compatibility: best_effort

   network_policies: {}
```

### Why these permissions?

| Path | Permission | Reason |
| --- | --- | --- |
| /opt/sio2 | Read-only | Agent code, dependencies, prompts, and schemas |
| /inputs | Read-only | Target repository and scan configuration |
| /sandbox/runs | Read-write | Reports, traces, and proposed patches |
| /tmp | Read-write | Disposable source copies and repair candidates |
| System paths | Mostly read-only | Python, shared libraries, certificates, and system configuration |

`include_workdir`: false prevents an automatic write grant for the entire /sandbox working directory.

`network_policies: {}` does not cancel provider permissions. The attached provider contributes the model-access rule to the effective policy. Other outbound access remains
denied unless another policy source grants it.

`best_effort` matches the upstream default. It does not guarantee enforcement of every optional kernel feature.


## 4. Create a Sandbox

Let's create the sandbox using the built Docker image.

```shell
openshell sandbox create \
    --workspace default \
    --name sio2-sandbox \
    --from sio2-openshell:local \
    --policy ./deploy/policy/sio2.yaml \
    --provider sio2-local \
    --driver-config-json '{
    "docker": {
        "mounts": [
        {
            "type": "volume",
            "source": "sio2-inputs",
            "target": "/inputs",
            "read_only": true
        }
        ]
    }
    }' \
    --detach \
    -- /usr/bin/sleep infinity
```

Understanding the sandbox creation options:
```text
 ┌──────────────────────┬────────────────────────────────────────────────────┐
 │ Option               │ Purpose                                            │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --workspace default  │ Matches the workspace approval label on the volume │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --from               │ Selects the built agent image                      │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --policy             │ Supplies the sandbox policy from the host          │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --provider           │ Attaches the configured model provider             │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --driver-config-json │ Requests the read-only volume attachment           │
 ├──────────────────────┼────────────────────────────────────────────────────┤
 │ --detach             │ Returns control to the host terminal               │
 └──────────────────────┴────────────────────────────────────────────────────┘
```

Inspect the base policy and the effective policy:

```shell
   openshell policy get sio2-sandbox --workspace default --base
   openshell policy get sio2-sandbox --workspace default --full
```

The effective policy should include the model-access rule contributed by sio2-local. Check for unexpected grants or a gateway-global policy override.

```shell
openshell sandbox exec sio2-sandbox \
    --workspace default \
    --no-login-shell \
    --env LOCAL_MODEL_URL=http://host.lima.internal:8080 \
    -- /opt/sio2/.venv/bin/sio2 \
      --input /inputs/target \
      --config /inputs/config.toml \
      --output /sandbox/runs/scan-001
```

## What happens when point to a different model provider

Let's say I want to go from https://host.lima.internal:8080 to a different model provider, for example, https://api.openai.com.

Let's look at what the policy allows:

```bash
openshell policy get sio2-sandbox --workspace default --full
```

Notice how the allowed local endpoint is `host.lima.internal:8080` and no rule permits api.openai.com. This means that if you try to point to the OpenAI API, the sandbox will block the network request according to the effective policy.