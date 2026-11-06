# OpenShell provider configuration for sio2

## Findings

sio2 needs one custom inference provider profile for its model endpoint. It does not need every profile in the upstream catalog.

Profiles define allowed endpoints, client binaries, and credential handling. The Python client still chooses the URL, model, and request format. [1][2]

The upstream OpenAI profile grants access to `api.openai.com` for curl binaries. It does not grant access to an arbitrary OpenAI-compatible server. [3]

The local CLI reports OpenShell 0.1.7. A candidate profile passed `openshell profile lint` without import or provider creation.

## Separate settings

| Setting | Responsibility |
|---|---|
| sio2 TOML `[model]` | Choose the request destination and model |
| Provider profile | Authorize the host, port, and Python executable |
| Provider instance | Attach profile configuration and optional credentials to a sandbox |

`inference_capable: true` describes the profile. It does not redirect requests or change the request format. [2]

sio2 appends `/v1/chat/completions` to its base URL. A server advertised as `http://localhost:8080/v1` therefore uses `http://localhost:8080` in sio2. [4]

## Local Colima endpoint

Inside a container, `localhost` names the container, not the host server. On this machine, Docker resolves `host.lima.internal` to `192.168.5.2`.

The image's Python executable resolves to `/usr/local/bin/python3.12`. Use that executable instead of a broad wildcard.

OpenShell blocks private destinations by default. The endpoint needs a narrow `allowed_ips` grant for the resolved host address. Loopback and link-local destinations remain blocked. [5]

Save this candidate as `sio2-local.yaml`:

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
  - host: host.lima.internal
    port: 8080
    protocol: rest
    access: read-write
    enforcement: enforce
    allowed_ips: ["192.168.5.2/32"]
binaries:
  - /usr/local/bin/python3.12
```

The address is specific to this machine. Verify DNS from the deployed environment before using that grant elsewhere.

Profiles with only optional credentials can create providers without static tokens. [6]

```bash
openshell profile lint -f sio2-local.yaml
openshell profile import -f sio2-local.yaml
openshell provider create --name sio2-local --type sio2-local
```

If authentication is necessary, set `LOCAL_MODEL_KEY` in the caller's environment. Use `--credential LOCAL_MODEL_KEY` during provider creation instead of a literal secret.

Attach the provider when creating the sandbox:

```bash
openshell sandbox create \
  --name sio2-local-demo \
  --from sio2-openshell:local \
  --provider sio2-local \
  -- sio2 --help
```

This command checks launch configuration only. An actual scan also needs source, scan configuration, output access, and the corresponding filesystem policy.

Lima maps `host.lima.internal` to the host loopback through its virtual network. This can reach services bound only to the host's `127.0.0.1`. [7]

Lima's `networkOpts.hostLoopback: false` disables that access. OpenShell must still authorize the private destination separately.

The destination port stays unchanged. `host.lima.internal:8080` reaches host port `8080`, not host port `808`.

Inspect the provider-composed policy with:

```bash
openshell policy get sio2-local-demo --full
```

## A different server URL

For a public endpoint such as `https://models.example.com/v1`, change the client and its authorization:

- Set sio2's base URL to `https://models.example.com`.
- Create a distinct profile with the new host and port `443`.
- Remove the Colima-specific private-IP grant for a public endpoint.
- Keep the executable grant narrow and attach the matching provider.
- Configure the new server's model ID and credentials if necessary.

A TOML endpoint change alone does not authorize a new destination. A profile change alone does not redirect the Python client. [1][2]

The official inference example also supports custom-profile updates. Export the profile, preserve `resource_version`, edit it, lint it, and submit `profile update`. [2]

Repository and package-registry profiles are unnecessary when source and dependencies arrive before the agent starts.

## Verification limits

The profile passed local CLI validation. No profile was imported, no provider was created, and no sandbox or live model request was launched.

Docker established the image executable path and the local host DNS address. Those checks do not establish connectivity from an OpenShell sandbox.

## Sources

1. [Official profile examples and adaptation rules](https://github.com/NVIDIA/OpenShell/blob/main/providers/README.md)
2. [Official native-client inference example](https://github.com/NVIDIA/OpenShell/blob/main/examples/local-inference/README.md)
3. [Official OpenAI profile](https://github.com/NVIDIA/OpenShell/blob/main/providers/openai.yaml)
4. Local implementation: `src/sio2/llm.py`, `OpenAIChat.chat`.
5. [Official private-IP routing example](https://github.com/NVIDIA/OpenShell/blob/main/examples/private-ip-routing/README.md)
6. [Official profile schema and optional-credential handling](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-providers/src/profiles.rs)
7. [Lima host-loopback networking](https://lima-vm.io/docs/config/network/user/)

Commands also match the installed 0.1.7 help for `profile`, `provider create`, `sandbox create`, and `policy get`.
