# OpenShell sandbox policy for sio2

## Purpose

The base policy grants filesystem access for the agent. An attached provider supplies the model endpoint and its credential rules. Keep those responsibilities separate. [1]

## Proposed policy

Save this as `deploy/policy/sio2.yaml`:

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

The system paths follow the upstream default. The application paths match `Dockerfile.openshell`. [1][2]

| Path | Access | Purpose |
|---|---|---|
| `/opt/sio2` | Read-only | Agent, Python environment, schemas, and packaged configuration |
| `/inputs` | Read-only | Runtime target source and scan configuration |
| `/sandbox` | Read-only | Working-directory access without a broad write grant |
| `/sandbox/runs` | Read-write | Reports, traces, patches, and validation artifacts |
| `/tmp` | Read-write | Disposable workspaces and candidate source |

The explicit child grant allows writes under `/sandbox/runs`, not throughout `/sandbox`.

`include_workdir: false` prevents an automatic write grant for the image's `/sandbox` working directory. [1]

`best_effort` matches the upstream compatibility default. It does not establish full enforcement of every optional kernel feature. The protected OpenShell baseline still needs Landlock ABI v3. [1]

The image declares non-root user `agent`, UID 1500. Preserve that identity. [2]

## Attach the policy and provider

The current provider file declares profile ID `sio2-local`. Use the provider instance name from its creation command, not the YAML filename.

```bash
openshell sandbox create \
  --name sio2-demo \
  --from sio2-openshell:local \
  --policy deploy/policy/sio2.yaml \
  --provider sio2-local \
  -- bash
```

This command starts a shell, not a scan. Source and configuration still need approved runtime provisioning.

Policy paths refer to paths inside the sandbox. A policy does not mount host directories or upload files.

An empty base network map denies outbound requests unless an attached provider or another effective-policy source grants them. [1]

Inspect both policy views from another terminal:

```bash
openshell policy get sio2-demo --base
openshell policy get sio2-demo --full
```

The full view includes provider-composed rules. An active gateway-global policy can take precedence, so inspect the actual selected policy. [1]

Filesystem grants do not replace Unix ownership or mount permissions. Keep target source read-only at the provisioning layer as well.

## Verification limits

The installed OpenShell 0.1.7 CLI has no `policy lint` command. `profile lint` validates provider profiles, not sandbox policies.

A local parser check can verify YAML syntax. Sandbox creation and runtime checks must verify semantic acceptance and actual enforcement.

This proposal grants neither package-registry access nor host Docker socket access. The existing Docker-based behavioral test backend remains unavailable inside this image.

No sandbox was created for this investigation.

## Sources

1. [Official default policy, filesystem enrichment, and policy inspection](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/default-policy.mdx)
2. Local image definition: `Dockerfile.openshell`.
3. [Official complete policy example](https://github.com/NVIDIA/OpenShell/blob/main/examples/sandbox-policy-quickstart/policy.yaml)
4. [Official policy schema](https://github.com/NVIDIA/OpenShell/blob/main/proto/sandbox.proto)
5. Installed CLI help: `openshell policy --help` and `openshell sandbox create --help`.
