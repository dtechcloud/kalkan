---
slug: iac-cloud-container
title_en: IaC / cloud / container misconfiguration
title_tr: IaC / bulut / konteyner yapılandırması
cwe: CWE-16, CWE-250, CWE-732
owasp: A05:2021
sources: security-audit-skill, deepsec, open-code-review
---

## Summary

Infrastructure as code (IaC), cloud policies, container images and orchestration manifests give a workload more identity, network reach or host access than intended. A finding needs a lower-trust actor who can use that excess. Source files show intent, not the live state. Separate defects that the repository proves from facts that only the deployment shows.

## What it is

- **IAM over-permission.** `Action: "*"` together with `Resource: "*"`, `iam:PassRole` with compute creation, wildcard principals in bucket, KMS, SNS or SQS policies. Azure `Owner` or `Contributor` at subscription scope. GCP bindings for `allUsers` or `allAuthenticatedUsers`.
- **Federated trust gaps.** Role trust that accepts any account, repository or branch: no `ExternalId`, or an OpenID Connect (OIDC) `sub` condition with a wildcard such as `repo:org/*`.
- **Network exposure.** `0.0.0.0/0` or `::/0` on SSH, RDP, database or admin ports. Public Kubernetes API endpoints without CIDR limits, `publicly_accessible = true` databases, admin paths on public load balancers.
- **Public storage.** Public ACLs, a disabled S3 public access block, public blob containers, broad presigned or SAS URLs.
- **Host access from containers (CWE-250).** `privileged: true`, `hostPID`, `hostNetwork`, `hostPath` mounts of `/` or `/var/run/docker.sock`, added capabilities such as `SYS_ADMIN`.
- **Kubernetes RBAC.** Wildcards, cluster-wide `secrets` read, `pods/exec`, `escalate`, `bind`, `impersonate` or `create pods` for low-trust subjects, bindings to `system:authenticated`, broad service accounts that pods mount by default.
- **Secret delivery (CWE-732).** A committed `terraform.tfstate`, Kubernetes `Secret` manifests with real values, secrets that other workloads read through RBAC or shared volumes, secrets in image `ENV` layers.
- **Open serverless entry points.** Function URLs with `NONE` auth, API Gateway methods with `authorization = "NONE"`, `--allow-unauthenticated` Cloud Functions, when the function does non-public work.
- **Bypassed proxy.** A backend that trusts identity headers is reachable without the auth proxy.
- **Hardening gaps.** A root user in the final image stage, no encryption at rest, the metadata service v1 (IMDSv1), no `readOnlyRootFilesystem`. These are `low` unless an attack path uses them.

## What it is not

- Mutable image tags, unpinned modules, `curl | sh` in a Dockerfile, CI workflows → `supply-chain-cicd`.
- A literal secret value in IaC, Helm values or a manifest → `hardcoded-secrets`.
- App settings such as debug mode, security headers or cookie flags → `security-misconfig`. CORS → `cors`.
- Vulnerable packages → `vulnerable-dependency`. kalkan does not scan built images.
- SSRF from app code to the metadata service → `ssrf`. The IMDS setting is context for its severity.
- Missing auth in handler code → `authn`. Tenant filters in data stores → `multi-tenant`.
- Missing CPU or memory limits → `dos-redos` only with a concrete shared-impact path, else hardening.

## Where to look

Find the files that each environment applies: root modules, overlays, values files, compose files. List exposed ports, workload identities, mounted secrets and cloud resources. Then follow a lower-trust request or workload into that list.

### Terraform
- `aws_iam_policy_document`, inline `jsonencode` policies, `assume_role_policy`, OIDC roles and their `token.actions.githubusercontent.com:sub` conditions.
- `aws_security_group` and `_rule`, `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block`, `aws_db_instance.publicly_accessible`, `metadata_options.http_tokens`, `aws_lambda_function_url.authorization_type`, EKS public endpoint settings.
- `google_*_iam_*` members, `azurerm_role_assignment` scopes, `azurerm_network_security_rule`, storage account public access.
- `.tfvars` files, committed state files, credential variables without `sensitive = true`, per-environment overlays.

### Kubernetes and Helm
- Pod specs in Deployments, StatefulSets, DaemonSets, Jobs and CronJobs: `securityContext`, `hostPath`, host namespaces, `automountServiceAccountToken`, `serviceAccountName`.
- `Role`, `ClusterRole` and their bindings. Services of type `LoadBalancer` or `NodePort`, Ingress rules for admin paths.
- Helm: `values.yaml` defaults and `{{ if .Values... }}` blocks that drop security settings. Render with each environment's values. Kustomize patches that remove `securityContext`.
- `kind: Secret` with `data` or `stringData`. Base64 is not encryption.

### Dockerfile and Compose
- The final stage `USER`, secrets in `ARG` or `ENV`, `COPY . .` without `.dockerignore`.
- Compose: `privileged: true`, a `docker.sock` mount, `network_mode: host`, `pid: host`, `cap_add`. `ports: ["5432:5432"]` binds every host interface, `"127.0.0.1:5432:5432"` only the local one.

### Cloud templates (CloudFormation, Bicep, ARM, Serverless, Pulumi)
- The same checks in `AWS::IAM::*` and `AWS::S3::BucketPolicy` resources, Bicep role assignments and NSG rules, `publicNetworkAccess: 'Enabled'`, credential parameters without `@secure()`, Serverless HTTP events without an authorizer.

## Safe patterns

- Name the actions, scope the resource ARNs, and add conditions (`aws:SourceArn`, `aws:PrincipalOrgID`, `sts:ExternalId`). Match the OIDC `sub` exactly to the repository and the branch or environment.
- Keep resources private by default: public access block on, private subnets, security groups that reference other groups, admin access through a VPN.
- Follow the Kubernetes "restricted" Pod Security profile: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`, no `hostPath`. Enforce it with Pod Security Admission labels.
- Use namespaced Roles with named verbs and resources. Set `automountServiceAccountToken: false` when the pod does not call the API.
- Deliver secrets through a secret manager, SOPS or sealed secrets. Keep state in an encrypted remote backend.
- Require IMDSv2 (`http_tokens = "required"`). A hop limit of 1 keeps containers away from it.
- Run images as a non-root `USER`, and use BuildKit secret mounts at build time.

## Weak mitigations

- Policies that trust labels, annotations or namespaces that a lower-trust user can set.
- A secure base chart that an overlay turns off, or a restricted security group while a load balancer also exposes the service.
- `sensitive = true` on a Terraform variable. It hides the output, but the state still holds the value.
- A NetworkPolicy without proof that the CNI enforces it.

## Verification checklist

- **attacker_control:** Name the lower-trust actor: an internet client, a workload in another namespace or tenant, a fork CI job, a compromised app container. Quote the resource line that exposes the identity, port, path or capability. Show that an active environment applies the file.
- **privilege_boundary:** Name the gained operation: read bucket objects, assume a role, exec into pods, reach the node through `hostPath` or `privileged`, connect to the database from the internet. Quote the permissions, or the exposed port and what listens on it.
- **unmitigated:** Quote the missing condition or restriction. Check overlays, defaults and other module files for a compensating setting. If an account-level control (SCP, organization policy, admission controller, cloud firewall) can stop it, answer `unknown`.
- A container breakout claim needs an attacker inside the container first: code execution in the app, or an untrusted workload. `privileged` without such a path is hardening.
- IAM wildcards in both `Action` and `Resource` are the dangerous shape. One wildcard alone can be intentional.
- Severity guide: a public bucket with sensitive data, an internet-facing admin or database port, or cluster-admin for a workload with untrusted input, high. Hardening gaps, low.

## Examples

### Terraform
```hcl
# Vulnerable: every repository of the organization, on any branch, can assume the deploy role
condition {
  test     = "StringLike"
  variable = "token.actions.githubusercontent.com:sub"
  values   = ["repo:example-org/*"]
}

# Secure: one repository and one protected environment
condition {
  test     = "StringEquals"
  variable = "token.actions.githubusercontent.com:sub"
  values   = ["repo:example-org/deploy-app:environment:production"]
}
```

```hcl
# Vulnerable: the database port is open to the internet
resource "aws_security_group_rule" "db" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}

# Secure: instead of cidr_blocks, allow only the app's security group
  source_security_group_id = aws_security_group.app.id
```

### Kubernetes and Helm
```yaml
# Vulnerable: a privileged pod spec with the host's Docker socket
containers:
  - name: web
    securityContext: { privileged: true }
    volumeMounts: [{ name: docker, mountPath: /var/run/docker.sock }]
volumes:
  - { name: docker, hostPath: { path: /var/run/docker.sock } }
---
# Secure: restricted profile, no host mounts, no API token
automountServiceAccountToken: false
securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }
containers:
  - name: web
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
```

## Dynamic test hints

- Never run `terraform apply`, use real cloud credentials, or probe real IP addresses, buckets or endpoints.
- Render locally: `docker compose config` for compose files, `helm template` or `kustomize build` with each values file when the tools exist.
- Only when the run allows it, use a local kind cluster with dummy workloads, and list rights with `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>`.
- Compare with the Checkov and Trivy candidates that kalkan already collected for the same file and line.

## False positive traps

- No environment applies the file: examples, test fixtures, unused modules, `count = 0` or `enabled = false`.
- The exposure is the purpose: a static website bucket, a public load balancer on 80 or 443.
- Read-only actions that need `Resource: "*"` (for example `ec2:Describe*`), or a wildcard action on one named resource.
- A sibling resource sets the encryption, or the provider default applies. S3 encrypts new objects by default since January 2023.
- Node agents (CNI, CSI, monitoring) run privileged by design. Report only an untrusted input path into them.
- Local development compose files. `Secret` manifests with placeholders or SOPS-encrypted values.
- Scanner rules that only express a policy preference: no resource limits, no liveness probe.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/CLOUD-AND-DEPLOYMENT.md` (MIT, Cloudflare): workload identity, ingress, container, configuration, storage and event classes, validation rules.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/tf-iam-wildcard.ts`, `tf-public-ingress.ts`, `tf-encryption-missing.ts`, `tf-secret-in-data.ts`, `tf-iac-surface.ts`, `k8s-secret-reference.ts`, `dockerfile-run-as-root.ts`, `gcp-cloud-function.ts`, `packages/processor/src/prompt/slug-notes.ts`, `highlights.ts` (Apache-2.0, Vercel): risky resource shapes, serverless notes.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/terraform.md`, `bicep.md` (Apache-2.0, alibaba/open-code-review contributors): permissive access, secrets, state files, insecure defaults.
- Pod Security and RBAC details, compose port binding, IMDSv2, the OIDC `sub` format and the S3 encryption default come from general knowledge.
