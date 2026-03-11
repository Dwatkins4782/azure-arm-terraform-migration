# Interview Prep: Terraform Application Consultant — Azure ARM Conversion

## Role Summary
- Rate: $70-75/hr W2
- Type: Contract (one-time conversion + ongoing support)
- Location: Remote, 30-40 hrs/week
- Schedule: Flexible hours for India team collaboration
- Industry: Enterprise healthcare (HIPAA)

---

## Section 1: ARM-to-Terraform Conversion Questions

### Q: "Walk us through your approach to converting an ARM template to Terraform."

**Answer Framework:**
1. **Inventory** — Catalog all resources in the ARM template, map parameters, variables, dependencies
2. **Export** — Use `aztfexport` to generate a baseline from live resources
3. **Refactor** — Restructure into modules, extract variables, replace hardcoded values
4. **Import** — Use Terraform 1.5+ import blocks to adopt existing resources into state
5. **Validate** — Run `terraform plan` to confirm zero-diff (functional equivalency)
6. **Test** — Compliance scanning (Checkov, OPA), functional testing

**Point to your project:** "I built a complete migration framework that demonstrates this end-to-end. It includes side-by-side ARM templates and Terraform modules with inline conversion comments explaining every ARM-to-Terraform pattern."

### Q: "What are the key differences between ARM and Terraform?"

| ARM | Terraform |
|-----|-----------|
| JSON (verbose, hard to read) | HCL (human-readable, concise) |
| No state file — Azure is the source of truth | State file tracks desired vs actual |
| `dependsOn` explicit | Dependencies implicit from references |
| `[concat()]`, `[parameters()]` functions | String interpolation `"${var.name}"` |
| `secureString` type | `sensitive = true` on variables |
| `uniqueString()` deterministic hash | `random_string` resource (stored in state) |
| Nested templates for reuse | Modules with clear input/output contracts |
| Single deployment scope (resource group/subscription) | Multi-provider, multi-scope |
| What-if preview (limited) | `terraform plan` (comprehensive) |

### Q: "Describe your experience with aztfexport."

**Answer:**
"I use `aztfexport` as the starting point, never the end product. The raw output is flat — no modules, hardcoded values, missing properties. My workflow is:

1. Run `aztfexport resource-group <name>` to generate baseline
2. Review the mapping file to understand resource coverage
3. Identify resources that didn't export cleanly (some types have partial support)
4. Refactor into a modular structure with proper variables and outputs
5. Compare against the original ARM template to catch anything aztfexport missed
6. Run `terraform plan` to verify zero drift

I've also built a wrapper script that automates post-processing — reformatting with `terraform fmt`, generating a CSV mapping of ARM resource to Terraform resource, and creating backup import commands."

### Q: "How do you handle state management during migration?"

**Answer:**
"State management is the highest-risk part of the migration. My approach:

1. **Remote state** on Azure Storage with AAD auth and state locking
2. **Multi-layer isolation** — separate state files per layer (networking, compute, database) to minimize blast radius
3. **Import strategy** — I use Terraform 1.5+ import blocks (declarative, reviewable in PR) over CLI imports
4. **Safety protocol** — Back up state before every operation, plan before every apply, never edit state manually in production
5. **State migration** — When splitting a monolithic config into modules, I use `terraform state mv` with pre/post validation

For this project, I'd recommend state files split by: `{env}/networking.tfstate`, `{env}/compute.tfstate`, `{env}/database.tfstate`, `{env}/security.tfstate`."

### Q: "How do you validate functional equivalency between ARM and Terraform?"

**Answer:**
"Three levels of validation:

1. **Plan-level**: After importing all resources, `terraform plan` should show zero changes. Any drift means the Terraform config doesn't match what ARM deployed.
2. **Resource-level**: I built a parity validation script that cross-references `az resource list` output against `terraform state list` to find: matched resources, resources missing from Terraform, and extra resources in Terraform.
3. **Compliance-level**: Run the same compliance scans (Checkov, OPA/Rego) against both the ARM output and the Terraform config to confirm identical security posture."

---

## Section 2: Healthcare/Regulated Environment Questions

### Q: "What HIPAA controls do you implement in infrastructure?"

**Key points:**
- **Encryption at rest**: TDE on SQL, encryption at host on AKS, Key Vault with HSM-backed keys
- **Encryption in transit**: TLS 1.2 minimum everywhere, no public endpoints
- **Access control**: Azure AD authentication, managed identities (no shared secrets), RBAC with least privilege
- **Audit logging**: SQL extended auditing (365-day retention), Key Vault diagnostic settings, VNet flow logs, all logs → Log Analytics
- **Network segmentation**: Private endpoints, NSGs with deny-all defaults, forced tunneling through Azure Firewall
- **Data integrity**: SQL Ledger for immutable audit trail, Advanced Threat Protection, vulnerability assessments

### Q: "How do you enforce compliance in your Terraform pipeline?"

**Answer:**
"I implement compliance as code at multiple layers:
1. **Pre-commit**: `terraform fmt`, `terraform validate`, TFLint
2. **Pipeline stage**: Checkov scan for known misconfigurations, OPA/Rego custom policies (e.g., deny if encryption disabled, deny if public access enabled)
3. **Azure Policy**: Azure-native guardrails that block non-compliant deployments even if Terraform tries
4. **Post-deploy**: Automated compliance reports, Security Center/Defender scoring"

---

## Section 3: OAuth 2.0 / SAML Questions

### Q: "Explain how you secure Terraform's authentication to Azure."

**Answer (order of preference):**
1. **Workload Identity Federation (OIDC)** — Best for CI/CD. The pipeline gets a short-lived token via federated identity credential. No secrets to manage or rotate.
2. **Managed Identity** — Best for Azure-hosted runners. The VM/container running Terraform automatically gets tokens from Azure Instance Metadata Service.
3. **Service Principal + Client Secret** — Fallback. Requires secret rotation (I enforce 90-day expiry) and secure storage in Key Vault.
4. **Azure CLI** — For local development only. Never in production pipelines.

"I always prefer secretless authentication. For Azure DevOps, I configure workload identity federation so the pipeline authenticates via OIDC — no client secrets stored anywhere."

### Q: "Describe your experience with OAuth 2.0 in production."

**Key flows to discuss:**
- **Client Credentials** (machine-to-machine): Used for Terraform service principals, API integrations
- **Authorization Code + PKCE** (user-facing): Used for web apps accessing Azure resources
- **On-Behalf-Of** (service chaining): Used when API A calls API B on behalf of user
- **Managed Identity** (Azure-native): IMDS endpoint provides tokens automatically

### Q: "How does SAML SSO work with Azure AD?"

**Answer:**
"SAML establishes federated trust between an Identity Provider (Azure AD) and a Service Provider (our application):

1. User accesses the application (SP)
2. SP generates a SAML AuthnRequest and redirects user to Azure AD (IdP)
3. User authenticates with Azure AD (MFA, conditional access)
4. Azure AD creates a SAML Assertion (signed XML containing user identity + claims)
5. User's browser POSTs the assertion to the SP's Assertion Consumer Service (ACS) URL
6. SP validates the XML signature, checks assertions, extracts claims
7. SP creates a local session and grants access based on claims

In healthcare, we add custom claims like `employee_id` and `department` for HIPAA audit trails."

---

## Section 4: REST API / Integration Questions

### Q: "How do you integrate Terraform deployments with ITSM tools?"

**Answer:**
"I integrate with ServiceNow via REST API at the pipeline level:

1. **Before apply**: Create a Change Request via `POST /api/now/table/change_request` with implementation plan, risk assessment, and affected CIs
2. **Attach plan**: Upload `terraform plan` output as an attachment to the CR
3. **Wait for approval**: Pipeline pauses until CR is approved in ServiceNow
4. **During apply**: Update CR status to 'Implement' via `PATCH`
5. **After apply**: Close CR with implementation notes, or trigger rollback workflow if apply fails

I've also built event-driven integrations using Azure Event Grid → Azure Function → ServiceNow CMDB for real-time infrastructure inventory sync."

---

## Section 5: Behavioral / Consulting Questions

### Q: "How do you independently lead a migration project?"

**Framework:**
1. **Discovery** (Week 1-2): Inventory ARM templates, deployed resources, dependencies, stakeholders
2. **Planning** (Week 2-3): Design module structure, state strategy, migration waves, rollback plan
3. **Pilot** (Week 3-4): Migrate one low-risk layer (e.g., monitoring), validate approach
4. **Execute** (Week 5-12): Migrate remaining layers in waves, each with validation
5. **Handoff** (Week 13+): Documentation, knowledge transfer, ongoing support

### Q: "How do you handle working with teams in India?"

**Answer:**
"I've worked in distributed teams across time zones. Key practices:
- **Overlap hours**: I flex my schedule to overlap 2-3 hours with India (typically early morning US / late afternoon IST)
- **Async communication**: Detailed PR descriptions, Confluence docs, and Loom videos so work continues across time zones
- **Handoff rituals**: End-of-day summaries documenting what was done, what's blocked, and what's next
- **Shared artifacts**: All decisions documented in code comments and ADRs (Architecture Decision Records)"

---

## Questions to Ask the Interviewer

1. How many ARM templates and resource groups are in scope?
2. What's the current CI/CD pipeline (Azure DevOps, GitHub Actions)?
3. Is there an existing Terraform codebase, or is this greenfield Terraform?
4. What Terraform and AzureRM provider versions are you targeting?
5. How is remote state managed today (or will I design that)?
6. What compliance frameworks apply beyond HIPAA?
7. Will I have access to production environments, or only non-prod?
8. What does the handoff look like — who maintains Terraform after conversion?
9. What's the timeline expectation for the conversion?
10. How many people are on the India team I'll collaborate with?
