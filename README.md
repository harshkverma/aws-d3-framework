# AWS Data Master Solution

A secure, flexible API architecture on AWS that authenticates users (OIDC), authorizes requests (OPA/Rego + DynamoDB RBAC), logs queries, and connects to multiple databases (S3, DynamoDB, Aurora, Snowflake).

![Architecture](https://raw.githubusercontent.com/harshkverma/aws-d3-framework/refs/heads/master/docs/Architecture.png)

---

## Features
- **RBAC & Policy:** Centralized, role-based access control for users. Easily customizable per firm’s standards (tenant-aware roles, resource/action scopes, optional column/filter constraints) so the architecture aligns with existing processes.

- **Database Flexibility:** Supports AWS data stores (S3, DynamoDB, Aurora) and external platforms (e.g., Snowflake). New or alternative databases can be added or swapped with minimal configuration changes, avoiding costly redesigns.

- **Authentication & Authorization:** Adapts to modern enterprise authentication (e.g., OpenID Connect at the edge) and can swap identity providers without reworking the flow. Authorization remains decoupled via Open Policy Agent (Rego), enabling policy changes without code churn.

- **Cloud-Native Scalability & Resilience:** Built on managed AWS services (Route 53, ALB, API Gateway, Lambda, EventBridge, SQS, DynamoDB) with autoscaling, buffering, DLQs, and multi-AZ durability for high availability.

- **Observability & Audit:** Structured request logging pipeline (EventBridge → SQS → Lambda) persisted to DynamoDB, with CloudWatch metrics, alarms, and tracing for end-to-end auditability.


## Links
- **Confluence documentation:** [Open in Confluence](https://thehkv.atlassian.net/wiki/pages/resumedraft.action?draftId=327698&draftShareId=0b69890d-8f14-410b-9cef-2fd9d1c87ad2))
- **Lucidchart (architecture diagram):** [Open in Lucidchart](https://lucid.app/lucidchart/be5c6252-01f1-4cad-ad14-b38f5178b1a5/edit?viewport_loc=-4226%2C-2030%2C6811%2C3320%2C0_0&invitationId=inv_0da8502b-cfd7-4e18-9c88-344228af42ac))

## Repo Structure
```text
.
├─ docs/
│  ├─ architecture.png
├─ policies/
│  ├─ policy.rego
│  ├─ data.json
│  └─ inputs.json
└─ README.md
