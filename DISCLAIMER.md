# Disclaimer

This is an independent research and portfolio project.

- **Synthetic data only.** All findings in this repository are fabricated
  examples. They do not describe any real system, account, or organization.
- **No real actions.** The agent writes reports and an audit trail. The one
  "sensitive" tool (`send_report`) is a dry-run stub and sends nothing.
- **Sandbox only.** The optional Terraform in `terraform/` intentionally creates
  insecure resources to generate scanner findings. Apply it **only in a
  throwaway cloud account you own and can afford to delete.** Never in a shared,
  production, or employer account.
- **Attack only your own systems.** The red-team harness targets this project's
  own agent. Do not point any technique here at systems you are not authorized
  to test.
- **Not security advice or certification.** Control mappings and risk scores are
  illustrative modeling choices, not an attestation of compliance.

This project is the author's own work, built from public frameworks (NIST
800-53, CIS AWS Foundations, the OWASP Agentic Top 10). It is not derived from
any employer's confidential material.
