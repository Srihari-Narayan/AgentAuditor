# Terraform — deliberately-misconfigured AWS sandbox (OPTIONAL)

> ⚠️ **DANGER:** this intentionally creates **insecure** resources so a scanner
> has something to find. Apply it **only in a throwaway AWS account you own and
> can delete.** Never in a shared, production, or employer account. You are
> responsible for any cost and exposure.

This is scaffolding for the "real data" path: stand up a sandbox with known
misconfigurations, run Prowler against it, and feed the JSON into the agent.

`main.tf` here is a **minimal, commented skeleton** — review and uncomment
before use. It is not applied in CI and nothing in the Python depends on it.

## Suggested flow

```bash
cd terraform
terraform init
terraform apply          # creates the insecure sandbox (review first!)

# scan it
pip install prowler
prowler aws -M json-ocsf -o ../data/findings/_scan

# normalize Prowler output into this project's finding schema, then:
python -m audit_agent.run --findings ../data/findings/your_normalized.json

terraform destroy        # tear it ALL down when finished
```

A normalizer from Prowler's schema to `Finding` is left as a (small) exercise —
map Prowler's `severity`/`check_id`/`resource` onto `severity`/`category`/
`resource`. Keep the sandbox short-lived.
