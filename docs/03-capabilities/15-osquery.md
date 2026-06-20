---
title: osquery
label: osquery
description: Query host state with osquery's SQL interface — with a deny-list that keeps a compromised caller out of credential-bearing tables.
icon: "🔎"
---

# osquery

`sys/osquery` exposes the host as SQL through `osqueryi`: list tables, query a
table, or run raw SQL. It is a single-tool capability, so `New` takes only a
Runner, no Backend. Its defining feature is a **deny-list** that refuses
credential-bearing tables on the convenience path.

## Construct a querier

```go
r, err := exec.NewRunner(exec.Sudo) // osquery reads privileged tables
if err != nil {
    return err
}
q, err := osquery.New(r) // ErrNotInstalled if osqueryi is absent
if err != nil {
    return err
}
```

## Query

```go
rows, err := q.QueryTable(ctx, "os_version")
tables, err := q.ListTables(ctx)
result, err := q.Query(ctx, &pb.OSQuery{Table: "processes"})
```

## The sensitive-table deny-list

<!-- docref: begin src=sys/osquery/osquery.go#sensitiveTables:1054224b -->
A curated deny-list refuses tables that expose credential material — `shadow`
(password hashes), `process_envs` (secrets in process environments), `crontab`,
`shell_history`, and `sudoers` — on the table path. They all pass the name
validity check, so a shape-only filter is not enough; this refuses them by name
so a compromised control server cannot exfiltrate them through the agent's
privileged osquery.
<!-- docref: end -->

<!-- docref: begin src=sys/osquery/osquery.go#client.Query:7d6685c6 -->
The deny-list gates the convenience *table* path: `Query` with a `Table` (and
`QueryTable`) refuses a sensitive name before building any SQL. The signed
`RawSql` escape hatch is intentionally **not** gated — it is the operator's
explicit, CA-signed path — so a sanctioned query can still reach a sensitive
table when the operator deliberately asks for it.
<!-- docref: end -->

{% callout type="warning" title="RawSql is the operator's responsibility" %}
`RawSql` bypasses the deny-list by design. Restrict who can issue it (it is a
signed command in the agent), because it can read anything osquery can.
{% /callout %}

## Related

- [Antivirus](/capabilities/antivirus) — malware scanning alongside host queries.
- [Inventory](/capabilities/inventory) — structured hardware/software facts
  without SQL.
