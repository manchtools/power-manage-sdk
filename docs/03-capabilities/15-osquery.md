---
title: osquery
label: osquery
description: Query host state with osquery's SQL interface — with a deny-list that keeps a compromised caller out of credential-bearing tables.
icon: "🔎"
---

# osquery

`sys/osquery` exposes the host as SQL through `osqueryi`: list tables, query a
table, or run raw SQL. It is a single-tool capability, so `New` takes only a
Runner, no Backend. A **deny-list** refuses credential-bearing tables on the
convenience path, which is the part to pay attention to.

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

<!-- docref: begin src=sys/osquery/osquery.go#client.QueryTable:5586f365 -->
`QueryTable` validates the table name (alphanumeric + underscore) and applies the
deny-list before building `SELECT * FROM <table>`, so an invalid or forbidden
name is rejected without running anything.
<!-- docref: end -->

## The sensitive-table deny-list

<!-- docref: begin src=sys/osquery/osquery.go#sensitiveTables:1054224b -->
A curated deny-list refuses tables that expose credential material — `shadow`
(password hashes), `process_envs` (secrets in process environments), `crontab`,
`shell_history`, and `sudoers` — on the table path. They all pass the name
validity check, so a shape-only filter is not enough; this refuses them by name
so a compromised control server cannot exfiltrate them through the agent's
privileged osquery.
<!-- docref: end -->

<!-- docref: begin src=sys/osquery/osquery.go#client.Query:29737495 -->
The deny-list gates **both** query paths: `Query` with a `Table` (and
`QueryTable`) refuses a sensitive name before building any SQL, and `RawSql` is
refused when it *references* a sensitive table. Even the signed raw-query path
cannot read `shadow`/`sudoers`/… — there is no osquery path to a credential
table.
<!-- docref: end -->

{% callout type="warning" title="RawSql is still the operator's responsibility" %}
`RawSql` runs arbitrary read-only SQL and is a signed command in the agent, so
restrict who can issue it. It is gated by the credential deny-list — it cannot
read `shadow`/`sudoers`/… — but it can still read any other table osquery
exposes.
{% /callout %}

## Related

- [Antivirus](/capabilities/antivirus) — malware scanning alongside host queries.
- Inventory (`sys/inventory`) — structured hardware/software facts without SQL.
