package authz

# ------------------------------------------------------------------------------
# Overview
#   Data-driven RBAC for data platforms (Aurora, Snowflake, DynamoDB, S3).
#   The code aims to stay stable; use the guide below to adapt behavior.
#
# Where to make changes (quick map)
#   1) Grant/revoke access (instances/tables/columns):
#      - Edit data.json → users[].roles and roles[].grants[].resources
#        * instances: ["inst-a","inst-*"]            # globs allowed
#        * tables   : ["orders","inst-b.audit","logs-prod/*"]
#        * columns  : columns_allow or columns_by_table (optional allow-lists)
#
#   2) Add a new data source type:
#      - Add an is_<source>(src) helper (see is_sql/is_s3/is_ddb).
#      - Extend required_query_fields_ok with that source’s required fields.
#
#   3) Change HTTP→SQL mapping or add methods:
#      - Edit method_to_action (e.g., map HEAD → "SELECT").
#
#   4) Adjust wildcard semantics:
#      - Default: omitting "instances"/"tables" in a grant means “any”.
#      - Optional rule (commented near inst_ok) makes ["*"] match even when
#        callers omit query.instance.
#
#   5) Relax/tighten per-source request requirements:
#      - Edit required_query_fields_ok (e.g., drop S3 query_sql requirement).
#
#   6) Customize Decision messages or add audit clues:
#      - Edit the Message rules at the bottom (e.g., add more cases).
#
#   7) Case sensitivity:
#      - Matching is case-insensitive via lower(...). Remove those calls to
#        enforce case-sensitive matching.
# ------------------------------------------------------------------------------

Status := "OK"

# ---------- Required fields & basics ----------
has_required_fields(i) if {
	i.user_id
	i.request.method
	i.query.query_type
}

user_in_data(id) if _ := data.users[lower(id)]

# ---------- HTTP → SQL action mapping ----------
# TODO: If you need to support another verb, add it here (e.g., HEAD -> "SELECT").
method_to_action(m) := "SELECT" if lower(m) == "get"
method_to_action(m) := "INSERT" if lower(m) == "post"
method_to_action(m) := "UPDATE" if lower(m) == "put"
method_to_action(m) := "DELETE" if lower(m) == "delete"
method_supported(m) if _ := method_to_action(m)

action(i) := a if a := method_to_action(i.request.method)
types_match(i) if lower(action(i)) == lower(i.query.query_type)

# ---------- Data source families ----------
# TODO: Add new sources here, then update required_query_fields_ok below.
is_sql(src) if lower(src) == "aurora"
is_sql(src) if lower(src) == "snowflake"
is_s3(src) if lower(src) == "s3"
is_ddb(src) if lower(src) == "dynamodb"

nonempty(x) if {
	x != null
	x != ""
}

# Per-source minimum fields required by the engine to evaluate safely
# NOTE: If your org does not require S3 Select SQL, relax the S3 branch below.
required_query_fields_ok(q) if {
	is_sql(q.data_source)
	nonempty(q.query_sql) # SQL engines need a query string
}

required_query_fields_ok(q) if {
	is_s3(q.data_source)
	nonempty(q.query_sql)
}

required_query_fields_ok(q) if {
	is_ddb(q.data_source)
	nonempty(q.KeyConditionExpression)
}

# ---------- Roles & grants from data ----------
role_ids_for(user) := rs if {
	u := data.users[lower(user)]
	rs := {r | r := u.roles[_]}
}

grants_for(user) := gset if {
	rids := role_ids_for(user)
	gset := {g |
		rid := rids[_]
		role := data.roles[rid]
		g := role.grants[_]
	}
}

# ---------- Glob helpers (instances/tables support * and ?) ----------
glob_to_re(s) := out if {
	a := replace(lower(s), ".", "\\.")
	b := replace(a, "*", ".*")
	out := replace(b, "?", ".")
}

glob_match(pat, val) if {
	v := lower(val)
	re := sprintf("^%s$", [glob_to_re(pat)])
	regex.match(re, v)
}

# Utility: key presence
has_key(obj, k) if object.get(obj, k, "__missing__") != "__missing__"

# Grant checks
grant_allows_action(g, act) if {
	acts := {lower(a) | a := g.actions[_]}
	"*" in acts
}

grant_allows_action(g, act) if {
	acts := {lower(a) | a := g.actions[_]}
	lower(act) in acts
}

# Data source match
#   - Omit "data_source" in a grant to mean "any"
#   - Or set "*"
ds_ok(g, q) if not has_key(g.resources, "data_source")
ds_ok(g, q) if lower(g.resources.data_source) == "*"
ds_ok(g, q) if lower(g.resources.data_source) == lower(q.data_source)

# Instance match
#   - Omit "instances" in a grant to mean "any"
#   - Otherwise, request must provide query.instance and match a glob
inst_ok(g, q) if not has_key(g.resources, "instances")

inst_ok(g, q) if {
	is_array(g.resources.instances)
	ilist := [lower(x) | x := g.resources.instances[_]]
	nonempty(q.instance)
	some i
	glob_match(ilist[i], q.instance)
}

# (Optional)
# If you want ["*"] in grants to match even when callers omit instance entirely,
# uncomment the rule below. Leave it commented to require instance when grants specify it.
# inst_ok(g, q) if {
#   is_array(g.resources.instances)
#   "*" in [lower(x) | x := g.resources.instances[_]]
#   not has_key(q, "instance")
# }

# Table helpers
qualified_table(q) := t if {
	nonempty(q.instance)
	t := sprintf("%s.%s", [lower(q.instance), lower(q.table)])
}

qualified_table(q) := t if {
	not nonempty(q.instance)
	t := lower(q.table)
}

# Table match
#   - Omit "tables" in a grant to mean "any"
#   - Supports plain table ("orders") or qualified ("inst-a.audit")
tbl_ok(g, q) if not has_key(g.resources, "tables")

tbl_ok(g, q) if {
	is_array(g.resources.tables)
	tlist := [lower(x) | x := g.resources.tables[_]]
	nonempty(q.table)
	some i
	glob_match(tlist[i], q.table)
}

tbl_ok(g, q) if {
	is_array(g.resources.tables)
	tlist := [lower(x) | x := g.resources.tables[_]]
	nonempty(q.table)
	qt := qualified_table(q)
	some i
	glob_match(tlist[i], qt)
}

grant_matches_resource(g, q) if {
	ds_ok(g, q)
	inst_ok(g, q)
	tbl_ok(g, q)
}

# Column constraints (optional)
exists_not_in(a, b) if {
	some x
	a[x]
	not b[x]
}

# Global columns allow-list
#   - Omit "columns_allow" in a grant to mean "no global column restriction"
#   - If the request does not specify columns, skip column checks
columns_global_ok(req, g) if not has_key(g.resources, "columns_allow")
columns_global_ok(req, g) if not has_key(req, "columns")

columns_global_ok(req, g) if {
	has_key(g.resources, "columns_allow")
	has_key(req, "columns")
	is_array(g.resources.columns_allow)
	reqset := {lower(c) | c := req.columns[_]}
	allow := {lower(c) | c := g.resources.columns_allow[_]}
	not exists_not_in(reqset, allow)
}

# Per-table columns allow-list
#   - Omit "columns_by_table" in a grant to mean "no per-table restriction"
#   - If no entry for this table, treat as unrestricted
columns_table_ok(req, g, q) if not has_key(g.resources, "columns_by_table")
columns_table_ok(req, g, q) if not has_key(req, "columns")

columns_table_ok(req, g, q) if {
	has_key(g.resources, "columns_by_table")
	is_array(g.resources.columns_by_table)
	nonempty(q.table)
	req_key := qualified_table(q)

	# presence map only; if no entry => no restriction
	tmap_present := {lower(e.table): true | e := g.resources.columns_by_table[_]}
	not has_key(tmap_present, req_key)
}

columns_table_ok(req, g, q) if {
	has_key(g.resources, "columns_by_table")
	is_array(g.resources.columns_by_table)
	has_key(req, "columns")
	nonempty(q.table)
	req_key := qualified_table(q)
	tmap := {lower(e.table): {lower(c) | c := e.columns[_]} | e := g.resources.columns_by_table[_]}
	has_key(tmap, req_key)
	allowt := tmap[req_key]
	reqset := {lower(c) | c := req.columns[_]}
	not exists_not_in(reqset, allowt)
}

columns_ok_for_grant(req, g, q) if {
	columns_global_ok(req, g)
	columns_table_ok(req, g, q)
}

# Any grant that authorizes the request
some_grant_allows(i) if {
	act := action(i)
	g := grants_for(i.user_id)[_]
	grant_allows_action(g, act)
	grant_matches_resource(g, i.query)
	columns_ok_for_grant(i.request, g, i.query)
}

# Reusable preconditions
basic_ok(i) if {
	has_required_fields(i)
	user_in_data(i.user_id)
	method_supported(i.request.method)
}

query_fields_ok(i) if required_query_fields_ok(i.query)

# MESSAGE

Message := "Access Granted" if {
	Decision == "Allowed"
}

Message := "User does not exist" if {
	has_required_fields(input)
	not user_in_data(input.user_id)
}

Message := "Insufficient privileges" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	not some_grant_allows(input)
}

# DECISIONS

# High-level flow:
#   - structural/identity checks -> Indeterminate
#   - method/type alignment      -> Denied
#   - per-source required fields -> Indeterminate
#   - grant evaluation           -> Allowed / Denied

Decision := "Allowed" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	some_grant_allows(input)
}

Decision := "Denied" if {
	basic_ok(input)
	not types_match(input)
}

Decision := "Denied" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	not some_grant_allows(input)
}

Decision := "Indeterminate" if not has_required_fields(input)

Decision := "Indeterminate" if {
	has_required_fields(input)
	not user_in_data(input.user_id)
}

Decision := "Indeterminate" if {
	has_required_fields(input)
	method_supported(input.request.method)
	not input.query.data_source
}

Decision := "Indeterminate" if {
	basic_ok(input)
	types_match(input)
	not query_fields_ok(input)
}
