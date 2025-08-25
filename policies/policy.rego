package authz

# What this policy does
# - Role-based access control for Aurora, Snowflake, DynamoDB, and S3.
# - The logic stays stable; you tune behavior via data.json and small helpers.

# Where to tweak things
# 1) Who can access what:
#    - Edit data.json → users[].roles and roles[].grants[].resources
#    - instances: ["inst-a","inst-*"]         (globs allowed)
#    - tables:    ["orders","inst-b.audit","logs-prod/*"]
#    - columns:   columns_allow or columns_by_table (optional allow-lists)
# 2) New data source:
#    - Add is_<source>(src) (see is_sql/is_s3/is_ddb)
#    - Update required_query_fields_ok with the fields that source needs
# 3) Extra verbs:
#    - Extend method_to_action (e.g., map HEAD → "SELECT")
# 4) Wildcards:
#    - Omitting "instances"/"tables" in a grant means “any”
#    - Optional rule near inst_ok lets ["*"] match even when the request omits instance
# 5) Per-source request requirements:
#    - Tighten/relax required_query_fields_ok as needed (e.g., S3 SQL not required)
# 6) Messages:
#    - Adjust the Message else-chain to add or refine reasons
# 7) Case-sensitivity:
#    - We compare with lower(...). Remove those calls to make matching case-sensitive.

Status := "OK"

# Core prerequisites
# User exists, method is known, and the query declares a type.
has_required_fields(i) if {
	i.user_id
	i.request.method
	i.query.query_type
}

user_in_data(id) if _ := data.users[lower(id)]

# HTTP/SQL verb mapping
# Accept either HTTP or SQL verbs and normalize them.
method_to_action(m) := "SELECT" if lower(m) == "get"
method_to_action(m) := "SELECT" if lower(m) == "select"

method_to_action(m) := "INSERT" if lower(m) == "post"
method_to_action(m) := "INSERT" if lower(m) == "insert"

method_to_action(m) := "UPDATE" if lower(m) == "put"
method_to_action(m) := "UPDATE" if lower(m) == "patch"
method_to_action(m) := "UPDATE" if lower(m) == "update"

method_to_action(m) := "DELETE" if lower(m) == "delete"
method_to_action(m) := "DELETE" if lower(m) == "del"

method_supported(m) if _ := method_to_action(m)

# Derived action + type check
# SQL action from the request method, then ensure it matches query_type.
action(i) := a if {
  a := method_to_action(i.request.method)
}

types_match(i) if {
  lower(action(i)) == lower(i.query.query_type)
}

# Source kind helpers
# Add more here when you bring in another engine.
is_sql(src) if lower(src) == "aurora"
is_sql(src) if lower(src) == "snowflake"
is_s3(src) if lower(src) == "s3"
is_ddb(src) if lower(src) == "dynamodb"

nonempty(x) if {
	x != null
	x != ""
}

# Minimum fields per source
# Keep these tight so we never authorize on incomplete requests.
required_query_fields_ok(q) if {
	is_sql(q.data_source)
	nonempty(q.query_sql)
}

required_query_fields_ok(q) if {
	is_s3(q.data_source)
	nonempty(q.query_sql)
}

required_query_fields_ok(q) if {
	is_ddb(q.data_source)
	nonempty(q.KeyConditionExpression)
}

# Roles and grants
# Expand user roles into a flattened set of grants.
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

# Globbing helpers for instance/table
# Translate '*' and '?' into regex to match globs.
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

# Presence helper
has_key(obj, k) if object.get(obj, k, "__missing__") != "__missing__"

# Grant checks
# Action is allowed if list has '*' or the exact action.
grant_allows_action(g, act) if {
	acts := {lower(a) | a := g.actions[_]}
	"*" in acts
}

grant_allows_action(g, act) if {
	acts := {lower(a) | a := g.actions[_]}
	lower(act) in acts
}

# Data source, instance, table checks
# If a field is omitted in a grant, it means “no restriction”.
ds_ok(g, q) if not has_key(g.resources, "data_source")
ds_ok(g, q) if lower(g.resources.data_source) == "*"
ds_ok(g, q) if lower(g.resources.data_source) == lower(q.data_source)

inst_ok(g, q) if not has_key(g.resources, "instances")

inst_ok(g, q) if {
	is_array(g.resources.instances)
	ilist := [lower(x) | x := g.resources.instances[_]]
	nonempty(q.instance)
	some i
	glob_match(ilist[i], q.instance)
}

qualified_table(q) := t if {
	nonempty(q.instance)
	t := sprintf("%s.%s", [lower(q.instance), lower(q.table)])
}

qualified_table(q) := t if {
	not nonempty(q.instance)
	t := lower(q.table)
}

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

# Column constraints
# Two types of allow-lists: global and per-table. If no columns are requested -> Skip.
exists_not_in(a, b) if {
	some x
	a[x]
	not b[x]
}

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

columns_table_ok(req, g, q) if not has_key(g.resources, "columns_by_table")
columns_table_ok(req, g, q) if not has_key(req, "columns")

columns_table_ok(req, g, q) if {
	has_key(g.resources, "columns_by_table")
	is_array(g.resources.columns_by_table)
	nonempty(q.table)
	req_key := qualified_table(q)

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

# Overall grant match
# A grant must pass the resource checks and any column constraints.
some_grant_allows(i) if {
	act := action(i)
	g := grants_for(i.user_id)[_]
	grant_allows_action(g, act)
	grant_matches_resource(g, i.query)
	columns_ok_for_grant(i.request, g, i.query)
}

# Reusable preconditions
# basic_ok covers structure and identity; query_fields_ok covers per-source fields.
basic_ok(i) if {
	has_required_fields(i)
	user_in_data(i.user_id)
	method_supported(i.request.method)
}

query_fields_ok(i) if required_query_fields_ok(i.query)

# Diagnostics for better messages
# Filter the user’s grants step by step; the first empty stage explains the denial.
grants_after_action(i) := gs if {
	act := action(i)
	gs := { g |
		g := grants_for(i.user_id)[_]
		grant_allows_action(g, act)
	}
}

grants_after_ds(i) := gs if {
	gs := { g |
		g := grants_after_action(i)[_]
		ds_ok(g, i.query)
	}
}

grants_after_inst(i) := gs if {
	gs := { g |
		g := grants_after_ds(i)[_]
		inst_ok(g, i.query)
	}
}

grants_after_tbl(i) := gs if {
	gs := { g |
		g := grants_after_inst(i)[_]
		tbl_ok(g, i.query)
	}
}

grants_after_cols(i) := gs if {
	gs := { g |
		g := grants_after_tbl(i)[_]
		columns_ok_for_grant(i.request, g, i.query)
	}
}

# Message
Message := "Access Granted" if {
	Decision == "Allowed"
} else := "User does not exist" if {
	has_required_fields(input)
	not user_in_data(input.user_id)
} else := sprintf("Insufficient privileges: user '%s' has no grants.", [lower(input.user_id)]) if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_for(input.user_id)) == 0
} else := sprintf("Insufficient privileges: action '%s' is not permitted by any grant.", [lower(action(input))]) if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_for(input.user_id)) > 0
	count(grants_after_action(input)) == 0
} else := sprintf("Insufficient privileges: data_source '%s' is not permitted.", [lower(input.query.data_source)]) if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_after_action(input)) > 0
	count(grants_after_ds(input)) == 0
} else := sprintf("Insufficient privileges: instance '%s' is not permitted.", [lower(object.get(input.query, "instance", ""))]) if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_after_ds(input)) > 0
	count(grants_after_inst(input)) == 0
} else := sprintf(
	"Insufficient privileges: table '%s' (qualified: '%s') is not permitted.",
	[ lower(object.get(input.query, "table", "")), qualified_table(input.query) ],
) if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_after_inst(input)) > 0
	count(grants_after_tbl(input)) == 0
} else := "Insufficient privileges: requested column set is not permitted by any matching grant." if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	count(grants_after_tbl(input)) > 0
	count(grants_after_cols(input)) == 0
} else := "Insufficient privileges" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	not some_grant_allows(input)
}

# Decision
Decision := "Allowed" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	some_grant_allows(input)
} else := "Denied" if {
	basic_ok(input)
	not types_match(input)
} else := "Denied" if {
	basic_ok(input)
	types_match(input)
	query_fields_ok(input)
	not some_grant_allows(input)
} else := "Indeterminate" if {
	not has_required_fields(input)
} else := "Indeterminate" if {
	has_required_fields(input)
	not user_in_data(input.user_id)
} else := "Indeterminate" if {
	has_required_fields(input)
	method_supported(input.request.method)
	not input.query.data_source
} else := "Indeterminate" if {
	basic_ok(input)
	types_match(input)
	not query_fields_ok(input)
} else := "Indeterminate" if {
	true
}