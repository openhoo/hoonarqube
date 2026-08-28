import ldap

connection = ldap.initialize(server_url)
connection.simple_bind("user", "secret")
records = connection.search_s(base_dn, ldap.SCOPE_SUBTREE)
