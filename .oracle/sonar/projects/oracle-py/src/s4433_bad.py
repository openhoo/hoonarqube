import ldap

connection = ldap.initialize(server_url)
records = connection.search_s(base_dn, ldap.SCOPE_SUBTREE)
