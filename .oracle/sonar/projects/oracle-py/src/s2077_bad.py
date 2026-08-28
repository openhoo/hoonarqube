uid = 7
name = "bob"

query = "SELECT * FROM users WHERE id=%s" % uid
lookup = "SELECT * FROM orders WHERE buyer='{}'".format(name)
delete = f"SELECT * FROM sessions WHERE user_id={uid}"

cursor.execute(query)
