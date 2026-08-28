cursor.execute("SELECT * FROM t")
cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))
message = "hi %s" % name
label = "count={}".format(total)
