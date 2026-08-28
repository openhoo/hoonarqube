settings = {}
cache = {}
for key, value in settings.items():
    cache[key] = value
for key in settings:
    print(cache.get(key))
