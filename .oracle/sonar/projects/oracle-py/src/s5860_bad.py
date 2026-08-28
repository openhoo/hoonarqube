import re

pattern = re.compile(r'(?P<a>.)')
matches = pattern.match(s)
g = matches.group('b')
