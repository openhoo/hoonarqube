import re

re.sub(r'(a)(b)(c)', r'\1, \9, \3', s)
