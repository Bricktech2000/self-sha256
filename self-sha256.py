data = '''
quote = "'" * 3
from hashlib import sha256
print(sha256(f'data = {quote}{data}{quote}{data}'.encode()).hexdigest())
'''
quote = "'" * 3
from hashlib import sha256
print(sha256(f'data = {quote}{data}{quote}{data}'.encode()).hexdigest())
