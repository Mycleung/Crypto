import Crypto
from Crypto.Hash import MD5

m = MD5.new()

print m.digest()
print m.hexdigest()
