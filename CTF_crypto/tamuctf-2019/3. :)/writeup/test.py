#!/usr/bin/env python2
import base64
from itertools import cycle

ct = "XUBdTFdScw5XCVRGTglJXEpMSFpOQE5AVVxJBRpLT10aYBpIVwlbCVZATl1WTBpaTkBOQFVcSQdH"
key = ':)'

print ''.join([chr(ord(x)^ord(y)) for x,y in zip(base64.b64decode(ct), cycle(key))])
