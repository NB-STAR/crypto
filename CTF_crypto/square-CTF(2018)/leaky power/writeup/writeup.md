首先去了解一下A128GCM

```java
public static final EncryptionMethod A128GCM = 
new EncryptionMethod("A128GCM", Requirement.RECOMMENDED, 128);

...

public EncryptionMethod(final String name, final Requirement req, final int cekBitLength) {
    super(name, req);  
    this.cekBitLength = cekBitLength; 
}  
    /**
     * Creates a new encryption method. The Content Encryption Key (CEK)
     * bit length is not specified.
     *
     * @param name The encryption method name. Must not be {@code null}.
     * @param req  The implementation requirement, {@code null} if not 
     *             known.
     */
public EncryptionMethod(final String name, final Requirement req) {
    this(name, req, 0);
}
```

有两个npy文件，读取一下数据。

```python
# -*- coding: UTF-8 -*-
import numpy as np
test=np.load('plaintexts.npy',encoding = "latin1") #加载文件
doc = open('plaintext', 'w')  #打开一个存储文件，并依次写入
doc.write(str(test))
doc.close()
```

```python
# -*- coding: UTF-8 -*-
import numpy as np
test=np.load('powertraces.npy',encoding = "latin1") #加载文件
doc = open('data_power', 'w')  #打开一个存储文件，并依次写入
doc.write(str(test))
doc.close()
```
