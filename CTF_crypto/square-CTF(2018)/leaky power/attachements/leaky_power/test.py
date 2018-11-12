# -*- coding: UTF-8 -*-
import numpy as np
test=np.load('plaintexts.npy',encoding = "latin1") #加载文件
doc = open('plaintext', 'w')  #打开一个存储文件，并依次写入
doc.write(str(test))
doc.close()
print str(test)
