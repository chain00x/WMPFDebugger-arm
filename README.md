# WMPFDebugger
ida arm打开（时间很久 要等）
```
cd '/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C'
```
## 搜索[perf] AppletIndexContainer::OnLoadStart
![alt text](image.png)
修改为这个地方的偏移
![alt text](image-1.png)
## 上个函数的最后调用的函数
![alt text](image-3.png)
![alt text](image-8.png)
不通版本这个位置偏移不同
![alt text](image-6.png)
![alt text](image-7.png)
这个值设置为1101
![alt text](image-4.png)

## 搜索SendToClientFilter
![alt text](image-2.png)
这个函数的
```
if ( v8[2] != 6 )
```
这个判断要为true，v8[2]的值不为6

## 搜索WAPCAdapterAppIndex.js
第一个引用
![alt text](image-5.png)
直接返回0x0