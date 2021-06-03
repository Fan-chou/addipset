# addipset

一个 Golang 的 ipset 动态链接，基于 `github.com/digineo/go-ipset/v2`

```
go build -buildmode=c-shared -o addipset.so main.go
```

# example

```python
from ctypes import cdll, c_char_p

ipset = cdll.LoadLibrary("./addipset.so")

ipset.Add.argtypes = [c_char_p, c_char_p]
ipset.Add.restype = c_char_p

ipset.Add("1.1.1.1".encode("utf-8"),"test".encode("utf-8"))
```