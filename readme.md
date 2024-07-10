一个旨在从文件的二进制中分辨ip和域名的工具

用法：python3 main.py -t target -o output.txt

a tool aims to recognize ip and domain from a file's binary

usage：python3 main.py -t target -o output.txt

todo

- [x] 提取代码中的字符串信息（""和''包裹的）
- [x] 提取ip
- [x] 提取域名
- [x] 提取敏感词关键字相关字符串
- [x] 文件夹遍历扫描
- [x] 多线程扫描
- [ ] 打包为so库
- [ ] 更加完善的敏感词关键词
- [ ] 更加完善的正则
- [ ] 更加完善的匹配策略
- [ ] 更加完善的接口、良好的交互性