# Bloodhound_data_parse
Bloodhound 数据解析工具

说明：
处理Active Directory中的安全主体（如用户、组、计算机等）的ACL信息，将信息导出CSV方便分析，该工具可与Bloodhound 配合使用，Bloodhound处理大量数据渲染慢

功能：
acl_audit(object_type='user')  # 审计用户对象acl
acl_audit(object_type='computer') # 审计计算机对象acl
acl_audit(object_type='group') #  审计组对象acl
get_computer_sessions_info()  # 获取所有计算机登录session
get_domain_users() # 获取域内所有用户
get_group_members() # 获取所有组下面用户


可以用以下采集器采集：
https://github.com/fox-it/BloodHound.py
https://github.com/OPENCYBER-FR/RustHound
ADExplorer.exe +  ADExplorerSnapshot.py 
SharpHound 

文件放置：
files 目录

输出结果：
output目录
