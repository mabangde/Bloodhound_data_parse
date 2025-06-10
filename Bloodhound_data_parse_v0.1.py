import os
import json
import re
import csv
import datetime
import locale

# 动态获取系统最佳编码方案
def get_system_encoding():
    sys_encoding = locale.getpreferredencoding().lower()
    return 'gb18030' if sys_encoding in ['gbk', 'gb2312', 'cp936', 'big5'] else 'utf-8-sig'

# 强制转义序列解码
def unescape_string(s):
    """将转义序列（如 \u4e2d）转换为真实字符"""
    if not isinstance(s, str):
        return s
    try:
        # 分步处理：先处理unicode转义，再处理其他转义
        return s.encode('latin1').decode('unicode_escape').encode('latin1').decode('utf-8')
    except Exception:
        return s

## 首字母大写转换
def transform_string(s):
    if '@' in s:
        s = s.split('@')[0]
    else:
        s = s.strip()
    return s.capitalize()

## 时间转换函数
def convert_timestamp_to_datetime(timestamp):
    try:
        dt_object = datetime.datetime.fromtimestamp(timestamp)
        formatted_date = dt_object.strftime('%Y-%m-%d %H:%M:%S')
        return formatted_date
    except Exception:
        return timestamp

# 从文件中加载JSON数据并缓存到字典中
def load_json_data(file_path):
    json_data = None
    with open(file_path, encoding='utf-8-sig') as f:
        json_data = json.loads(f.read(), strict=False)
    return json_data['data']

def get_json_data(objlabel):
    objlabel = objlabel.lower()
    json_file_path = "./files/"

    # 创建一个字典，将对象类型映射到文件名
    file_mapping = {
        'computer': '',
        'user': '',
        'group': '',
        'ou': '',
        'domain': ''
    }
    for file in os.listdir(json_file_path):
        if file.endswith('.json'):
            if 'computers' in file:
                file_mapping['computer'] = os.path.join(json_file_path, file)
            elif 'users' in file:
                file_mapping['user'] = os.path.join(json_file_path, file)
            elif 'groups' in file:
                file_mapping['group'] = os.path.join(json_file_path, file)
            elif 'ous' in file:
                file_mapping['ou'] = os.path.join(json_file_path, file)
            elif 'domains' in file:
                file_mapping['domain'] = os.path.join(json_file_path, file)

    # 检查请求的对象类型是否在文件映射中
    if objlabel not in file_mapping:
        raise ValueError(f"未找到对象类型为 '{objlabel}' 的文件")

    # 从文件中加载JSON数据并缓存到字典中
    if objlabel not in get_json_data.cache:
        get_json_data.cache[objlabel] = load_json_data(file_mapping[objlabel])
    return get_json_data.cache[objlabel]

get_json_data.cache = {}

def obj_info(PrincipalObj):
    if PrincipalObj['PrincipalType'] != 'Base':
        sidinfo = {}
        '''
        预定义的安全主体（如 Administrators、Domain Admins 等）而设定的，这些安全主体的信息可以在代码加载 JSON 数据时就提前获取
        '''
        wellknownsids = [
            {'pattern': r'^S-1-5-21-(.*?)-527$', 'name': 'Enterprise Key Admins', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-512$', 'name': 'Domain Admins', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-513$', 'name': 'Domain Users', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-500$', 'name': 'Administrator', 'PrincipalType': 'User'},
            {'pattern': r'^S-1-5-21-(.*?)-519$', 'name': 'Enterprise Admins', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-515$', 'name': 'Domain Computers', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-517$', 'name': 'Cert Publishers', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-516$', 'name': 'Domain Controllers', 'PrincipalType': 'Group'},
            {'pattern': r'^S-1-5-21-(.*?)-526$', 'name': 'Key Admins', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-544$', 'name': 'Administrators', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-548$', 'name': 'Account Operators', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-551$', 'name': 'Backup Operators', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-555$', 'name': 'Remote Desktop Users', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-573$', 'name': 'Event Log Readers', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-574$', 'name': 'Certificate Service DCOM Access', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-575$', 'name': 'RDS Remote Access Servers', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-576$', 'name': 'RDS Endpoint Servers', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-577$', 'name': 'RDS Management Servers', 'PrincipalType': 'Group'},
            {'pattern': r'S-1-5-32-578$', 'name': 'Hyper-V Administrators', 'PrincipalType': 'Group'}

        ]
        for wellknownsid in wellknownsids:
            if PrincipalObj['PrincipalSID'] is not None:
                if re.search(wellknownsid['pattern'], PrincipalObj['PrincipalSID']):
                    sidinfo['name'] = wellknownsid['name']
                    sidinfo['PrincipalType'] = wellknownsid['PrincipalType']
                    sidinfo['PrincipalSID'] = PrincipalObj['PrincipalSID']
                    break

        # 从缓存中读取JSON数据
        for data in get_json_data(PrincipalObj['PrincipalType']):
            if data["ObjectIdentifier"] == PrincipalObj['PrincipalSID']:
                sidinfo['name'] = data['Properties']['name']
                sidinfo['PrincipalSID'] = data["ObjectIdentifier"]
                sidinfo['PrincipalType'] = PrincipalObj['PrincipalType']
                break

        return sidinfo

# 写入文件
def write_file(file_name, content):
    """
    将内容写入文件
    :param file_path: 文件名
    :param content: 写入的内容
    :return: None
    """
    output_dir = 'output'
    encoding = get_system_encoding()
    
    # 检查目录是否存在，不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 创建output目录
    output_dir = os.path.join(os.getcwd(), output_dir)
    file_path = os.path.join(output_dir, file_name)
    print(f"[+] 写入文件: {file_path} (编码: {encoding})")
    
    # 转义序列转换
    content = unescape_string(content)
    
    with open(file_path, mode='a', encoding=encoding, errors='replace') as f:
        f.write(content + '\n')

def write_csv(file_name, header, data, encoding=None):
    if encoding is None:
        encoding = get_system_encoding()
        
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_dir = os.path.join(os.getcwd(), output_dir)

    file_path = os.path.join(output_dir, file_name)
    #print(f"[+] 写入CSV: {file_path} (编码: {encoding})")
    
    # 数据处理：字符串转义
    processed_data = []
    for row in data:
        if isinstance(row, list):
            processed_row = [unescape_string(str(cell)) if isinstance(cell, str) else cell for cell in row]
            processed_data.append(processed_row)
        elif isinstance(row, dict):
            processed_row = {key: unescape_string(str(value)) if isinstance(value, str) else value 
                            for key, value in row.items()}
            processed_data.append(processed_row)
        else:
            processed_data.append(row)

    with open(file_path, mode='a', encoding=encoding, errors='replace', newline='') as file:
        if processed_data and isinstance(processed_data[0], dict):
            writer = csv.DictWriter(file, fieldnames=header)
            if os.stat(file_path).st_size == 0:
                writer.writeheader()
            for row in processed_data:
                writer.writerow(row)
        else:
            writer = csv.writer(file)
            if os.stat(file_path).st_size == 0:
                writer.writerow(header)
            for row in processed_data:
                writer.writerow(row)

def acl_audit(object_type):
    # 在屏幕上输出当前要审计的对象类型
    print(f"[+] 正在审计 {object_type} 对象ACL...")
    '''
    默认高权限组无需输出
    :param object_type: 要审计的对象类型（例如'group'，'user','domain', 'computer', 'ou'等）
    :return: None
    '''
    # 定义过滤列表，用于过滤掉不需要输出的安全主体
    sid_filter = {'administrator', 'domain admins', 'key admins', 'enterprise admins', 'enterprise key admins',
                  'administrators', 'account operators'}

    # 结果写入csv：
    header = ['Object Name', 'Security Principal', 'Right', 'Principal Type']
    file_name = f"{object_type.capitalize()}_Acl_Info.csv"
    log_file_name = f"{object_type.capitalize()}_Acl_Info.log"

    # 从缓存中读取JSON数据
    objects = get_json_data(object_type)

    log_content = ""
    for obj in objects:
        acl_exists = False
        rows_to_write = []
        for ace in obj['Aces']:
            # 获取与ACE关联的安全主体的名称和类型
            ace_obj = obj_info({'PrincipalSID': ace['PrincipalSID'], 'PrincipalType': ace['PrincipalType']})
            if ace_obj and not any(ace_obj['name'].lower().startswith(x) for x in sid_filter):
                if not acl_exists:
                    # 如果找到了ACL，则添加对象的名称和分隔符到日志内容中
                    log_content += "=" * 50 + '\n'
                    log_content += f"{object_type.capitalize()}对象:\t{obj['Properties']['name']}\n"
                    acl_exists = True
                obj_name = ace_obj['name'] if ace_obj else 'N/A'
                if not any(obj_name.lower().startswith(x) for x in sid_filter):
                    rows_to_write.append([obj['Properties']['name'], obj_name, ace['RightName'], ace['PrincipalType']])
                    # 添加ACE信息到日志内容中
                    log_content += f"ACE:\n安全主体:\t{obj_name}\n权限:\t{ace['RightName']}\n安全主体类型:\t{ace['PrincipalType']}\n\n"

        if rows_to_write:
            write_csv(file_name, header, rows_to_write)

    # 将日志内容写入文件
    write_file(log_file_name, log_content)
    

## 获取计算机 'RegistrySessions', 'DcomUsers','RemoteDesktopUsers', 'LocalAdmins', 'PSRemoteUsers', 'Sessions', 'PrivilegedSessions' 等信息
def get_computer_sessions_info():
    print("[+] 正在获取计算机Sessions 信息")
    session_keys = [
        'RegistrySessions', 'DcomUsers', 'LocalAdmins',
        'PSRemoteUsers', 'Sessions', 'PrivilegedSessions'
    ]
    object_type = "computer"
    objects = get_json_data(object_type)

    def print_registry_or_privileged_session(session):
        try:
            user = obj_info({
                'PrincipalType': 'User',
                'PrincipalSID': session.get('UserSID')
            })['name']
            computer = obj_info({
                'PrincipalType': 'Computer',
                'PrincipalSID': session.get('ComputerSID')
            })['name']
            return f"\t用户: {user:<20} 计算机: {computer:<20}\n"
        except Exception as e:
            return f"\t处理错误: {e}\n"

    def print_other_session(session):
        try:
            object_info = obj_info({
                'PrincipalSID': session['ObjectIdentifier'],
                'PrincipalType': session['ObjectType']
            })
            if object_info:
                return f"\t{object_info['name']:<40}\n"
        except Exception as e:
            return f"\t处理错误: {e}\n"

    log_file_name = 'computer_sessions_info.log'
    log_content = ""
    for obj in objects:
        for session_key in session_keys:
            results = obj[session_key]['Results']
            if len(results) > 0:
                log_content += "=" * 60 + '\n'
                log_content += f"Computer: {obj['Properties']['name']}\t => {session_key}\n"

                for session in results:
                    if session_key in ['RegistrySessions', 'PrivilegedSessions', 'Sessions']:
                        other_session_output = print_registry_or_privileged_session(session)
                        if other_session_output:
                            log_content += other_session_output
                    else:
                        other_session_output = print_other_session(session)
                        if other_session_output:
                            log_content += other_session_output

    write_file(log_file_name, log_content)
                        
                        

## 获取所有域用户列表并输出csv
def get_domain_users():
    print("[+] 正在获取当前域所有用户信息...")
    object_type = "user"
    user_info_list = []
    
    objects = get_json_data(object_type)
    ## 获取所有用户名
    for object in objects:
        Properties = object['Properties']
        user_info = {
            'samaccountname': Properties.get('samaccountname', ''),
            'admincount': Properties.get('admincount', ''),
            'description': Properties.get('description', ''),
            'displayname': Properties.get('displayname', ''),
            'distinguishedname': Properties.get('distinguishedname', ''),
            'PrimaryGroupSID': obj_info({
                'PrincipalSID': object['PrimaryGroupSID'],
                'PrincipalType': 'Group'
            }).get('name', ''),
            'enabled': Properties.get('enabled', ''),
            'whencreated': convert_timestamp_to_datetime(Properties.get('whencreated', '')),
            'lastlogontimestamp': convert_timestamp_to_datetime(Properties.get('lastlogontimestamp', '')),
            'pwdlastset': convert_timestamp_to_datetime(Properties.get('pwdlastset', '')),
        }
        user_info_list.append(list(user_info.values()))

    # 写入CSV文件
    file_name = 'domain_users.csv'
    header = list(user_info.keys())
    write_csv(file_name, header, user_info_list)

## 获取所有组成员
def get_group_members():
    print("[+] 正在获取域所有组内成员...")
    groups = get_json_data("Group")
    group_csv_data = []  # 用于保存 group 的信息

    for group in groups:
        group_name = group.get("Properties", {}).get("name", "")
        if not group_name:
            continue

        members = group.get("Members", [])
        if not members:
            continue
        try:
            member_names = [obj_info({
                "PrincipalType": member["ObjectType"],
                "PrincipalSID": member["ObjectIdentifier"]
            }).get("name", "") for member in members]
            
            for member_name in member_names:
                group_csv_data.append({
                    "group_name": group_name,
                    "member_name": member_name
                })
        except Exception:
            continue

    # 如果 group_csv_data 不为空，则将数据写入 CSV 文件
    if group_csv_data:
        file_name = 'group_members.csv'
        header = ['group_name', 'member_name']
        write_csv(file_name, header, group_csv_data)

        # 生成日志文件
        log_file_name = 'group_members.log'
        log_content = ""

        current_group = ""
        for group_info in group_csv_data:
            if group_info['group_name'] != current_group:
                if current_group != "":
                    log_content += "\n"
                log_content += "=" * 60 + '\n'
                log_content += f"Group: {unescape_string(group_info['group_name'])} => Members:\n"
                current_group = group_info['group_name']
            log_content += f"\t{unescape_string(group_info['member_name'])}\n"

        # 将内容写入文件
        write_file(log_file_name, log_content)
        
def get_domain_computers():
    print("[+] 正在获取域内所有计算机信息...")
    computers = get_json_data("computer")
    
    computer_data = []
    log_content = ""
    
    for comp in computers:
        props = comp.get('Properties', {})
        
        # 核心属性提取 + 新增 domainsid 和 DumpSMSAPassword
        computer_info = {
            'ObjectIdentifier': comp.get('ObjectIdentifier', 'N/A'),
            'Name': props.get('name', 'N/A'),
            'Description': props.get('description', 'N/A'),
            'OperatingSystem': props.get('operatingsystem', 'N/A'),
            'DomainSID': props.get('domainsid', 'N/A'),  # 新增 domainsid
            'DumpSMSAPassword': ';'.join(comp.get('DumpSMSAPassword', [])),  # 数组转字符串
            'SAMAccountName': props.get('samaccountname', 'N/A'),
            'DistinguishedName': props.get('distinguishedname', 'N/A'),
            'Enabled': props.get('enabled', 'N/A'),
            'LastLogon': convert_timestamp_to_datetime(props.get('lastlogon', '')),
            'LastLogonTimestamp': convert_timestamp_to_datetime(props.get('lastlogontimestamp', '')),
            'PwdLastSet': convert_timestamp_to_datetime(props.get('pwdlastset', '')),
            'WhenCreated': convert_timestamp_to_datetime(props.get('whencreated', '')),
            'UnconstrainedDelegation': props.get('unconstraineddelegation', 'N/A'),
            'TrustedToAuth': props.get('trustedtoauth', 'N/A'),
            'HasLAPS': props.get('haslaps', 'N/A'),
            'Domain': props.get('domain', 'N/A')
        }
        
        # 处理服务主体名称
        spns = props.get('serviceprincipalnames', [])
        computer_info['ServicePrincipalNames'] = '; '.join(spns) if spns else 'N/A'
        
        computer_data.append(computer_info)
        
        # 日志内容生成
        log_content += "=" * 60 + "\n"
        log_content += f"计算机名称: {computer_info['Name']}\n"
        log_content += f"描述: {computer_info['Description']}\n"
        log_content += f"操作系统: {computer_info['OperatingSystem']}\n"
        log_content += f"域SID: {computer_info['DomainSID']}\n"  # 日志中添加 domainsid
        log_content += f"MSA密码导出: {computer_info['DumpSMSAPassword'] or '无'}\n"  # 日志中添加 DumpSMSAPassword
    
    # 写入文件
    if computer_data:
        file_name = 'domain_computers.csv'
        header = list(computer_data[0].keys())
        write_csv(file_name, header, computer_data)
        write_file('domain_computers.log', log_content)


if __name__ == '__main__':
    # 初始化系统编码
    locale.setlocale(locale.LC_ALL, '')
    
    print(f"系统编码: {locale.getpreferredencoding()}")
    print(f"使用文件编码: {get_system_encoding()}")
    
    # 主函数执行
    get_computer_sessions_info()  # 获取所有计算机登录session
    get_domain_users()  # 获取域内所有用户
    get_group_members()  # 获取所有组下面用户 
    get_domain_computers()
    
    # ACL审计
    acls = ['domain', 'user', 'computer', 'group'] 
    for acl in acls:
        acl_audit(object_type=acl)
    
    # 生成说明文件
    readme = f"""输出文件编码说明：
    1. 编码方式: {get_system_encoding()}
    2. 如遇乱码，请用以下方式打开：
       - 文本编辑器: 选择对应编码
       - Excel: 数据 → 获取数据 → 从文本/CSV → 选择文件 → 设置编码
    3. 技术支持: contact@example.com
    """
    write_file("README.txt", readme)
    print("[+] 所有操作已完成!")
