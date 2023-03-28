import os
import json
import re
import csv
import datetime


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
    except Exception as e:
        return timestamp


# 从文件中加载JSON数据并缓存到字典中
def load_json_data(file_path):
    json_data = None
    with open(file_path, encoding='utf-8-sig') as f:
        json_data = json.loads(f.read())
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
    if objlabel == 'foreignsecurityprincipal':
        #print(f"[+] 不支持请求对象类型为 '{objlabel}' 的数据")
        return None
    elif objlabel not in file_mapping:
        return None
        #raise ValueError(f"未找到对象类型为 '{objlabel}' 的文件")

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
        if PrincipalObj['PrincipalType'] == 'foreignsecurityprincipal':
            sidinfo['name'] = PrincipalObj['PrincipalSID']
            sidinfo['PrincipalType'] = 'foreignsecurityprincipal'
            sidinfo['PrincipalSID'] = PrincipalObj['PrincipalSID']

        for wellknownsid in wellknownsids:
            if re.search(wellknownsid['pattern'], PrincipalObj['PrincipalSID']):
                sidinfo['name'] = wellknownsid['name']
                sidinfo['PrincipalType'] = wellknownsid['PrincipalType']
                sidinfo['PrincipalSID'] = PrincipalObj['PrincipalSID']
                break

        # 从缓存中读取JSON数据
        if get_json_data(PrincipalObj['PrincipalType']):
            for data in get_json_data(PrincipalObj['PrincipalType']):
                if data["ObjectIdentifier"] == PrincipalObj['PrincipalSID']:
                    try:
                        sidinfo['name'] = data['Properties']['name']
                        sidinfo['PrincipalSID'] = data["ObjectIdentifier"]
                        sidinfo['PrincipalType'] = PrincipalObj['PrincipalType']
                    except KeyError:
                        return None
                    except ValueError as e:
                        #print(f"Warning：{e}")
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
    # 检查目录是否存在，不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # 创建output目录
    output_dir = os.path.join(os.getcwd(), output_dir)
    file_path = os.path.join(output_dir, file_name)
    print(f"[+] 写入文件: {file_path}")
    # print(content)
    with open(file_path, mode='a', encoding='utf-8') as f:
        f.write(content + '\n')


def write_csv(file_name, header, data, encoding='utf-8'):
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_dir = os.path.join(os.getcwd(), output_dir)

    file_path = os.path.join(output_dir, file_name)
    with open(file_path, mode='a', encoding=encoding, newline='') as file:
        if data and isinstance(data[0], dict):
            writer = csv.DictWriter(file, fieldnames=header)
            write_row_func = writer.writerow
        else:
            writer = csv.writer(file)
            write_row_func = writer.writerow

        if os.stat(file_path).st_size == 0:
            if isinstance(writer, csv.DictWriter):
                writer.writeheader()
            else:
                writer.writerow(header)

        for row in data:
            try:
                write_row_func(row)
            except UnicodeEncodeError:
                if isinstance(row, dict):
                    filtered_row = {}
                    for key, value in row.items():
                        if isinstance(value, str):
                            filtered_row[key] = value.encode('gbk', 'ignore').decode('gbk')
                        else:
                            filtered_row[key] = value
                    write_row_func(filtered_row)
                else:
                    filtered_row = []
                    for cell in row:
                        if isinstance(cell, str):
                            filtered_row.append(cell.encode('gbk', 'ignore').decode('gbk'))
                        else:
                            filtered_row.append(cell)
                    write_row_func(filtered_row)


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
            write_csv(file_name, header, rows_to_write, encoding="gbk")

    # 将日志内容写入文件
    write_file(log_file_name, log_content)


## 获取计算机 'RegistrySessions', 'DcomUsers','RemoteDesktopUsers', 'LocalAdmins', 'PSRemoteUsers', 'Sessions', 'PrivilegedSessions' 等信息
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
            return f"\tAn error occurred: {e}\n"

    def print_other_session(session):
        try:
            object_info = obj_info({
                'PrincipalSID': session['ObjectIdentifier'],
                'PrincipalType': session['ObjectType']
            })
            if object_info:
                return f"\t{object_info['name']:<40}\n"
        except Exception as e:
            return f"\tAn error occurred: {e}\n"

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
        if 'samaccountname' in Properties:
            user_info = {
                'samaccountname': Properties['samaccountname'],
                'admincount': Properties['admincount'],
                'description': Properties['description'],
                'displayname': Properties['displayname'],
                'distinguishedname': Properties['distinguishedname'],
                'PrimaryGroupSID': obj_info({
                    'PrincipalSID': object['PrimaryGroupSID'],
                    'PrincipalType': 'Group'
                })['name'],
                'enabled': Properties['enabled'],
                'whencreated': convert_timestamp_to_datetime(Properties['whencreated']),
                'lastlogontimestamp': convert_timestamp_to_datetime(Properties['lastlogontimestamp']),
                'pwdlastset': convert_timestamp_to_datetime(Properties['pwdlastset']),
            }
            user_info_list.append(list(user_info.values()))

    # 写入CSV文件

    file_name = 'domain_users.csv'
    header = list(user_info.keys())
    write_csv(file_name, header, user_info_list, encoding='gbk')


## 获取所有组成员
def get_group_members():
    print("[+] 正在获取域所有组内成员...")
    groups = get_json_data("Group")
    group_csv_data = []  # 用于保存 group 的信息

    # 新增：定义日志内容的字符串和分隔线
    log_content = ""

    for group in groups:
        group_name = group.get("Properties", {}).get("name")
        if not group_name:
            continue

        members = group.get("Members", [])
        if not members:
            continue

        # 新增：将分隔线添加到日志内容中
        log_content += f"Group: {transform_string(group_name)} => Members:\n{'-' * 60}\n"

        # 新增：将成员名称添加到列表中
        member_names = [
            obj_info({"PrincipalType": member["ObjectType"], "PrincipalSID": member["ObjectIdentifier"]}).get("name")
            if obj_info({"PrincipalType": member["ObjectType"], "PrincipalSID": member["ObjectIdentifier"]}) is not None
            else None
            for member in members
        ]

        # 新增：忽略成员名称为 None 的成员
        member_names = [member_name for member_name in member_names if member_name is not None]

        for member_name in member_names:
            group_csv_data.append({"group_name": group_name, "member_name": member_name})
            # 新增：将成员名称添加到日志内容中
            log_content += f"\t{member_name}\n"

    # 如果 group_csv_data 不为空，则将数据写入 CSV 文件
    if group_csv_data:
        file_name = 'group_members.csv'
        header = ['group_name', 'member_name']
        write_csv(file_name, header, group_csv_data, encoding='gbk')

        # 新增：将内容写入文件
        write_file('group_members.log', log_content)


def get_computers():
    log_file_name = 'computers.log'
    log_content = ""

    print("[+] 正在获取计算机信息...")

    computers = get_json_data("Computer")
    for i, computer in enumerate(computers, start=1):
        properties = computer.get("Properties", {})
        computer_name = properties.get("name")
        log_content += "=" * 60 + '\n'
        log_content += f"[{i}] Computer: {computer_name}" + '\n'

        primary_group_sid = computer.get("PrimaryGroupSID")
        if primary_group_sid:
            group = obj_info({"PrincipalSID": primary_group_sid, "PrincipalType": "Group"})
            log_content += f"\t Group: {group['name']}" + '\n'

        operatingsystem = properties.get("operatingsystem")
        if operatingsystem:
            log_content += f"\t operatingsystem: {operatingsystem}" + '\n'

        serviceprincipalnames = properties.get("serviceprincipalnames")
        if len(serviceprincipalnames) > 1:
            for spn in serviceprincipalnames:
                log_content += f"\t SPN: {spn}" + '\n'

    # 将日志内容写入文件
    write_file(log_file_name, log_content)

    # 打印输出结果
    print("[+] 获取计算机信息完成！")


def get_trusts():
    print("[+] 正在获取域信任关系信息...")
    domains = get_json_data("Domain")
    trusts_data = []  # 用于保存域信任关系信息

    for domain in domains:
        domain_name = domain.get("Properties", {}).get("name")
        if not domain_name:
            continue

        trusts = domain.get("Trusts", [])
        if not trusts:
            continue

        for trust in trusts:
            target_domain_name = trust.get("TargetDomainName")
            if target_domain_name:
                trusts_data.append({"source_domain": domain_name, "target_domain": target_domain_name})

    # 如果 trusts_data 不为空，则将数据写入日志文件
    if trusts_data:
        log_file_name = 'domain_trusts.log'
        log_content = ""

        for trust in trusts_data:
            log_content += "=" * 60 + '\n'
            log_content += f"Source Domain: {trust['source_domain']} => Target Domain: {trust['target_domain']}\n"

        # 新增：将内容写入文件
        write_file(log_file_name, log_content)




if __name__ == '__main__':

    get_computers() # 所有计算机
    get_trusts() # 域信任关系
    get_computer_sessions_info()  # 获取所有计算机登录session
    get_domain_users()  # 获取域内所有用户
    get_group_members()  # 获取所有组下面用户
    acls = ['domain', 'user', 'computer', 'group']
    for acl in acls:
        acl_audit(object_type=acl)
