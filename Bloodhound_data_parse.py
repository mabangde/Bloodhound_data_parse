import os
import json
import re
import csv
import datetime
import sys

def print(*args, **kwargs):
    built_in_print(*args, **kwargs)
    output_dir = 'output'
    # 检查目录是否存在，不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # 创建output目录
    output_dir = os.path.join(os.getcwd(), output_dir)
    file_path = os.path.join(output_dir, 'output.txt')
    with open(file_path, "a", encoding="utf-8") as f:
        built_in_print(*args, file=f, **kwargs)

built_in_print = __builtins__.print

# 保存系统自带的print函数


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
    # 检查目录是否存在，不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # 创建output目录
    output_dir = os.path.join(os.getcwd(), output_dir)
    file_path = os.path.join(output_dir, file_name)
    print(f"写入文件: {file_path}")
    print(content)
    with open(file_path, mode='a', encoding='utf-8') as f:
        f.write(content + '\n')


def write_csv(file_name, header, data,  encoding= 'utf-8'):
    """
    将ACL信息写入CSV文件
    :param file_name: 文件名，不需要路径
    :param header: CSV文件头部
    :param data: 要写入的内容
    :return: None
    """

    output_dir = 'output'
    # 检查目录是否存在，不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # 创建output目录
    output_dir = os.path.join(os.getcwd(), output_dir)


    #print(f"写入文件: {file_path}")
    # 生成文件名
    file_path = os.path.join(output_dir, file_name)
    with open(file_path, mode='a', encoding= encoding, newline='') as file:
        writer = csv.writer(file)
        if os.stat(file_path).st_size == 0:
            writer.writerow(header)
        for row in data:
            try:
                writer.writerow(row)
            except UnicodeEncodeError:
                filtered_row = []
                for cell in row:
                    if isinstance(cell, str):
                        filtered_row.append(cell.encode('gbk', 'ignore').decode('gbk'))
                    else:
                        filtered_row.append(cell)


def acl_audit(object_type):
    '''
    默认高权限组无需输出
    :param object_type: 要审计的对象类型（例如'group'，'user', 'computer', 'ou'等）
    :return: None
    '''
    # 定义过滤列表，用于过滤掉不需要输出的安全主体
    sid_filter = {'administrator', 'domain admins', 'key admins', 'enterprise admins', 'enterprise key admins',
                  'administrators', 'account operators'}

    # 结果写入csv：
    header = ['Object Name', 'Security Principal', 'Right', 'Principal Type']
    file_name = f"{object_type.capitalize()}_Acl_Info.csv"

    # 从缓存中读取JSON数据
    objects = get_json_data(object_type)


    for obj in objects:
        acl_exists = False
        rows_to_write = []
        for ace in obj['Aces']:
            # 获取与ACE关联的安全主体的名称和类型
            ace_obj = obj_info({'PrincipalSID': ace['PrincipalSID'], 'PrincipalType': ace['PrincipalType']})
            if ace_obj and not any(ace_obj['name'].lower().startswith(x) for x in sid_filter):
                if not acl_exists:
                    # 如果找到了ACL，则打印对象的名称和分隔符
                    print("=" * 50)
                    print(f"{object_type.capitalize()}对象:\t{obj['Properties']['name']}")
                    acl_exists = True
                obj_name = ace_obj['name'] if ace_obj else 'N/A'
                if not any(obj_name.lower().startswith(x) for x in sid_filter):
                    rows_to_write.append([obj['Properties']['name'], obj_name, ace['RightName'], ace['PrincipalType']])
                    # 打印ACE信息
                    print(f"ACE:\n安全主体:\t{obj_name}\n权限:\t{ace['RightName']}\n安全主体类型:\t{ace['PrincipalType']}\n")

        if rows_to_write:
            # 创建output目录

            write_csv(file_name, header, rows_to_write)


## 获取计算机 'RegistrySessions', 'DcomUsers','RemoteDesktopUsers', 'LocalAdmins', 'PSRemoteUsers', 'Sessions', 'PrivilegedSessions' 等信息
def get_computer_sessions_info():
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
            print(f"\t用户: {user:<20} 计算机: {computer:<20}")
        except Exception as e:
            print(f"\tAn error occurred: {e}")

    def print_other_session(session):
        try:
            object_info = obj_info({
                'PrincipalSID': session['ObjectIdentifier'],
                'PrincipalType': session['ObjectType']
            })
            if object_info:
                print(f"\t{object_info['name']:<40}")
        except Exception as e:
            print(f"\tAn error occurred: {e}")

    for obj in objects:
        for session_key in session_keys:
            results = obj[session_key]['Results']
            if len(results) > 0:
                print("=" * 60)
                print(f"Computer: {obj['Properties']['name']}\t => {session_key}")

                for session in results:
                    if session_key in ['RegistrySessions', 'PrivilegedSessions']:
                        print_registry_or_privileged_session(session)
                    else:
                        print_other_session(session)
                        

## 获取所有域用户列表并输出csv
def get_domain_users():
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
                'distinguishedname':Properties['distinguishedname'],
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
    write_csv(file_name, header,user_info_list,encoding= 'gbk')


## 获取所有计算机列表
def get_group_members():
    groups = get_json_data("Group")
    group_info_list = []
    total_member_count = 0

    for group in groups:
        group_properties = group.get("Properties")
        members = group.get("Members", [])
        if not members:
            continue
        group_info = {"name": group_properties.get("name")}
        member_names = [obj_info({"PrincipalType": member["ObjectType"], "PrincipalSID": member["ObjectIdentifier"]}).get("name") for member in members]
        group_info["members"] = member_names
        group_info_list.append(group_info)
        total_member_count += len(members)

    if total_member_count > 0:
        for group_info in group_info_list:
            print("=" * 60)
            print(f"Group: {transform_string(group_info['name'])} => Members:")
            for member_name in group_info["members"]:
                print(f"\t{member_name}")

if __name__ == '__main__':
    '''
    acl_audit(object_type='user')  # 审计用户对象acl
    acl_audit(object_type='computer') # 审计计算机对象acl
    acl_audit(object_type='group') #  审计组对象acl
    get_computer_sessions_info()  # 获取所有计算机登录session
    get_domain_users() # 获取域内所有用户
    get_group_members() # 获取所有组下面用户
    '''
    #acl_audit(object_type='computer')
    #get_group_members()
    #get_domain_users()
    #get_computer_sessions_info()
