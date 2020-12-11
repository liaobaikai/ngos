import paramiko
import argparse
import os
import sys
import time

ngos_name = "ngos"
author = "ngos.top"

version_info = """
测试版
"""

arg_parser = argparse.ArgumentParser(description='''
    用法1：python3 ngos.py -h {hostname} -u {username} -P {port}  -p {password} -e {scriptfile}
    用法2：python3 ngos.py -e scriptfile1 -e scriptfile2 --csv-file ./host-list.csv
''', add_help=False)

arg_parser.add_argument('-d', '--dir', dest="target_dir_name", default="/tmp", help="上传脚本的文件目录")

arg_parser.add_argument('-c', '--command', default="#", help="批量执行的命令")
arg_parser.add_argument('-e', '--execute', dest="execute_files", default="#",
                        help="执行那个文件，可填多个，用空格隔开（先将文件上传，然后再执行文件）", nargs="+")
arg_parser.add_argument('-E', '--execute-dir', dest="execute_dir_name", default="#", help="执行的脚本的目录，里面的所有脚本都会执行")
arg_parser.add_argument('--csv-file', dest="local_csv_file", default="#",
                        help="服务器csv文件信息: 主机名, 用户名, 密码, 端口号，无需填写标题")

# 单击登录
arg_parser.add_argument('-h', '--hostname', dest="remote_hostname", default="#", help="远程服务器主机名")
arg_parser.add_argument('-P', '--port', dest="remote_port", default="22", help="远程服务器端口")
arg_parser.add_argument('-u', '--username', dest="remote_username", default="#", help="远程服务器用户名")
arg_parser.add_argument('-p', '--password', dest="remote_password", default="#", help="远程服务器密码")
# 单击登录

params = arg_parser.parse_args()

# 主机信息
host_list = []

# 后台运行脚本
background_running_script = 'nohup sh {} >> {} &'


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


target_dir = os.path.join(params.target_dir_name, ngos_name)


# 执行文件
def execute_script(ssh_client, remote_script_file):
    print("{} - {} [INFO] Send executing script...".format(now(), ngos_name.upper()))
    ssh_client.exec_command(background_running_script
                            .format(remote_script_file, os.path.join(target_dir, "{}.log".format(ngos_name))))
    print("{} - {} [INFO] Send done.".format(now(), ngos_name.upper()))


# 判断远程目录是否存在
def remote_exists_dir(ssh_client, remote_dir):
    stdin, stdout, stderr = ssh_client.exec_command('cd ' + remote_dir)
    return stderr.read() == b''


# 上传脚本到目标服务器
def upload_script_file(ssh_client, file_names):
    transport = ssh_client.get_transport()  # type: paramiko.Transport
    sftp = paramiko.SFTPClient.from_transport(transport)
    host, port = transport.getpeername()
    if file_names:
        is_check_remote_dir = False
        for file_name in file_names:
            # 判断文件是否存在
            if file_name == '#':
                print("必须指定执行文件！")
                return
            if not os.path.exists(file_name):
                print("文件不存在！", file_name)
                sys.exit(0)

            remote_file = os.path.join(target_dir, os.path.basename(file_name))
            print('{} - {} [INFO] Waiting copy file `{}` to `scp -P{} {}@{}:{}` ...'
                  .format(now(), ngos_name.upper(), file_name, port, transport.get_username(), host, remote_file))

            if not is_check_remote_dir:
                print("{} - {} [INFO] Checking remote directory `{}`...".format(now(), ngos_name.upper(), target_dir))
                if not remote_exists_dir(ssh_client, target_dir):
                    print("{} - {} [INFO] Directory not exists, create directory `{}`..."
                          .format(now(), ngos_name.upper(), target_dir))
                    stdin, stdout, stderr = ssh_client.exec_command("mkdir -p " + target_dir)
                    if stdout.read() != b'':
                        print(stdout.read().decode())
                    if stderr.read() != b'':
                        print(stderr.read().decode())
                print("{} - {} [INFO] Ok.".format(now(), ngos_name.upper()))
                is_check_remote_dir = True

            print("{} - {} [INFO] Start transfer file ... `{}` to `{}`".format(now(), ngos_name.upper(), file_name, remote_file))
            sftp.put(file_name, remote_file)
            print("{} - {} [INFO] Ok.".format(now(), ngos_name.upper()))

        # 发送完成，执行文件
        for execute_file in params.execute_files:
            execute_script(ssh_client, os.path.join(target_dir, execute_file))


# 连接到ssh
def connect_ssh(host_info):
    hostname = host_info.get("hostname")
    if hostname == '#':
        arg_parser.print_help()
        return
    username = host_info.get("username")
    if username == '#':
        arg_parser.print_help()
        return
    password = host_info.get("password")
    if password == '#':
        arg_parser.print_help()
        return
    port = host_info.get("port")

    # print("hostname:", hostname)
    # print("username:", username)
    # print("password:", password)
    # print("port:", port)

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=hostname,
                       username=username,
                       password=password,
                       port=port)

    files = []
    if params.execute_dir_name != "#":
        for file_name in os.listdir(params.execute_dir_name):
            files.append(os.path.join(params.execute_dir_name, file_name))

    upload_script_file(ssh_client, file_names=files)


# 准备连接到ssh服务器
def prepare_connect_ssh(ssh_info):
    host_info = []
    for item in ssh_info:
        host_info.append(item.strip())

    connect_ssh({
        "hostname": host_info[0],
        "username": host_info[1],
        "password": host_info[2],
        "port": host_info[3],
    })


# 从csv文件读取配置信息
def read_from_csv(file_name):
    with open(file_name, 'r') as f:
        for line in f.readlines():
            line = line.strip()
            prepare_connect_ssh(line.split(","))


# 检查是否传入文件信息
def check_files():
    pass


if __name__ == "__main__":

    if params.local_csv_file != '#':
        read_from_csv(params.local_csv_file)
    else:
        # 单击登录
        prepare_connect_ssh([params.remote_hostname,
                             params.remote_username,
                             params.remote_password,
                             params.remote_port])
