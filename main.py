import json
import os
import threading
import tkinter as tk
import paramiko

# 配置文件路径
config_path = os.path.expanduser("~/Library/Application Support/SynchronizeDeleteFiles/config.json")
file_record_path = os.path.expanduser("~/Library/Application Support/SynchronizeDeleteFiles/file_records.json")


# 加载配置文件
def load_config():
    if os.path.exists(config_path):
        with open(config_path, 'r') as file:
            return json.load(file)
    else:
        return {
            "local_dir": "",
            "remote_dir": "",
            "ssh_host": "",
            "ssh_user": "",
            "ssh_password": "",
            "exclude_files": []
        }


config = load_config()


# 创建并返回 SFTP 连接
def create_sftp_connection(ssh_host, ssh_user, ssh_password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
    sftp = ssh.open_sftp()
    return ssh, sftp


# 递归创建远程文件夹
def create_remote_folder(sftp, remote_folder):
    dirs_to_create = []
    while True:
        try:
            sftp.stat(remote_folder)
            break
        except IOError:
            dirs_to_create.append(remote_folder)
            remote_folder = os.path.dirname(remote_folder)

    for directory in reversed(dirs_to_create):
        sftp.mkdir(directory)


# 显示同步过程的结果
def update_log(message):
    log_text.config(state="normal")
    log_text.insert("end", message + "\n")
    log_text.see("end")
    log_text.config(state="disabled")


# 同步文件功能
def sync_files():
    local_dir = local_dir_entry.get()
    remote_dir = remote_dir_entry.get()
    ssh_host = ssh_host_entry.get()
    ssh_user = ssh_user_entry.get()
    ssh_password = ssh_password_entry.get()
    exclude_files = config["exclude_files"]

    def perform_sync():
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
                with ssh.open_sftp() as sftp:
                    file_records = load_file_records()
                    current_local_files = {}

                    for root, dirs, files in os.walk(local_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if any(file_path.endswith(excl) for excl in exclude_files):
                                continue
                            relative_path = os.path.relpath(file_path, local_dir)
                            stat = os.stat(file_path)
                            file_attributes = {"size": stat.st_size, "mtime": stat.st_mtime}
                            current_local_files[relative_path] = file_attributes

                            if relative_path not in file_records or file_records[relative_path] != file_attributes:
                                update_log(f"上传文件: {relative_path}")
                                remote_file_path = os.path.join(remote_dir, relative_path).replace("\\", "/")
                                remote_folder = os.path.dirname(remote_file_path)
                                create_remote_folder(sftp, remote_folder)
                                sftp.put(file_path, remote_file_path)
                                file_records[relative_path] = file_attributes

                    for relative_path in list(file_records.keys()):
                        if relative_path not in current_local_files:
                            update_log(f"删除远程文件: {relative_path}")
                            remote_file_path = os.path.join(remote_dir, relative_path).replace("\\", "/")
                            try:
                                sftp.remove(remote_file_path)
                                del file_records[relative_path]
                            except Exception as e:
                                update_log(f"删除远程文件失败: {relative_path} - {e}")

                    # 执行命令删除空文件夹
                    delete_empty_folders_command = f"find {remote_dir} -type d -empty -delete"
                    stdin, stdout, stderr = ssh.exec_command(delete_empty_folders_command)
                    error = stderr.read().decode()
                    if error:
                        update_log(f"删除空文件夹失败: {error}")
                    else:
                        update_log("成功删除空文件夹")
                    save_file_records(file_records)
            update_log("同步完成，文件同步已完成！")
        except Exception as e:
            update_log(f"同步失败，发生错误: {str(e)}")

    threading.Thread(target=perform_sync).start()


# 加载文件记录
def load_file_records():
    if os.path.exists(file_record_path):
        with open(file_record_path, "r") as f:
            return json.load(f)
    return {}


# 保存文件记录
def save_file_records(records):
    with open(file_record_path, "w") as f:
        f.write(json.dumps(records, indent=4))


def test_connection():
    ssh_host = ssh_host_entry.get()
    ssh_user = ssh_user_entry.get()
    ssh_password = ssh_password_entry.get()

    try:
        # 使用上下文管理器分别处理 SSH 和 SFTP
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
            with ssh.open_sftp() as sftp:
                update_log(f"成功连接到 {ssh_host}，SFTP 测试通过")
    except Exception as e:
        update_log(f"无法连接到 {ssh_host}，错误信息: {str(e)}")


# 打开配置文件目录
def open_config():
    directory_path = os.path.expanduser("~/Library/Application Support/SynchronizeDeleteFiles")
    if os.path.exists(directory_path):
        os.system(f"open '{directory_path}'")


# 创建 GUI 界面
root = tk.Tk()
root.resizable(False, False)
root.title("文件同步助手")


def create_labeled_entry(root, label_text, default_text, show=None):
    frame = tk.Frame(root)
    frame.pack(fill="x")
    label = tk.Label(frame, text=label_text, width=9, anchor="w")
    label.pack(side="left")
    entry = tk.Entry(frame, width=60, show=show)
    entry.insert(0, default_text)
    entry.pack(side="left", fill="x", expand=True)
    return entry


local_dir_entry = create_labeled_entry(root, "本地资源路径:", config.get("local_dir", ""))
remote_dir_entry = create_labeled_entry(root, "远程资源路径:", config.get("remote_dir", ""))
ssh_host_entry = create_labeled_entry(root, "SSH主机:", config.get("ssh_host", ""))
ssh_user_entry = create_labeled_entry(root, "SSH用户:", config.get("ssh_user", ""))
ssh_password_entry = create_labeled_entry(root, "SSH密码:", config.get("ssh_password", ""), show="*")

log_text = tk.Text(root, width=90, height=15, state="disabled")
log_text.pack()

sync_button = tk.Button(root, text="同步文件", command=sync_files)
sync_button.pack(side="left")
test_button = tk.Button(root, text="测试连接", command=test_connection)
test_button.pack(side="left")
config_button = tk.Button(root, text="打开配置目录", command=open_config)
config_button.pack(side="left")

root.mainloop()