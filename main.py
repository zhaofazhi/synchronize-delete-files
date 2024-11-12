# 文件同步工具
# 作者: [赵发志]
# 日期: 2024-11-12
# 描述: 使用 Tkinter 创建的文件同步配置工具，支持排除特定文件的上传、MD5 校验及自动同步功能。
# pyinstaller --windowed --icon='icon.icns' --name=SynchronizeDeleteFiles main.py
import hashlib
import json
import os
import threading
import tkinter as tk
from tkinter import messagebox

import paramiko

config_path = os.path.expanduser("~/Library/Application Support/SynchronizeDeleteFiles/config.json")
md5_file_path = os.path.expanduser("~/Library/Application Support/SynchronizeDeleteFiles/md5_record.json")


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


# 计算文件的MD5
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# 获取已存在的MD5记录
def load_md5_record(local_dir):
    if os.path.exists(md5_file_path):
        with open(md5_file_path, "r") as f:
            return json.load(f)
    return {local_dir: {}}


# 显示同步过程的结果
def update_log(message):
    log_text.config(state="normal")
    log_text.insert("end", message + "\n")
    log_text.see("end")
    log_text.config(state="disabled")


# 同步文件（在后台线程中执行）
def sync_files():
    local_dir = local_dir_entry.get()
    remote_dir = remote_dir_entry.get()
    ssh_host = ssh_host_entry.get()
    ssh_user = ssh_user_entry.get()
    ssh_password = ssh_password_entry.get()
    exclude_files = config["exclude_files"]

    # 加载MD5记录
    existing_md5 = load_md5_record(local_dir)

    # 连接服务器并启动同步
    def perform_sync():
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
            sftp = ssh.open_sftp()

            # 遍历本地文件并进行同步
            for root, _, files in os.walk(local_dir):
                for file in files:
                    relative_path = os.path.relpath(os.path.join(root, file), local_dir)
                    local_file_path = os.path.join(root, file)

                    # 跳过排除文件
                    if any(relative_path.endswith(excl) for excl in exclude_files):
                        continue

                    # 检查并计算 MD5 值
                    new_md5 = calculate_md5(local_file_path)
                    if (relative_path not in existing_md5[local_dir] or
                            existing_md5[local_dir][relative_path] != new_md5):

                        # 上传文件
                        remote_file_path = os.path.join(remote_dir, relative_path)
                        remote_folder_path = os.path.dirname(remote_file_path)
                        try:
                            sftp.stat(remote_folder_path)
                        except FileNotFoundError:
                            ssh.exec_command(f"mkdir -p {remote_folder_path}")
                        sftp.put(local_file_path, remote_file_path)

                        # 更新日志和 MD5 记录
                        update_log(f"同步文件: {relative_path}")
                        existing_md5[local_dir][relative_path] = new_md5  # 记录成功的上传文件 MD5 值
                        with open(md5_file_path, "w", encoding="utf-8") as f:
                            json.dump(existing_md5, f, indent=4, ensure_ascii=False)
            # 多线程删除服务器上多余的文件

            # 在文件同步前生成一次本地文件路径集合
            def get_local_file_paths(local_dir):
                return {os.path.relpath(os.path.join(root, f), local_dir) for root, _, files in os.walk(local_dir) for f
                        in files}
            # 在同步或删除时使用这个集合
            local_file_paths = get_local_file_paths(local_dir)
            for relative_path in list(existing_md5[local_dir].keys()):
                if relative_path not in local_file_paths:
                    remote_file_path = os.path.join(remote_dir, relative_path)
                    try:
                        sftp.remove(remote_file_path)
                        update_log(f"删除文件: {relative_path}")
                        del existing_md5[local_dir][relative_path]  # 移除已删除文件的 MD5 记录
                        with open(md5_file_path, "w", encoding="utf-8") as f:
                            json.dump(existing_md5, f, indent=4, ensure_ascii=False)
                    except FileNotFoundError:
                        update_log(f"文件未找到，跳过删除: {relative_path}")

            update_log("同步完成！")
            sftp.close()
            ssh.close()
        except Exception as e:
            messagebox.showerror("同步失败", str(e))

    threading.Thread(target=perform_sync).start()  # 启动后台同步线程


# 测试SSH连接
def test_connection():
    ssh_host = ssh_host_entry.get()
    ssh_user = ssh_user_entry.get()
    ssh_password = ssh_password_entry.get()

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
        messagebox.showinfo("连接成功", f"成功连接到 {ssh_host}")
        ssh.close()
    except Exception as e:
        messagebox.showerror("连接失败", str(e))


def open_config():
    directory_path = os.path.expanduser('~/Library/Application Support/SynchronizeDeleteFiles')
    if os.path.exists(directory_path):
        os.system(f"open ~/Library/Application\ Support/SynchronizeDeleteFiles")


# 创建GUI界面
root = tk.Tk()
root.resizable(False, False)  # 禁止水平和垂直调整窗口大小
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

sync_button = tk.Button(root, text="同步文件", command=lambda: threading.Thread(target=sync_files).start())
sync_button.pack(side="left")
test_button = tk.Button(root, text="测试连接", command=test_connection)
test_button.pack(side="left")
test_button = tk.Button(root, text="打开配置目录", command=open_config)
test_button.pack(side="left")

root.mainloop()