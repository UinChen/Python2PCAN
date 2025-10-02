import can
import time
import csv
from datetime import datetime
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue


class CANMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CAN总线监控与通信工具")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # 设置中文字体支持
        self.font_config()

        # CAN总线相关变量
        self.bus = None
        self.is_connected = False
        self.DEFAULT_SEND_ID = 0x123
        self.DEFAULT_SEND_DATA = [0x01, 0x02, 0x03, 0x04]

        # 记录相关变量
        self.csv_file = None
        self.csv_writer = None
        self.is_saving = False
        self.save_path = ""

        # 线程和队列
        self.receive_thread = None
        self.stop_event = threading.Event()
        self.message_queue = queue.Queue()

        # 创建UI
        self.create_widgets()

        # 启动消息处理线程
        self.process_messages()

    def font_config(self):
        """配置字体以支持中文显示"""
        default_font = ('SimHei', 10)
        self.root.option_add("*Font", default_font)

    def create_widgets(self):
        """创建所有UI组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 连接设置区域
        connect_frame = ttk.LabelFrame(main_frame, text="CAN总线连接设置", padding="10")
        connect_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(connect_frame, text="接口类型:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_var = tk.StringVar(value="pcan")
        interface_combo = ttk.Combobox(connect_frame, textvariable=self.interface_var,
                                       values=["pcan", "socketcan", "kvaser"], width=10)
        interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(connect_frame, text="通道:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.channel_var = tk.StringVar(value="PCAN_USBBUS1")
        channel_entry = ttk.Entry(connect_frame, textvariable=self.channel_var, width=15)
        channel_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(connect_frame, text="波特率:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.bitrate_var = tk.StringVar(value="500000")
        bitrate_combo = ttk.Combobox(connect_frame, textvariable=self.bitrate_var,
                                     values=["125000", "250000", "500000", "1000000"], width=10)
        bitrate_combo.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        self.connect_btn = ttk.Button(connect_frame, text="连接", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=6, padx=10, pady=5)

        # 发送区域
        send_frame = ttk.LabelFrame(main_frame, text="发送报文", padding="10")
        send_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(send_frame, text="ID (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.send_id_var = tk.StringVar(value="123")
        send_id_entry = ttk.Entry(send_frame, textvariable=self.send_id_var, width=10)
        send_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(send_frame, text="数据 (空格分隔十六进制值):").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.send_data_var = tk.StringVar(value="01 02 03 04")
        send_data_entry = ttk.Entry(send_frame, textvariable=self.send_data_var, width=30)
        send_data_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        self.send_btn = ttk.Button(send_frame, text="发送报文", command=self.send_message, state=tk.DISABLED)
        self.send_btn.grid(row=0, column=4, padx=10, pady=5)

        # 扩展帧复选框
        self.extended_frame_var = tk.BooleanVar(value=False)
        extended_check = ttk.Checkbutton(send_frame, text="扩展帧 (29位)", variable=self.extended_frame_var)
        extended_check.grid(row=0, column=5, padx=10, pady=5)

        # 记录区域
        log_frame = ttk.LabelFrame(main_frame, text="记录设置", padding="10")
        log_frame.pack(fill=tk.X, pady=(0, 10))

        self.log_path_var = tk.StringVar(value="")
        log_path_entry = ttk.Entry(log_frame, textvariable=self.log_path_var, width=50)
        log_path_entry.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        browse_btn = ttk.Button(log_frame, text="浏览...", command=self.browse_log_file)
        browse_btn.grid(row=0, column=1, padx=5, pady=5)

        self.log_btn = ttk.Button(log_frame, text="开始记录", command=self.toggle_logging, state=tk.DISABLED)
        self.log_btn.grid(row=0, column=2, padx=10, pady=5)

        # 消息显示区域
        message_frame = ttk.LabelFrame(main_frame, text="消息记录", padding="10")
        message_frame.pack(fill=tk.BOTH, expand=True)

        # 创建表格
        columns = ("时间戳", "类型", "ID", "数据长度", "数据")
        self.message_tree = ttk.Treeview(message_frame, columns=columns, show="headings")

        # 设置列宽和标题
        self.message_tree.column("时间戳", width=150, anchor=tk.W)
        self.message_tree.column("类型", width=60, anchor=tk.CENTER)
        self.message_tree.column("ID", width=80, anchor=tk.CENTER)
        self.message_tree.column("数据长度", width=80, anchor=tk.CENTER)
        self.message_tree.column("数据", width=300, anchor=tk.W)

        for col in columns:
            self.message_tree.heading(col, text=col)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(message_frame, orient=tk.VERTICAL, command=self.message_tree.yview)
        self.message_tree.configure(yscroll=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.message_tree.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_var = tk.StringVar(value="未连接到CAN总线")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def toggle_connection(self):
        """切换CAN总线连接状态"""
        if not self.is_connected:
            # 尝试连接
            try:
                self.bus = can.interface.Bus(
                    interface=self.interface_var.get(),
                    channel=self.channel_var.get(),
                    bitrate=int(self.bitrate_var.get())
                )
                self.is_connected = True
                self.connect_btn.config(text="断开连接")
                self.send_btn.config(state=tk.NORMAL)
                self.log_btn.config(state=tk.NORMAL)
                self.status_var.set(
                    f"已连接到 {self.interface_var.get()} 通道 {self.channel_var.get()}, 波特率 {self.bitrate_var.get()}")

                # 启动接收线程
                self.stop_event.clear()
                self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                self.receive_thread.start()

            except Exception as e:
                messagebox.showerror("连接失败", f"无法连接到CAN总线: {str(e)}")
                self.is_connected = False
        else:
            # 断开连接
            self.disconnect()

    def disconnect(self):
        """断开CAN总线连接"""
        if self.is_connected:
            self.stop_event.set()
            if self.receive_thread and self.receive_thread.is_alive():
                self.receive_thread.join(1.0)
            if self.bus:
                self.bus.shutdown()
                self.bus = None
            self.is_connected = False
            self.connect_btn.config(text="连接")
            self.send_btn.config(state=tk.DISABLED)
            self.log_btn.config(state=tk.DISABLED)
            self.status_var.set("已断开CAN总线连接")

    def send_message(self):
        """发送CAN报文"""
        if not self.is_connected:
            messagebox.showwarning("未连接", "请先连接到CAN总线")
            return

        try:
            # 解析ID
            arbitration_id = int(self.send_id_var.get(), 16)

            # 解析数据
            data_str = self.send_data_var.get()
            data = [int(byte, 16) for byte in data_str.split()]

            # 检查数据长度
            if len(data) > 8:
                messagebox.showerror("数据错误", "CAN报文数据长度不能超过8字节")
                return

            # 创建报文
            msg = can.Message(
                arbitration_id=arbitration_id,
                data=data,
                is_extended_id=self.extended_frame_var.get()
            )

            # 发送报文
            self.bus.send(msg)

            # 显示和记录
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            self.add_message_to_tree(timestamp, "发送", arbitration_id, data)

            # 如果正在记录，保存发送的报文
            if self.is_saving:
                self.save_to_csv(msg, '发送')

        except ValueError as e:
            messagebox.showerror("输入错误", f"无效的输入: {str(e)}\n请确保ID和数据是有效的十六进制值")
        except can.CanError as e:
            messagebox.showerror("发送失败", f"发送CAN报文失败: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"发送过程中发生错误: {str(e)}")

    def receive_messages(self):
        """接收CAN报文的线程函数"""
        while not self.stop_event.is_set():
            try:
                msg = self.bus.recv(0.1)  # 0.1秒超时
                if msg:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    self.message_queue.put(("接收", timestamp, msg))

                    # 如果正在记录，保存接收的报文
                    if self.is_saving:
                        self.save_to_csv(msg, '接收')
            except Exception as e:
                if not self.stop_event.is_set():
                    self.message_queue.put(("错误", datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], str(e)))
                time.sleep(1)

    def process_messages(self):
        """处理消息队列中的消息并更新UI"""
        while not self.message_queue.empty():
            item = self.message_queue.get()
            if item[0] == "错误":
                # 显示错误消息
                timestamp, error_msg = item[1], item[2]
                self.add_message_to_tree(timestamp, "错误", 0, [error_msg])
            else:
                # 显示CAN消息
                msg_type, timestamp, msg = item
                self.add_message_to_tree(timestamp, msg_type, msg.arbitration_id, list(msg.data))

        # 定期检查队列
        self.root.after(100, self.process_messages)

    def add_message_to_tree(self, timestamp, msg_type, arbitration_id, data):
        """将消息添加到表格中"""
        # 格式化数据
        id_str = f"0x{arbitration_id:X}"
        data_len = len(data)

        # 处理错误消息的数据显示
        if msg_type == "错误":
            data_str = data[0] if data else ""
        else:
            data_str = ' '.join([f'0x{byte:02X}' for byte in data])

        # 设置行颜色
        tag = "send" if msg_type == "发送" else "receive" if msg_type == "接收" else "error"

        # 插入数据
        self.message_tree.insert("", tk.END, values=(timestamp, msg_type, id_str, data_len, data_str), tags=(tag,))

        # 滚动到最后一行
        self.message_tree.yview_moveto(1.0)

        # 限制表格中的行数，防止内存溢出
        if len(self.message_tree.get_children()) > 1000:
            first_item = self.message_tree.get_children()[0]
            self.message_tree.delete(first_item)

        # 配置表格行颜色
        self.message_tree.tag_configure("send", background="#e1f5fe")
        self.message_tree.tag_configure("receive", background="#e8f5e9")
        self.message_tree.tag_configure("error", background="#ffebee")

    def browse_log_file(self):
        """浏览日志文件保存路径"""
        default_filename = f"can_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=default_filename
        )
        if file_path:
            self.log_path_var.set(file_path)

    def toggle_logging(self):
        """切换日志记录状态"""
        if not self.is_saving:
            # 开始记录
            file_path = self.log_path_var.get()
            if not file_path:
                default_filename = f"can_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                file_path = os.path.join(os.getcwd(), default_filename)
                self.log_path_var.set(file_path)

            if self.init_csv_file(file_path):
                self.is_saving = True
                self.log_btn.config(text="停止记录")
                self.status_var.set(f"已连接，正在记录到 {os.path.basename(file_path)}")
                messagebox.showinfo("开始记录", f"已开始记录到CSV文件:\n{file_path}")
        else:
            # 停止记录
            self.stop_logging()
            self.log_btn.config(text="开始记录")
            self.status_var.set(f"已连接，未记录")
            messagebox.showinfo("停止记录", f"已停止记录到CSV文件")

    def init_csv_file(self, file_path):
        """初始化CSV文件并写入表头"""
        try:
            # 创建目录（如果不存在）
            directory = os.path.dirname(file_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            # 打开文件并写入表头
            self.csv_file = open(file_path, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow(['时间戳', '类型', 'ID', '数据长度', '数据'])
            self.save_path = file_path
            return True
        except Exception as e:
            messagebox.showerror("文件错误", f"无法创建CSV文件: {str(e)}")
            return False

    def save_to_csv(self, message, msg_type):
        """将CAN报文保存到CSV文件"""
        if self.csv_writer is None:
            return False

        try:
            # 格式化数据
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            data_str = ' '.join([f'0x{byte:02X}' for byte in message.data])

            # 写入CSV
            self.csv_writer.writerow([
                timestamp,
                msg_type,  # '发送' 或 '接收'
                f'0x{message.arbitration_id:X}',
                len(message.data),
                data_str
            ])

            # 立即刷新到文件
            self.csv_file.flush()
            return True
        except Exception as e:
            self.message_queue.put(
                ("错误", datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], f"写入CSV失败: {str(e)}"))
            return False

    def stop_logging(self):
        """停止日志记录"""
        if self.is_saving and self.csv_file:
            self.csv_file.close()
            self.csv_file = None
            self.csv_writer = None
            self.is_saving = False

    def on_close(self):
        """关闭窗口时的清理工作"""
        self.stop_logging()
        self.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = CANMonitorApp(root)
    root.mainloop()
